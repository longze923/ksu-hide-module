// 网络 socket 隐藏模块
// 覆盖范围：
// 1. /proc/net/unix - 隐藏 ksud/SukiSI daemon 的 unix domain socket
// 2. /proc/net/tcp, /proc/net/tcp6 - 隐藏 daemon 的 TCP 端口
// 3. /proc/net/raw, /proc/net/packet, /proc/net/udp - 同上
// 4. netlink SOCK_DIAG (INET_DIAG / UNIX_DIAG) - 绕过 /proc/net 枚举时的侧信道
//
// 策略：基于"拥有者进程是否被隐藏"来判定是否隐藏 socket
// 如果 socket 的创建者进程 (sk->sk_owner_pid 或 file->f_owner.pid) 被标记隐藏，则隐藏该 socket

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/un.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/cred.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/netlink.h>
#include <uapi/linux/unix_diag.h>
#include <uapi/linux/inet_diag.h>

#include "ksu_stealth_core.h"

// 外部符号
extern bool is_hidden_pid(pid_t pid);
extern bool caller_should_see_hidden(void);

// ---- 通用判定：该 socket 是否应被隐藏 ----
static bool should_hide_sock(struct sock *sk)
{
    struct socket *sock;
    struct file *file;
    pid_t pid = 0;
    bool hidden = false;

    KSU_MODULE_CHECK(ksu_hide_net_enabled);

    if (!sk)
        return false;

    /* 防御：拒绝明显非法的 sock 指针（如 seq_file 的 SEQ_START_TOKEN 等
     * magic 值），避免注入点位于 token 检查之前时解引用崩溃。
     * 用 0x1000 做低地址阈值（arm64 最小页大小 4K），不依赖 PAGE_SIZE 宏。 */
    if ((unsigned long)sk < 0x1000)
        return false;

    /*
     * tcp4_seq_show 的 ehash 链表会包含 TCP_TIME_WAIT / TCP_NEW_SYN_RECV
     * 条目，它们只有 struct sock_common（sk_state 可读），没有完整的
     * struct sock 字段。我们的注入点位于 tcp4_seq_show 的状态分发之前，
     * 若继续读 sk->sk_socket / sk->sk_callback_lock 会越界访问已释放/复用
     * 的内存（LIST_POISON dead000000000122）→ 内核 panic 黑屏重启。
     * 这里先按 sk_state 排除这两种非完整 sock 条目。
     */
    if (sk->sk_state == TCP_TIME_WAIT || sk->sk_state == TCP_NEW_SYN_RECV)
        return false;

    if (caller_should_see_hidden())
        return false;

    /*
     * 通过 sk->sk_socket->file 的 f_owner PID 判断 socket 创建者。
     *
     * 加锁说明（5.15 GKI，与内核 f_getown()/sock_i_uid() 一致）：
     *  - sk->sk_socket 由 sk_callback_lock 保护（sock_orphan/sock_graft
     *    用 write_lock_bh 修改），读取必须持 read_lock_bh；
     *  - file->f_owner.pid 由 f_owner.lock + RCU 保护，struct pid 是 RCU
     *    延迟释放（free_pid -> call_rcu），pid_vnr() 必须在 rcu_read_lock()
     *    内调用，否则会访问已释放的 struct pid；
     *  - is_hidden_pid() -> find_task_by_vpid() 同样要求调用方持有 RCU。
     *
     * 修复前：上述访问全部无锁，/proc/net/tcp 读取路径与进程退出/关闭
     * socket 并发时触发 UAF（fault addr = dead000000000122，LIST_POISON），
     * 导致内核 panic 黑屏重启。
     */
    rcu_read_lock();
    read_lock_bh(&sk->sk_callback_lock);
    sock = sk->sk_socket;
    if (sock) {
        file = sock->file;
        if (file) {
            read_lock_irq(&file->f_owner.lock);
            if (file->f_owner.pid)
                pid = pid_vnr(file->f_owner.pid);
            read_unlock_irq(&file->f_owner.lock);

            if (pid > 0 && is_hidden_pid(pid))
                hidden = true;
        }
    }
    read_unlock_bh(&sk->sk_callback_lock);
    rcu_read_unlock();

    return hidden;
}

// ---- 1. /proc/net/* 行过滤 ----
// 由于 /proc/net/* 文件每行格式不同，这里提供一个"包含关键词"过滤
// 再辅以 sock 的通用判定
//
// 该过滤器在 /proc/net/* 的 seq_file show 回调返回一行时被调用
// （通过 patch tcp4_seq_show / unix_seq_show / udp_seq_show 等）

bool ksu_net_proc_line_filter(const char *line, struct sock *sk)
{
    if (!sk)
        return false;
    KSU_MODULE_CHECK(ksu_hide_net_enabled);
    return should_hide_sock(sk);
}

// ---- 2. /proc/net/unix sun_path 关键词过滤 ----
// 有些 /proc/net/unix 输出里有 "@ksu" / "@SukiSI" / "@magisk" 等抽象 socket 名
// 即使没有 sock 指针匹配，也能通过关键词命中

static bool sun_path_has_hidden_keyword(const char *sun_path)
{
    size_t len;

    KSU_MODULE_CHECK(ksu_hide_net_enabled);

    if (!sun_path)
        return false;
    // 抽象 socket (@开头) 的关键词过滤
    // 使用 hash 子串搜索，避免明文 "ksu"/"magisk"/"sukisu" 出现在 .rodata
    len = strlen(sun_path);
    if (len == 0)
        return false;
    return ksu_sg_contains_keyword(sun_path, len);
}

bool ksu_net_unix_line_filter(const char *sun_path, struct sock *sk)
{
    KSU_MODULE_CHECK(ksu_hide_net_enabled);

    if (caller_should_see_hidden())
        return false;
    if (should_hide_sock(sk))
        return true;
    if (sun_path_has_hidden_keyword(sun_path))
        return true;
    return false;
}

// ---- 3. netlink SOCK_DIAG (inet_diag / unix_diag) ----
//
// SOCK_DIAG 通过 netlink socket 枚举全系统 socket，绕过 /proc/net 文件层。
// 我们在 dump_done 之前的 sk_diag_fill 钩子注入过滤。
//
// 对于 inet_diag:
//   sk_diag_fill() 在每个 socket 填充 nlmsg 时调用
//   如果 should_hide_sock(sk) → 跳过填充，直接返回 0 长度
//
// 对于 unix_diag:
//   sk_diag_dump_icons() 中调用 unix_diag_fill_sock()
//   同上
//
// 提供通用判定函数供 patch 注入的钩子调用：

bool ksu_diag_should_skip_sock(struct sock *sk)
{
    KSU_MODULE_CHECK(ksu_hide_net_enabled);
    return should_hide_sock(sk);
}

EXPORT_SYMBOL_GPL(ksu_net_proc_line_filter);
EXPORT_SYMBOL_GPL(ksu_net_unix_line_filter);
EXPORT_SYMBOL_GPL(ksu_diag_should_skip_sock);

MODULE_LICENSE("GPL");
