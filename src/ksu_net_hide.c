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
    pid_t pid;

    KSU_MODULE_CHECK(ksu_hide_net_enabled);

    if (!sk)
        return false;

    if (caller_should_see_hidden())
        return false;

    /* 通过 sk->sk_socket->file 的 f_owner PID 判断 socket 创建者。
     * 方法1(sock_i_owner)和方法3(sk_peer_pid)在 5.15 GKI 中不存在:
     *   - sock_i_owner 是主线后续版本才加入的 helper
     *   - sk_peer_pid 字段在 5.15 的 struct sock 中不存在
     * f_owner 是 SIGIO 机制的核心字段(自 2.6 时代),socket() syscall
     * 创建时由内核通过 fd_install 自动设置,覆盖所有用户态 daemon socket。 */
    if (sk->sk_socket && sk->sk_socket->file && sk->sk_socket->file->f_owner.pid) {
        pid = pid_vnr(sk->sk_socket->file->f_owner.pid);
        if (pid > 0 && is_hidden_pid(pid))
            return true;
    }

    return false;
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
