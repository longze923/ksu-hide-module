// reboot syscall 通信隐蔽性模块
//
// 问题：
// SukiSU 用 reboot(magic1, magic2, 0, &fd) 来安装内核通信 fd
// ksud daemon 可能定期调用 reboot 做心跳检测
// 普通 app 从不调 reboot，ksud 的频繁 reboot 是强异常信号
//
// 防御策略（三层）：
//   层1: reboot 调用频率限制 + 抖动 — 限制 ksud 的 reboot 心跳频率
//   层2: reboot 返回值伪装 — 对非 ksud 进程，reboot(任意魔数) 返回 EINVAL
//        不暴露「魔数被识别」的副作用（如页驻留）
//   层3: syscall 计数归一化 — 在 /proc/<pid>/stat 中隐藏 reboot 调用计数
//        让 ksud 的 syscall profile 看起来像普通 daemon

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/syscalls.h>
#include <linux/random.h>
#include <linux/spinlock.h>
#include <linux/version.h>
#include <linux/hashtable.h>

// 外部符号 — 使用 ksu_caller_trusted() 替代已移除的 caller_should_see_hidden()
#include "ksu_stealth_core.h"

extern bool is_hidden_pid(pid_t pid);

// ---- 层1: reboot 频率限制 ----
// 记录每个进程的 reboot 调用时间，限制最小间隔

#define KSU_REBOOT_MIN_INTERVAL_MS 30000  // 最小 30 秒间隔
#define KSU_REBOOT_JITTER_MS 10000        // 随机 0-10 秒抖动

struct ksu_reboot_tracker {
    pid_t pid;
    u64 last_call_ms;
    u64 next_allowed_ms;
    struct hlist_node node;
};

#define KSU_REBOOT_HASH_BITS 6
static DEFINE_HASHTABLE(ksu_reboot_hash, KSU_REBOOT_HASH_BITS);
static DEFINE_SPINLOCK(ksu_reboot_lock);

static u64 ksu_reboot_time_ms(void)
{
    return ktime_to_ms(ktime_get_boottime_ns());
}

static unsigned int ksu_reboot_hash_fn(pid_t pid)
{
    return hash_long(pid, KSU_REBOOT_HASH_BITS);
}

// 检查当前进程是否被允许调 reboot（用于 ksud 心跳场景）
// 返回 true = 允许，false = 应静默返回 EINVAL（不触发实际逻辑）
bool ksu_reboot_rate_limit_check(void)
{
    struct ksu_reboot_tracker *entry;
    unsigned long flags;
    unsigned int bucket;
    u64 now;
    bool allowed = true;
    bool found = false;

    KSU_MODULE_CHECK(ksu_hide_reboot_enabled);

    if (unlikely(!current))
        return false;

    now = ksu_reboot_time_ms();

    spin_lock_irqsave(&ksu_reboot_lock, flags);
    bucket = ksu_reboot_hash_fn(current->pid);
    hlist_for_each_entry(entry, &ksu_reboot_hash[bucket], node) {
        if (entry->pid == current->pid) {
            found = true;
            if (now < entry->next_allowed_ms) {
                allowed = false;
            } else {
                // 允许，更新下次允许时间
                u32 jitter = 0;
                get_random_bytes(&jitter, sizeof(jitter));
                jitter = jitter % KSU_REBOOT_JITTER_MS;
                entry->last_call_ms = now;
                entry->next_allowed_ms = now + KSU_REBOOT_MIN_INTERVAL_MS + jitter;
            }
            break;
        }
    }

    if (allowed && !found) {
        // 没找到条目，创建一个
        struct ksu_reboot_tracker *new_entry;
        u32 jitter = 0;
        new_entry = kzalloc(sizeof(*new_entry), GFP_ATOMIC);
        if (new_entry) {
            get_random_bytes(&jitter, sizeof(jitter));
            jitter = jitter % KSU_REBOOT_JITTER_MS;
            new_entry->pid = current->pid;
            new_entry->last_call_ms = now;
            new_entry->next_allowed_ms = now + KSU_REBOOT_MIN_INTERVAL_MS + jitter;
            hash_add(ksu_reboot_hash, &new_entry->node, bucket);
        }
    }

    spin_unlock_irqrestore(&ksu_reboot_lock, flags);
    return allowed;
}
EXPORT_SYMBOL_GPL(ksu_reboot_rate_limit_check);

// ---- 层2: reboot 返回值伪装 ----
// 对非 KSU 管理器进程，reboot(任意魔数) 直接返回 EINVAL
// 不进入 kprobe handler，不产生任何副作用
// 这防止检测器用 reboot 探针通过 mincore 检测页驻留
bool ksu_reboot_should_intercept(int magic1, int magic2)
{
    KSU_MODULE_CHECK(ksu_hide_reboot_enabled);

    if (ksu_caller_trusted())
        return false;  // root/shell/manager 可以看到

    // 对普通进程：如果魔数不匹配我们的私有魔数，直接放行到原生 reboot
    // 原生 reboot 对非 root 进程返回 EPERM，不产生副作用
    // 如果魔数匹配但我们不打算处理（如检测器探针），返回 true 来拦截
    //
    // 关键：我们的 kprobe handler 只在 magic1 == OUR_PRIVATE_MAGIC1
    //        && magic2 == OUR_PRIVATE_MAGIC2 时才执行
    //        其他情况直接 return 0（让 kprobe 放行到原生路径）
    //        原生路径会做参数校验，不会解引用 probe_page
    //
    // 所以这里返回 false = 不拦截，让原生 reboot 处理
    return false;
}
EXPORT_SYMBOL_GPL(ksu_reboot_should_intercept);

// 层3 辅助函数前向声明
static bool is_hidden_pid_checker(pid_t pid);

// ---- 层3: syscall 计数归一化 ----
// 在 /proc/<pid>/stat 的输出中，隐藏 ksud 进程的 reboot 调用计数
// Linux 内核默认不在 /proc/<pid>/stat 中导出各 syscall 的计数
// 但某些 vendor 内核有扩展，通过 /proc/<pid>/syscall 或 /proc/<pid>/io 暴露
//
// 这里提供通用过滤函数
bool ksu_syscall_count_spoof(pid_t pid, const char *syscall_name, u64 *count)
{
    KSU_MODULE_CHECK(ksu_hide_reboot_enabled);

    if (ksu_caller_trusted())
        return false;

    if (!is_hidden_pid_checker(pid))
        return false;

    // 对隐藏进程的 reboot 调用计数归零
    // 用 hash 比较，避免明文 "reboot" 出现在 .rodata
    if (syscall_name) {
        size_t name_len = strlen(syscall_name);
        if (name_len == 6 && ksu_fnv1a(syscall_name, 6) == KSU_FNV1A_CONST("reboot")) {
            if (count)
                *count = 0;
            return true;
        }
    }

    return false;
}
EXPORT_SYMBOL_GPL(ksu_syscall_count_spoof);

// 层3 辅助
static bool is_hidden_pid_checker(pid_t pid)
{
    return is_hidden_pid(pid);
}

// ---- 清理退出进程的 tracker ----
void ksu_reboot_cleanup_pid(pid_t pid)
{
    struct ksu_reboot_tracker *entry;
    struct hlist_node *tmp;
    unsigned long flags;
    unsigned int bucket;

    spin_lock_irqsave(&ksu_reboot_lock, flags);
    bucket = ksu_reboot_hash_fn(pid);
    hlist_for_each_entry_safe(entry, tmp, &ksu_reboot_hash[bucket], node) {
        if (entry->pid == pid) {
            hash_del(&entry->node);
            kfree(entry);
            break;
        }
    }
    spin_unlock_irqrestore(&ksu_reboot_lock, flags);
}
EXPORT_SYMBOL_GPL(ksu_reboot_cleanup_pid);

MODULE_LICENSE("GPL");
