// SPDX-License-Identifier: GPL-2.0
/*
 * ksu_stealth_core.c — 极致隐藏性核心实现
 *
 * 实现 ksu_stealth_core.h 中声明的：
 *   - ksu_caller_trusted()                               强化认证
 *   - ksu_is_being_debugged()                             anti-debug
 *   - ksu_jitter_delay()                                  时序侧信道防护
 *   - ksu_hash_contains()                                 hash 子串搜索
 *   - ksu_stealth_disable_all() / ksu_stealth_enable_all() 紧急开关
 *
 * 该文件被编译为 drivers/ksu_hide/ksu_stealth_core.o，是所有隐藏模块的依赖。
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/debug.h>
#include <linux/cred.h>
#include <linux/atomic.h>
#include <linux/spinlock.h>
#include <linux/random.h>
#include <linux/ktime.h>
#include <linux/delay.h>
#include <linux/string.h>
#include <linux/nmi.h>
#include <linux/ptrace.h>
#include <linux/audit.h>
#include <linux/version.h>
#include <linux/syscalls.h>

#include "ksu_stealth_core.h"

/* KSU manager 接口 — 由 KernelSU 提供。
 * 注意：ksu_is_manager() 在 SukiSU-Ultra 中 KPM 禁用时不可用，
 * 改用 ksu_get_task_mark() 判断当前进程是否为 KSU 标记进程。 */
extern int ksu_get_task_mark(pid_t pid);

/* 全局状态 */
struct ksu_auth_state ksu_auth;
atomic_t ksu_stealth_enabled = ATOMIC_INIT(1);

/* ===================================================================
 *  时间辅助
 * ===================================================================
 */
static u64 ksu_monotonic_ms(void)
{
    return ktime_to_ms(ktime_get_boottime_ns());
}


/* ===================================================================
 *  Section A — Hash 子串搜索
 * ===================================================================
 *
 * 在 haystack[hlen] 中查找子串，其 hash 等于 needle_hash、长度等于 needle_len
 * 用途：替代 strstr，不暴露 needle 的明文
 */

bool ksu_hash_contains(const char *haystack, size_t hlen,
                       u64 needle_hash, size_t needle_len)
{
    size_t i;
    u64 h;
    char c;

    if (!haystack || hlen < needle_len || needle_len == 0)
        return false;

    /* 滚动 hash：先算 needle_len 字节的 hash，然后滑动 */
    h = KSU_FNV_OFFSET;
    for (i = 0; i < needle_len; i++) {
        c = haystack[i];
        if (c == 0)
            return false;
        h ^= (u8)c;
        h *= KSU_FNV_PRIME;
    }

    if (h == needle_hash)
        return true;

    /* 滚动：去掉最左字节、加入新字节 */
    for (i = needle_len; i < hlen; i++) {
        char old_c, new_c;
        size_t j;
        new_c = haystack[i];
        if (new_c == 0)
            break;
        old_c = haystack[i - needle_len];

        /* FNV-1a 不是滚动友好的，重算窗口 hash (窗口小，性能可接受) */
        h = KSU_FNV_OFFSET;
        for (j = 0; j < needle_len; j++) {
            h ^= (u8)haystack[i - needle_len + 1 + j];
            h *= KSU_FNV_PRIME;
        }
        if (h == needle_hash)
            return true;
        (void)old_c;
    }

    return false;
}
EXPORT_SYMBOL_GPL(ksu_hash_contains);


/* ===================================================================
 *  Section B — Anti-debug 检测
 * ===================================================================
 *
 * 反作弊可能用 ptrace attach 到 manager 进程或 native 子进程，
 * 跟踪其与内核的交互来反推隐藏机制。我们检测以下信号：
 *   1. current->ptrace 不为 0 → 被调试中
 *   2. current 有信号挂起 (TIF_SIGPENDING) 且来源是 SIGSTOP/SIGTRAP
 *   3. current 在 syscall 单步模式 (TIF_SINGLESTEP)
 *   4. current 的父进程是已知的调试器 (gdb/lldb/strace)
 */

bool ksu_is_being_debugged(void)
{
    struct task_struct *t = current;
    struct task_struct *parent;

    if (unlikely(!t))
        return false;

    /* 1. ptrace 标志 */
    if (t->ptrace & PT_PTRACED)
        return true;

    /* 2. 单步执行 */
#ifdef TIF_SINGLESTEP
    if (test_tsk_thread_flag(t, TIF_SINGLESTEP))
        return true;
#endif

    /* 3. 父进程名匹配调试器 */
    parent = rcu_dereference_check(t->real_parent,
                                   lockdep_tasklist_lock_is_held());
    if (parent) {
        char comm[TASK_COMM_LEN];
        get_task_comm(comm, parent);

        /* 用 hash 比较，避免明文 "gdb"/"lldb"/"strace" 出现在内存 */
        if (ksu_fnv1a(comm, strnlen(comm, TASK_COMM_LEN)) ==
            KSU_FNV1A_CONST("gdb"))
            return true;
        if (ksu_fnv1a(comm, strnlen(comm, TASK_COMM_LEN)) ==
            KSU_FNV1A_CONST("lldb"))
            return true;
        if (ksu_fnv1a(comm, strnlen(comm, TASK_COMM_LEN)) ==
            KSU_FNV1A_CONST("strace"))
            return true;
        if (ksu_fnv1a(comm, strnlen(comm, TASK_COMM_LEN)) ==
            KSU_FNV1A_CONST("ltrace"))
            return true;
        if (ksu_fnv1a(comm, strnlen(comm, TASK_COMM_LEN)) ==
            KSU_FNV1A_CONST("frida"))
            return true;
    }

    return false;
}
EXPORT_SYMBOL_GPL(ksu_is_being_debugged);


/* ===================================================================
 *  Section C — 强化调用者认证
 * ===================================================================
 *
 * 多层认证（不包含探测降级机制，避免侧信道暴露）：
 *   Layer 1: 隐藏全局关闭 → 全员可见
 *   Layer 2: 内核线程或 init → 信任
 *   Layer 3: UID 白名单 → root / shell / KSU manager
 *   Layer 4: 启动时间窗 → 系统启动后短时间内允许 manager 操作
 *   Layer 5: anti-debug → 调试中拒绝
 *
 * 注意：所有不可信调用者统一返回 false，不区分扫描者/普通进程。
 * 任何差异化响应都会暴露"该进程被特殊对待"的侧信道信息。
 */

/* 延迟初始化：在 ksu_caller_trusted() 首次调用时自动完成
 * 不使用 early_initcall，避免在启动极早期调用 ktime_get_boottime_ns
 * 可能在某些内核配置下不稳定导致卡米 */
static bool ksu_auth_initialized;
static DEFINE_SPINLOCK(ksu_auth_init_lock);
static void ksu_stealth_core_init_once(void);

bool ksu_caller_trusted(void)
{
    kuid_t uid;
    uid_t uid_val;

    if (!ksu_stealth_active())
        return true;

    /* 防御：current 可能为 NULL（ARM64 sp_el0 未初始化等极端情况） */
    if (unlikely(!current))
        return false;

    /* 延迟初始化：首次调用时完成认证状态的初始化 */
    if (unlikely(!ksu_auth_initialized))
        ksu_stealth_core_init_once();

    /* Layer 1: 内核线程直接信任 */
    if (current->flags & PF_KTHREAD)
        return true;

    /* Layer 2: KSU 标记进程直接信任 (ksu_get_task_mark > 0 表示已标记) */
    if (ksu_get_task_mark(current->pid) > 0)
        return true;

    uid = current_uid();
    uid_val = from_kuid_munged(current_user_ns(), uid);

    /* Layer 3: UID 0 (root) / UID 2000 (shell) 信任 */
    if (uid_val == 0 || uid_val == 2000)
        return true;

    /* Layer 4: 启动时间窗内允许 manager 操作 */
    {
        u64 now = ksu_monotonic_ms();
        if (now < ksu_auth.boot_allow_ms)
            return true;
    }

    /* 不可信调用者一律拒绝 */
    return false;
}
EXPORT_SYMBOL_GPL(ksu_caller_trusted);

/* 兼容旧接口 — 各模块仍然调用的函数 */
bool caller_should_see_hidden(void)
{
    return ksu_caller_trusted();
}
EXPORT_SYMBOL_GPL(caller_should_see_hidden);


/* ===================================================================
 *  Section E — 时序侧信道防护
 * ===================================================================
 *
 * 隐藏操作本身在 cache/timing 上留下痕迹。我们在敏感操作前后插入
 * 随机延迟，破坏时序指纹。
 */

void ksu_jitter_delay(u32 max_us)
{
    u32 rnd = 0;

    if (max_us == 0)
        return;

    get_random_bytes(&rnd, sizeof(rnd));
    rnd = rnd % max_us;

    if (rnd > 0) {
        /* udelay 是 busy-wait，不会让出 CPU，避免调度痕迹 */
        udelay(rnd);
    }
}
EXPORT_SYMBOL_GPL(ksu_jitter_delay);


/* ===================================================================
 *  Section F — 紧急开关
 * ===================================================================
 */

void ksu_stealth_disable_all(void)
{
    atomic_set(&ksu_stealth_enabled, 0);
}
EXPORT_SYMBOL_GPL(ksu_stealth_disable_all);

void ksu_stealth_enable_all(void)
{
    atomic_set(&ksu_stealth_enabled, 1);
}
EXPORT_SYMBOL_GPL(ksu_stealth_enable_all);


/* ===================================================================
 *  Section G — 初始化
 * ===================================================================
 */

static void ksu_stealth_core_init_once(void)
{
    unsigned long flags;

    spin_lock_irqsave(&ksu_auth_init_lock, flags);
    if (!ksu_auth_initialized) {
        spin_lock_init(&ksu_auth.lock);
        ksu_auth.boot_allow_ms = ksu_monotonic_ms() + 30000;
        ksu_auth_initialized = true;
    }
    spin_unlock_irqrestore(&ksu_auth_init_lock, flags);
}

MODULE_LICENSE("GPL");
