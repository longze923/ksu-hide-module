// namespace inode mtime 对齐模块 — 对抗检测器9 (magic_delta)
//
// 攻击原理：
//   fstatat("/proc/self/ns/mnt", AT_SYMLINK_NOFOLLOW) → mnt.st_mtim
//   fstatat("/proc/self/ns/net", AT_SYMLINK_NOFOLLOW) → net.st_mtim
//   if (mnt.st_mtim.tv_sec + 1 < net.st_mtim.tv_sec) → 命中
//
// 当 SukiSU/SUSFS 对目标进程做 mount namespace 隔离时，
// /proc/self/ns/mnt 的时间戳可能与 /proc/self/ns/net 不一致
//
// 防御策略：
//   在 nsfs 的 getattr 回调中，对所有 namespace inode 的 st_mtim
//   返回统一值（进程创建时间或一个固定的早期时间）
//   确保任意两个 ns inode 的 mtime 差 < 1 秒

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/cred.h>
#include <linux/time.h>
#include <linux/nsproxy.h>
#include <linux/proc_ns.h>
#include <linux/version.h>

// 外部符号
extern bool caller_should_see_hidden(void);

// ---- 基线时间：内核启动后 1 秒，作为所有 ns inode 的统一 mtime ----
// 这样所有 ns inode 看起来都是在内核启动后 1 秒创建的
// 互相之间的差 = 0，远小于 1 秒阈值
static struct timespec64 ksu_ns_baseline_mtime;

static int ksu_ns_baseline_inited = 0;
static DEFINE_SPINLOCK(ksu_ns_init_lock);

static void ksu_init_ns_baseline(void)
{
    unsigned long flags;

    spin_lock_irqsave(&ksu_ns_init_lock, flags);
    if (ksu_ns_baseline_inited) {
        spin_unlock_irqrestore(&ksu_ns_init_lock, flags);
        return;
    }

    // 用内核启动时间 + 1 秒作为基线
    // 这样 ns inode 的 mtime 在所有进程看来都一致
    // 注意: ktime_to_seconds() 在 5.15 内核中不存在 (ktime.h 只提供
    // ktime_to_ns/us/ms)。直接用 ktime_get_boottime_ts64() 获取 timespec64。
    ktime_get_boottime_ts64(&ksu_ns_baseline_mtime);
    ksu_ns_baseline_mtime.tv_sec += 1;
    ksu_ns_baseline_mtime.tv_nsec = 0;

    ksu_ns_baseline_inited = 1;
    spin_unlock_irqrestore(&ksu_ns_init_lock, flags);
}

// ---- 对 /proc/self/ns/* 的 stat 结果做 mtime 对齐 ----
//
// 调用时机：在 nsfs_getattr 或 proc_ns_getattr 返回前
// 对 stat 中的 mtime/ctime/atime 强制覆盖
//
// 参数：
//   stat - 内核已填充的 kstat
//   inode - 被查询的 ns inode
//
// 返回：true 如果修改了 stat（调用方据此决定是否覆盖）

bool ksu_ns_align_mtime(struct kstat *stat, struct inode *inode)
{
    if (!stat || !inode)
        return false;

    KSU_MODULE_CHECK(ksu_hide_ns_mtime_enabled);
    if (caller_should_see_hidden())
        return false;

    ksu_init_ns_baseline();

    // 强制覆盖 mtime、ctime、atime 为基线值
    // atime 设为和 mtime 相同，避免 atime > mtime 的异常
    stat->mtime.tv_sec = ksu_ns_baseline_mtime.tv_sec;
    stat->mtime.tv_nsec = ksu_ns_baseline_mtime.tv_nsec;
    stat->ctime.tv_sec = ksu_ns_baseline_mtime.tv_sec;
    stat->ctime.tv_nsec = ksu_ns_baseline_mtime.tv_nsec;
    stat->atime.tv_sec = ksu_ns_baseline_mtime.tv_sec;
    stat->atime.tv_nsec = ksu_ns_baseline_mtime.tv_nsec;

    return true;
}
EXPORT_SYMBOL_GPL(ksu_ns_align_mtime);

// ---- 更精细版：对特定 ns 类型做对齐 ----
// 即使检测器改用 /proc/self/ns/user 或 /proc/self/ns/pid
// 也全部对齐
bool ksu_ns_align_mtime_by_name(struct kstat *stat, const char *ns_name)
{
    // 对所有 ns 类型都做对齐
    if (!stat || !ns_name)
        return false;

    KSU_MODULE_CHECK(ksu_hide_ns_mtime_enabled);
    if (caller_should_see_hidden())
        return false;

    ksu_init_ns_baseline();

    stat->mtime.tv_sec = ksu_ns_baseline_mtime.tv_sec;
    stat->mtime.tv_nsec = ksu_ns_baseline_mtime.tv_nsec;
    stat->ctime.tv_sec = ksu_ns_baseline_mtime.tv_sec;
    stat->ctime.tv_nsec = ksu_ns_baseline_mtime.tv_nsec;
    stat->atime.tv_sec = ksu_ns_baseline_mtime.tv_sec;
    stat->atime.tv_nsec = ksu_ns_baseline_mtime.tv_nsec;

    return true;
}
EXPORT_SYMBOL_GPL(ksu_ns_align_mtime_by_name);

MODULE_LICENSE("GPL");
