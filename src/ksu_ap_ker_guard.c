// ap_ker 防御模块 — 对抗检测器12的页驻留探针
//
// 攻击原理：
//   1. 检测器 mmap 一页匿名内存，写入已知模式
//   2. madvise(MADV_DONTNEED) 驱逐页
//   3. mincore 确认页未驻留
//   4. 发起 syscall(45, probe_page, -1) 即 truncate(path=probe_page, length=-1)
//      或其他带用户指针参数的 syscall
//   5. 如果内核有 hook 在 fd/参数校验前解引用了 probe_page 指针，
//      页被 fault-in 重新驻留
//   6. mincore 检测到页驻留 → 判定内核被 hook
//
// 防御策略（三层）：
//   层1: mincore 侧 — 在 madvise(MADV_DONTNEED) 路径注入，记录被驱逐的页，
//        后续该进程的 mincore 对这些页强制返回「未驻留」
//   层2: 截断路径侧 — 确保 truncate/ftruncate/at syscall 在 fd 校验前
//        不解引用用户指针（通过审计 hook 注入点）
//   层3: 通用侧 — 对所有我们的 hook 增加「指针有效性预检」，
//        不在标准校验前碰用户空间。使用 access_ok 做纯地址范围校验，
//        不触发页 fault-in

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <linux/cred.h>
#include <linux/pagemap.h>
#include <linux/version.h>
#include <linux/hashtable.h>
#include "ksu_stealth_core.h"

// 外部符号
extern bool caller_should_see_hidden(void);

// ---- 层1: mincore 探针检测 ----
//
// 检测器的典型模式：
//   madvise(addr, PAGE_SIZE, MADV_DONTNEED)  → 驱逐
//   mincore(addr, PAGE_SIZE, &vec)           → vec[0]=0 (未驻留)
//   syscall(45, addr, -1)                     → 触发 hook 解引用
//   mincore(addr, PAGE_SIZE, &vec)           → vec[0]=1 (驻留了!) → 命中
//
// 防御：记录「最近被 MADV_DONTNEED 的单页匿名映射」，
// 在后续 mincore 中对这些页强制返回 0（未驻留）
//
// 注入点：madvise 的 MADV_DONTNEED/MADV_REMOVE 路径末尾调用
// ksu_probe_on_madvise_dontneed() 来注册被驱逐的页

#define KSU_PROBE_HASH_BITS 8
#define KSU_PROBE_HASH_SIZE (1 << KSU_PROBE_HASH_BITS)
#define KSU_PROBE_ENTRY_TTL_MS 5000  // 5秒后过期

struct ksu_probe_entry {
    unsigned long addr;        // 被驱逐的页地址
    struct mm_struct *mm;      // 所属进程的 mm
    u64 timestamp_ms;          // 驱逐时间
    struct hlist_node node;
};

static DEFINE_HASHTABLE(ksu_probe_hash, KSU_PROBE_HASH_BITS);
static DEFINE_SPINLOCK(ksu_probe_lock);

static u64 ksu_get_time_ms(void)
{
    return ktime_to_ms(ktime_get_boottime_ns());
}

static unsigned int ksu_probe_hash_fn(unsigned long addr, struct mm_struct *mm)
{
    return hash_long(addr ^ (unsigned long)mm, KSU_PROBE_HASH_BITS);
}

// 在 madvise(MADV_DONTNEED) 路径末尾调用，注册被驱逐的页
void ksu_probe_on_madvise_dontneed(unsigned long addr, size_t len,
                                    struct mm_struct *mm)
{
    struct ksu_probe_entry *entry;
    unsigned long flags;
    unsigned int bucket;

    if (!atomic_read(&ksu_hide_ap_ker_enabled)) return;

    if (!mm || !addr)
        return;

    // 只关注检测器的典型模式：1 页匿名映射
    if (len != PAGE_SIZE)
        return;

    entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
    if (!entry)
        return;

    entry->addr = addr & PAGE_MASK;
    entry->mm = mm;
    entry->timestamp_ms = ksu_get_time_ms();

    spin_lock_irqsave(&ksu_probe_lock, flags);
    bucket = ksu_probe_hash_fn(entry->addr, mm);
    // 先清理同地址旧条目
    {
        struct ksu_probe_entry *old;
        struct hlist_node *tmp;
        hlist_for_each_entry_safe(old, tmp, &ksu_probe_hash[bucket], node) {
            if (old->addr == entry->addr && old->mm == mm) {
                hlist_del(&old->node);
                kfree(old);
                break;
            }
        }
    }
    hash_add(ksu_probe_hash, &entry->node, bucket);
    spin_unlock_irqrestore(&ksu_probe_lock, flags);
}
EXPORT_SYMBOL_GPL(ksu_probe_on_madvise_dontneed);

// 检查某页是否应该被 mincore 报告为「未驻留」
// 在 mincore 的 filldump 路径中调用
bool ksu_probe_should_hide_resident(unsigned long addr, struct mm_struct *mm)
{
    struct ksu_probe_entry *entry;
    struct hlist_node *tmp;
    unsigned long flags;
    unsigned int bucket;
    bool hide = false;
    u64 now;

    if (!mm || !addr)
        return false;

    KSU_MODULE_CHECK(ksu_hide_ap_ker_enabled);
    if (caller_should_see_hidden())
        return false;

    now = ksu_get_time_ms();
    addr = addr & PAGE_MASK;

    spin_lock_irqsave(&ksu_probe_lock, flags);
    bucket = ksu_probe_hash_fn(addr, mm);
    hlist_for_each_entry_safe(entry, tmp, &ksu_probe_hash[bucket], node) {
        if (entry->addr == addr && entry->mm == mm) {
            // 在 TTL 窗口内，强制报告未驻留
            if (now - entry->timestamp_ms < KSU_PROBE_ENTRY_TTL_MS) {
                hide = true;
            } else {
                // 过期，删除
                hlist_del(&entry->node);
                kfree(entry);
            }
            break;
        }
    }
    spin_unlock_irqrestore(&ksu_probe_lock, flags);

    return hide;
}
EXPORT_SYMBOL_GPL(ksu_probe_should_hide_resident);

// ---- 层2: truncate 路径保护 ----
//
// 审计点：确保 KSU/SUSFS 的 hook 不在 sys_truncate 的 fd 校验前执行
// 这个函数在 truncate/ftruncate 的 hook 入口被调用，
// 如果 fd 无效或 length 异常，直接放行到原生路径，不做任何处理
bool ksu_truncate_hook_guard(int fd, unsigned long length)
{
    // fd < 0 → 标准内核会返回 EBADF，不要在此前做任何 hook
    if (fd < 0)
        return false;  // false = 不执行 hook 逻辑，放行
    // length == (unsigned long)-1 → 无效参数
    if (length == (unsigned long)-1)
        return false;
    return true;  // true = 可以执行 hook
}
EXPORT_SYMBOL_GPL(ksu_truncate_hook_guard);

// ---- 层3: 通用用户指针安全检查 ----
//
// 所有我们的 hook 在访问用户指针前调用此函数
// 使用 access_ok 做纯地址范围校验，不触发页 fault-in
// 不调用 get_user_pages_fast / follow_page，避免任何页表操作
bool ksu_safe_user_ptr_check(const void __user *ptr, size_t size)
{
    unsigned long addr = (unsigned long)ptr;
    struct mm_struct *mm = current->mm;

    if (!ptr || !mm)
        return false;

    // 检查指针范围是否在用户空间
    if (addr + size < addr)
        return false;
    if (addr >= TASK_SIZE)
        return false;
    if (size == 0)
        return false;

    // 纯地址范围校验，不碰页表，不触发 fault-in
    return access_ok((const void __user *)addr, size);
}
EXPORT_SYMBOL_GPL(ksu_safe_user_ptr_check);

// ---- 清理过期条目（定期调用）----
void ksu_probe_cleanup_expired(void)
{
    struct ksu_probe_entry *entry;
    struct hlist_node *tmp;
    unsigned long flags;
    int i;
    u64 now;

    if (!atomic_read(&ksu_hide_ap_ker_enabled)) return;
    now = ksu_get_time_ms();

    spin_lock_irqsave(&ksu_probe_lock, flags);
    hash_for_each_safe(ksu_probe_hash, i, tmp, entry, node) {
        if (now - entry->timestamp_ms >= KSU_PROBE_ENTRY_TTL_MS) {
            hash_del(&entry->node);
            kfree(entry);
        }
    }
    spin_unlock_irqrestore(&ksu_probe_lock, flags);
}
EXPORT_SYMBOL_GPL(ksu_probe_cleanup_expired);

MODULE_LICENSE("GPL");
