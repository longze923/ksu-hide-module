// /proc/<pid>/mounts & mountinfo 行级过滤模块
//
// 虽然SUSFS sus_mount已做挂载隐藏，但作为纵深防御：
// 在 seq_file 输出层再做一次关键词过滤
// 确保任何包含 ksu/susfs/magisk/zygisk 等关键词的挂载行
// 都不会出现在目标进程的 /proc/self/mounts 中
//
// 所有关键词使用 hash 子串匹配，明文不出现在 .rodata

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/mount.h>
#include <linux/nsproxy.h>
#include <linux/mnt_namespace.h>
#include <linux/cred.h>
#include <linux/string.h>
#include <linux/slab.h>

#include "ksu_stealth_core.h"

// 外部符号
extern bool caller_should_see_hidden(void);

// ---- 过滤 /proc/<pid>/mounts 的一行 ----
// 在 seq_printf 输出一行前调用
// 返回 true = 该行应被跳过（不输出）
bool ksu_mounts_line_filter(const char *line, size_t len)
{
    if (caller_should_see_hidden())
        return false;

    if (!line || len == 0)
        return false;

    // 使用 hash 子串匹配，不暴露明文关键词
    return ksu_sg_contains_keyword(line, len);
}
EXPORT_SYMBOL_GPL(ksu_mounts_line_filter);

// ---- 过滤 /proc/<pid>/mountinfo 的一行 ----
bool ksu_mountinfo_line_filter(const char *line, size_t len)
{
    return ksu_mounts_line_filter(line, len);
}
EXPORT_SYMBOL_GPL(ksu_mountinfo_line_filter);

// ---- 过滤 /proc/<pid>/mountstats 的一行 ----
bool ksu_mountstats_line_filter(const char *line, size_t len)
{
    return ksu_mounts_line_filter(line, len);
}
EXPORT_SYMBOL_GPL(ksu_mountstats_line_filter);

// ---- 额外：过滤 /proc/filesystems ----
bool ksu_filesystems_line_filter(const char *line, size_t len)
{
    if (caller_should_see_hidden())
        return false;
    if (!line || len == 0)
        return false;

    // 文件系统名可能包含 ksu/susfs 等关键词
    return ksu_sg_contains_keyword(line, len);
}
EXPORT_SYMBOL_GPL(ksu_filesystems_line_filter);

MODULE_LICENSE("GPL");
