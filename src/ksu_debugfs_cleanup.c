// SPDX-License-Identifier: GPL-2.0
//
// kprobe / debugfs / ftrace 痕迹清理 — 极致隐藏版
//
// 优化点（vs 旧版）：
//   1. 移除明文符号关键词数组 — 改用 ksu_string_guard 的 hash 比较
//   2. 使用 ksu_caller_trusted() 替代 caller_should_see_hidden()
//   3. （移除反作弊进程差异化，统一隐藏策略）
//   4. tracing 过滤与 kprobes/kallsyms 复用同一 hash 比较
//
// 覆盖：
//   - /sys/kernel/debug/kprobes/list
//   - /sys/kernel/debug/kprobes/enabled
//   - /sys/kernel/debug/tracing/available_filter_functions
//   - /sys/kernel/debug/tracing/available_events
//   - /proc/kallsyms
//   - /proc/modules

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/kprobes.h>
#include <linux/ftrace.h>
#include <linux/tracepoint.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/cred.h>
#include <linux/version.h>
#include <linux/string.h>

#include "ksu_stealth_core.h"

/* 字符串守卫接口 */
extern bool ksu_sg_hidden_kprobe_sym(const char *s, size_t len);
extern bool ksu_sg_hidden_kallsyms_sym(const char *s, size_t len);
extern bool ksu_sg_hidden_module_name(const char *s, size_t len);
/* ===================================================================
 *  Section A — kprobes/list 行过滤
 * ===================================================================
 *
 * 行格式: "0xffff0000abcdef12  k  __arm64_sys_reboot+0x0/0x20 [MODULE]"
 * 提取 symbol 部分做 hash 匹配
 */

/* 从 kprobe 行中提取 symbol 部分：
 * 格式: "<addr>  <type>  <symbol>+<offset>/<size> [module]"
 * 提取 <symbol> 起始位置和长度
 */
static void ksu_extract_kprobe_sym(const char *line, size_t len,
                                    const char **sym_start, size_t *sym_len)
{
    size_t i;
    int space_count = 0;
    const char *sym = NULL;
    size_t slen = 0;

    *sym_start = NULL;
    *sym_len = 0;

    /* 跳过前导空白和地址，找到第二个空白后的符号 */
    for (i = 0; i < len; i++) {
        if (line[i] == ' ' || line[i] == '\t') {
            if (sym) {
                /* symbol 结束 */
                break;
            }
            space_count++;
            /* 跳过连续空白 */
            while (i + 1 < len && (line[i + 1] == ' ' || line[i + 1] == '\t'))
                i++;
            if (space_count == 2) {
                sym = &line[i + 1];
            }
        } else if (sym) {
            slen++;
            /* symbol 结束于 '+' 或空白 */
            if (line[i] == '+')
                break;
        }
    }

    if (sym && slen > 0) {
        *sym_start = sym;
        *sym_len = slen;
    }
}

bool ksu_kprobes_list_filter(const char *line, size_t line_len)
{
    const char *sym;
    size_t sym_len;

    if (!line || line_len == 0)
        return false;

    KSU_MODULE_CHECK(ksu_hide_debugfs_enabled);
    if (ksu_caller_trusted())
        return false;

    /* 整行 hash 子串匹配（兜底） */
    if (ksu_sg_hidden_kprobe_sym(line, line_len))
        return true;

    /* 提取 symbol 部分单独匹配（更精确） */
    ksu_extract_kprobe_sym(line, line_len, &sym, &sym_len);
    if (sym && sym_len > 0) {
        if (ksu_sg_hidden_kprobe_sym(sym, sym_len))
            return true;
    }

    return false;
}
EXPORT_SYMBOL_GPL(ksu_kprobes_list_filter);


/* ===================================================================
 *  Section B — /proc/kallsyms 符号过滤
 * ===================================================================
 */

bool ksu_kallsyms_filter(const char *sym_name)
{
    if (!sym_name)
        return false;

    KSU_MODULE_CHECK(ksu_hide_debugfs_enabled);
    if (ksu_caller_trusted())
        return false;

    /* 提取符号名（kallsyms 行格式 "ffff000080123456 T symbol_name"） */
    {
        const char *p = sym_name;
        const char *end = sym_name + strlen(sym_name);
        /* 跳过地址和类型字段，找 symbol 起始 */
        int space_count = 0;
        while (p < end) {
            if (*p == ' ' || *p == '\t') {
                space_count++;
                while (p < end && (*p == ' ' || *p == '\t'))
                    p++;
                if (space_count == 2)
                    break;
            } else {
                p++;
            }
        }

        if (p < end) {
            size_t plen = end - p;
            /* 截断到第一个空白或换行 */
            size_t i;
            for (i = 0; i < plen; i++) {
                if (p[i] == ' ' || p[i] == '\t' || p[i] == '\n' ||
                    p[i] == '\r' || p[i] == '\0')
                    break;
            }
            return ksu_sg_hidden_kallsyms_sym(p, i);
        }
    }

    /* 如果传入的本身就是符号名（不含地址前缀），直接 hash 比较 */
    return ksu_sg_hidden_kallsyms_sym(sym_name, strlen(sym_name));
}
EXPORT_SYMBOL_GPL(ksu_kallsyms_filter);


/* ===================================================================
 *  Section C — tracing 行过滤
 * ===================================================================
 *
 * tracing 文件包含的格式更宽松，我们做宽松的 hash 子串匹配
 */

bool ksu_tracing_line_filter(const char *line, size_t line_len)
{
    if (!line || line_len == 0)
        return false;

    KSU_MODULE_CHECK(ksu_hide_debugfs_enabled);
    if (ksu_caller_trusted())
        return false;

    /* 复用 kprobe 符号集合（包括 reboot, ksu_, susfs_, sukisu 等） */
    return ksu_sg_hidden_kprobe_sym(line, line_len);
}
EXPORT_SYMBOL_GPL(ksu_tracing_line_filter);


/* ===================================================================
 *  Section D — /proc/modules 行过滤
 * ===================================================================
 */

bool ksu_proc_modules_filter(const char *line)
{
    if (!line)
        return false;

    KSU_MODULE_CHECK(ksu_hide_debugfs_enabled);
    if (ksu_caller_trusted())
        return false;

    return ksu_sg_hidden_module_name(line, strlen(line));
}
EXPORT_SYMBOL_GPL(ksu_proc_modules_filter);


MODULE_LICENSE("GPL");
