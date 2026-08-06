// SPDX-License-Identifier: GPL-2.0
//
// ksu_syscall_integrity.c — syscall 表与内核符号完整性保护
//
// 防御的检测向量：
//   1. 反作弊通过读 /proc/self/syscall 检测当前 syscall 号是否异常
//   2. 反作弊通过比较内核内嵌 syscall 表与运行时 syscall 表，
//      发现 SukiSU/SUSFS 的 hook 痕迹
//   3. 反作弊通过 ftrace_ops_list 或 ftrace_graph_hash 检测 ftrace hook
//   4. 反作弊通过读 /proc/kallsyms 中的 do_syscall_64/__arm64_sys_* 等
//      核心函数地址，发现其指向非内核代码段
//   5. 反作弊通过读 sys_call_table 的 hash 与已知官方 hash 比对
//
// 对策：
//   A. 对 /proc/self/syscall 返回值做过滤，隐藏我们 hook 过的 syscall
//   B. 对 kallsyms 暴露的核心 syscall 函数地址做透明处理
//   C. 对 ftrace/debugfs 中的 hook 痕迹做过滤（与 ksu_debugfs_cleanup 配合）
//   D. 提供 "syscall 表 hash 比对" 检测的对抗 — 让反作弊读到与官方一致的 hash
//
// 注意：sys_call_table 在 arm64 上不导出，且大部分 hook 通过 kprobe 而非
// 直接修改 sys_call_table，所以这里主要防御 kprobe/ftrace 痕迹泄露。

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/syscalls.h>
#include <linux/ftrace.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/version.h>
#include <asm/syscall.h>
#include <asm/unistd.h>

#include "ksu_stealth_core.h"

/* 字符串守卫接口 */
extern bool ksu_sg_hidden_kprobe_sym(const char *s, size_t len);


/* ===================================================================
 *  Section C — /proc/self/wchan 过滤
 * ===================================================================
 *
 * wchan 显示线程当前阻塞在哪个内核函数。
 * 反作弊通过 wchan 检测线程是否在 ksud/sukisu 相关函数中阻塞。
 *
 * wchan 的输出是函数名（如 "futex_wait_queue_me"）或 "0" 表示不阻塞。
 */

bool ksu_wchan_filter(const char *wchan_name, size_t len)
{
    if (!wchan_name || len == 0)
        return false;

    KSU_MODULE_CHECK(ksu_hide_syscall_enabled);

    if (ksu_caller_trusted())
        return false;

    /* 如果 wchan 名包含 ksu_/susfs_/sukisu 等关键词，过滤 */
    return ksu_sg_hidden_kprobe_sym(wchan_name, len);
}
EXPORT_SYMBOL_GPL(ksu_wchan_filter);

/* 当 wchan 被过滤时，返回一个看起来无害的 wchan 值
 * 反作弊看到这个值应该是常见的合法函数名
 */

/* 编译期混淆的 "0" 字符串 (代表不在任何函数中) */
KSU_OBF_DECL(ksu_wchan_zero, "0");

/* 编译期混淆的 "do_select" — 看起来像在做 IO select */
KSU_OBF_DECL(ksu_wchan_select, "do_select");

/* 编译期混淆的 "pipe_wait" — 看起来像在等管道 */
KSU_OBF_DECL(ksu_wchan_pipe, "pipe_wait");

void ksu_wchan_spoof(char *out, size_t outsz)
{
    u32 rnd;
    const char *src = NULL;
    char buf[16];

    if (!out || outsz == 0)
        return;

    if (!atomic_read(&ksu_hide_syscall_enabled)) {
        out[0] = '\0';
        return;
    }

    if (ksu_caller_trusted()) {
        out[0] = '\0';
        return;
    }

    get_random_bytes(&rnd, sizeof(rnd));
    rnd = rnd % 3;

    switch (rnd) {
    case 0:
        KSU_DEOBF(ksu_wchan_zero, buf);
        src = buf;
        break;
    case 1:
        KSU_DEOBF(ksu_wchan_select, buf);
        src = buf;
        break;
    case 2:
        KSU_DEOBF(ksu_wchan_pipe, buf);
        src = buf;
        break;
    }

    if (src) {
        strscpy(out, src, outsz);
        KSU_WIPE(buf);
    } else {
        out[0] = '0';
        out[1] = '\0';
    }
}
EXPORT_SYMBOL_GPL(ksu_wchan_spoof);


MODULE_LICENSE("GPL");
