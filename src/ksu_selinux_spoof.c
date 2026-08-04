// SPDX-License-Identifier: GPL-2.0
//
// SELinux 上下文伪装模块 — 极致隐藏版
//
// 优化点（vs 旧版）：
//   1. 移除明文 context 关键词数组 — 改用 ksu_string_guard 的 hash 比较
//   2. 假 context 字符串 ("u:r:system:s0") 用编译期混淆宏构造，不出现在 .rodata
//   3. 使用 ksu_caller_trusted() 替代 caller_should_see_hidden()
//   4. （移除反作弊进程差异化，统一返回 system context）
//
// 目标：
//   1. /proc/self/attr/current — 隐藏 u:r:su:s0 / u:r:magisk:s0 / u:r:kernelsu:s0 等
//   2. /proc/self/attr/prev    — 过滤 :zygote: 残留（检测器8）
//   3. /proc/self/attr/exec    — 同上
//   4. /sys/fs/selinux/enforce — 永远返回 Enforcing（即使被临时设为 permissive）
//   5. /sys/fs/selinux/policy  — policy hash 不暴露（防止与官方比对发现 patch）

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "ksu_stealth_core.h"

/* 字符串守卫接口 */
extern bool ksu_sg_hidden_selinux_ctx(const char *s, size_t len);

/* ===================================================================
 *  编译期混淆的"假 system context"字符串
 * ===================================================================
 *
 * "u:r:system:s0" 通过 KSU_OBF_DECL 在编译期 XOR 加密，运行时解密到栈缓冲区
 * 反作弊扫内核镜像找不到这个字符串
 */

/* "u:r:system:s0" - 长度 13 */
KSU_OBF_DECL(ksu_fake_system_ctx, "u:r:system:s0");


/* ===================================================================
 *  Section A — /proc/self/attr/current 伪装
 * ===================================================================
 *
 * 如果当前调用者不可信且其 SELinux context 含 root 关键词，
 * 返回伪装的 system context。
 * 返回的字符串由调用方负责 kfree()。
 */

char *ksu_spoof_selinux_context(const char *original)
{
    char *fake;
    size_t orig_len;

    if (!original)
        return NULL;

    /* 可信调用者：返回原始值 */
    if (ksu_caller_trusted())
        return NULL;

    orig_len = strlen(original);
    if (orig_len == 0 || orig_len > 256)
        return NULL;

    /* hash 比较检查是否含 root context 关键词 */
    if (!ksu_sg_hidden_selinux_ctx(original, orig_len))
        return NULL;

    /* 统一返回 system context — 不区分进程类型，避免侧信道暴露 */
    {
        char ctx_buf[16];
        KSU_DEOBF(ksu_fake_system_ctx, ctx_buf);
        fake = kstrdup(ctx_buf, GFP_KERNEL);
        KSU_WIPE(ctx_buf);
    }

    return fake;
}
EXPORT_SYMBOL_GPL(ksu_spoof_selinux_context);


/* ===================================================================
 *  Section B — /proc/self/attr/prev 过滤 :zygote: 残留
 * ===================================================================
 */

bool ksu_attr_prev_has_hidden(const char *prev_context, size_t len)
{
    if (!prev_context || len == 0)
        return false;

    if (ksu_caller_trusted())
        return false;

    /* hash 比较同时覆盖 :zygote: 和所有 root context 关键词 */
    return ksu_sg_hidden_selinux_ctx(prev_context, len);
}
EXPORT_SYMBOL_GPL(ksu_attr_prev_has_hidden);


/* ===================================================================
 *  Section C — /sys/fs/selinux/enforce 伪装
 * ===================================================================
 */

int ksu_spoof_enforce(int real_enforce)
{
    if (ksu_caller_trusted())
        return real_enforce;

    /* 永远返回 Enforcing */
    return 1;
}
EXPORT_SYMBOL_GPL(ksu_spoof_enforce);


/* ===================================================================
 *  Section D — SELinux 行级过滤（用于 seq_file 输出）
 * ===================================================================
 */

bool ksu_selinux_attr_line_filter(const char *line, size_t len)
{
    if (!line || len == 0)
        return false;

    if (ksu_caller_trusted())
        return false;

    return ksu_sg_hidden_selinux_ctx(line, len);
}
EXPORT_SYMBOL_GPL(ksu_selinux_attr_line_filter);


MODULE_LICENSE("GPL");
