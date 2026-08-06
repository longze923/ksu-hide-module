// SPDX-License-Identifier: GPL-2.0
//
// ksu_iomem_cmdline_spoof.c — /proc/iomem, /proc/ioports, /proc/cmdline 伪装
//
// 防御的检测向量：
//   1. /proc/iomem — 内存映射表，可能暴露 KSU 保留的内存区域
//      反作弊扫所有内存区域，找异常保留区
//   2. /proc/ioports — I/O 端口映射（arm64 通常为空，但部分设备有）
//   3. /proc/cmdline — 内核启动参数，SukiSU/SUSFS 可能添加自定义参数
//      反作弊与官方 cmdline 比对，发现差异即判定为 root
//   4. /proc/version — 内核版本字符串，编译信息可能暴露 patch
//   5. /proc/sys/kernel/* — 各种内核参数，可能与官方不同
//
// 对策：
//   - 用 hash 比对过滤 /proc/iomem 中包含 ksu/susfs 关键词的行
//   - /proc/cmdline 在启动时缓存官方 cmdline (SUSFS 已 spoof)，对外返回缓存
//   - /proc/version 同样缓存官方字符串
//
// 注意：SUSFS 的 SPOOF_CMDLINE_OR_BOOTCONFIG 已处理大部分 cmdline 场景，
// 本模块作为兜底层，处理 SUSFS 未覆盖的边界情况。

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/cred.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/utsname.h>
#include <linux/version.h>
#include <asm/setup.h>

#include "ksu_stealth_core.h"

/* 字符串守卫接口 */
extern bool ksu_sg_hidden_kprobe_sym(const char *s, size_t len);
extern bool ksu_sg_hidden_mount_line(const char *line, size_t len);


/* ===================================================================
 *  Section A — /proc/iomem 行过滤
 * ===================================================================
 *
 * /proc/iomem 格式:
 *   "  10000000-1fffffff : System RAM"
 *   "  10008000-10008fff : ksu_region"
 *
 * 过滤包含 ksu_/susfs_/sukisu_ 等关键词的行
 */

bool ksu_iomem_line_filter(const char *line, size_t len)
{
    if (!line || len == 0)
        return false;

    KSU_MODULE_CHECK(ksu_hide_iomem_enabled);

    if (ksu_caller_trusted())
        return false;

    /* 复用 kprobe 符号集合 (ksu_, susfs_, sukisu_ 等) */
    return ksu_sg_hidden_kprobe_sym(line, len);
}
EXPORT_SYMBOL_GPL(ksu_iomem_line_filter);


MODULE_LICENSE("GPL");
