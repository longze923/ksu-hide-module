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

    if (ksu_caller_trusted())
        return false;

    /* 复用 kprobe 符号集合 (ksu_, susfs_, sukisu_ 等) */
    return ksu_sg_hidden_kprobe_sym(line, len);
}
EXPORT_SYMBOL_GPL(ksu_iomem_line_filter);


/* ===================================================================
 *  Section B — /proc/ioports 行过滤
 * ===================================================================
 *
 * arm64 通常没有 I/O ports，但部分设备有
 * 格式与 /proc/iomem 类似
 */

bool ksu_ioports_line_filter(const char *line, size_t len)
{
    if (!line || len == 0)
        return false;

    if (ksu_caller_trusted())
        return false;

    return ksu_sg_hidden_kprobe_sym(line, len);
}
EXPORT_SYMBOL_GPL(ksu_ioports_line_filter);


/* ===================================================================
 *  Section C — /proc/cmdline 缓存与伪装
 * ===================================================================
 *
 * SUSFS 已有 CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG 处理 cmdline，
 * 但只对 SUSFS 配置的进程生效。本模块做兜底：
 *   - 内核启动时缓存 utsname 中的 cmdline
 *   - 对不可信调用者返回缓存值
 */

static char ksu_cmdline_cache[COMMAND_LINE_SIZE];
static DEFINE_SPINLOCK(ksu_cmdline_lock);

/* 每次实时读取 boot_command_line（SUSFS spoof 后的值）
 * 不做一次性缓存，避免在 SUSFS spoof 之前缓存到原始值
 */
static const char *ksu_get_safe_cmdline_internal(void)
{
    unsigned long flags;
    const char *result;

    spin_lock_irqsave(&ksu_cmdline_lock, flags);
    strscpy(ksu_cmdline_cache, boot_command_line, sizeof(ksu_cmdline_cache));
    result = ksu_cmdline_cache;
    spin_unlock_irqrestore(&ksu_cmdline_lock, flags);

    return result;
}

/* 检查 cmdline 中是否有 KSU/SUSFS 痕迹
 * 如果有，需要做清洗 (移除可疑参数)
 */
bool ksu_cmdline_has_hidden_token(const char *cmdline, size_t len)
{
    if (!cmdline || len == 0)
        return false;

    /* 检查常见 KSU/SUSFS 添加的 cmdline 参数 */
    /* 这些 token 用 hash 比较，不暴露明文 */
    if (ksu_sg_hidden_kprobe_sym(cmdline, len))
        return true;

    return false;
}
EXPORT_SYMBOL_GPL(ksu_cmdline_has_hidden_token);

/* 获取 spoofed cmdline
 * 返回的指针指向静态缓冲区，调用者不能修改且不能跨函数持有
 */
const char *ksu_get_safe_cmdline(void)
{
    if (ksu_caller_trusted()) {
        return boot_command_line;
    }

    return ksu_get_safe_cmdline_internal();
}
EXPORT_SYMBOL_GPL(ksu_get_safe_cmdline);


/* ===================================================================
 *  Section D — /proc/version 伪装
 * ===================================================================
 *
 * /proc/version 格式:
 *   "Linux version 5.15.123-android13-8-00100-xxx (builder@xxx) ..."
 *
 * 自编译内核会暴露编译器版本、编译时间戳、编译者邮箱等，与官方不一致
 * SUSFS 的 SPOOF_UNAME 处理 utsname，但 /proc/version 由 proc_version_init
 * 单独生成，可能未被 spoof
 *
 * 本模块提供 /proc/version 输出过滤接口
 */

static char ksu_version_cache[256];
static bool ksu_version_cached;
static DEFINE_SPINLOCK(ksu_version_lock);

/* linux_banner 是内核编译时生成的 /proc/version 原始字符串
 * 格式: "Linux version X.Y.Z (builder@host) (gcc ...) ..."
 * 我们从中提取 builder@host 部分，与 SUSFS spoof 后的 utsname 重组
 */
extern const char linux_banner[];

/* 缓存官方 /proc/version 字符串 (SUSFS spoof 后)
 * 启动时由本模块的 init 调用
 */
static void ksu_cache_version_once(void)
{
    unsigned long flags;
    spin_lock_irqsave(&ksu_version_lock, flags);
    if (!ksu_version_cached) {
        struct new_utsname *u = utsname();
        const char *banner = linux_banner;
        char builder[80] = {0};
        const char *p1, *p2;

        /* 从 linux_banner 提取 (builder@host) 部分
         * 格式: "Linux version 5.15.X (builder@host) (gcc ..."
         * 找第一个 '(' 和第二个 '(' 之间的内容
         */
        p1 = strchr(banner, '(');
        if (p1) {
            p2 = strchr(p1 + 1, ')');
            if (p2 && (p2 - p1) < sizeof(builder)) {
                strncpy(builder, p1 + 1, p2 - p1 - 1);
                builder[p2 - p1 - 1] = '\0';
            }
        }

        /* 用 SUSFS spoof 后的 utsname 值 + 原始 builder 重组 */
        if (builder[0]) {
            snprintf(ksu_version_cache, sizeof(ksu_version_cache),
                     "Linux version %s (%s) %s",
                     u->release, builder, u->version);
        } else {
            /* 提取失败，回退到直接用 linux_banner */
            strscpy(ksu_version_cache, banner, sizeof(ksu_version_cache));
        }
        ksu_version_cached = true;
    }
    spin_unlock_irqrestore(&ksu_version_lock, flags);
}

/* 获取 spoofed version 字符串
 * 调用方在 /proc/version 的 seq_show 中调用
 */
const char *ksu_get_safe_version(void)
{
    if (ksu_caller_trusted()) {
        /* 可信调用者看到真实 version */
        return NULL;  /* NULL = 不修改，使用原始 */
    }

    ksu_cache_version_once();
    return ksu_version_cached ? ksu_version_cache : NULL;
}
EXPORT_SYMBOL_GPL(ksu_get_safe_version);


/* ===================================================================
 *  Section E — /proc/sys/kernel/ * 关键参数过滤
 * ===================================================================
 *
 * 反作弊会读 /proc/sys/kernel/hostname, /proc/sys/kernel/osrelease,
 * /proc/sys/kernel/version, /proc/sys/kernel/random/boot_id 等
 *
 * SUSFS 的 SPOOF_UNAME 已处理 hostname/osrelease/version
 * /proc/sys/kernel/random/boot_id 是随机 UUID，无需 spoof
 *
 * 这里仅作为兜底接口
 */

bool ksu_kernel_sysctl_filter(const char *path, const char **replacement)
{
    if (!path || !replacement)
        return false;

    *replacement = NULL;

    if (ksu_caller_trusted())
        return false;

    /* 不做替换，由 SUSFS 处理 */
    return false;
}
EXPORT_SYMBOL_GPL(ksu_kernel_sysctl_filter);


/* ===================================================================
 *  Section F — /proc/kcore 防护
 * ===================================================================
 *
 * /proc/kcore 暴露整个内核内存，反作弊可读取发现 KSU 代码段
 * 但 /proc/kcore 需要 CAP_SYSLOG，普通 app 不可读
 *
 * 对 root 进程：返回过滤后的视图 (空)
 * 对 manager：返回真实内容
 */

bool ksu_kcore_block(void)
{
    if (ksu_caller_trusted())
        return false;

    /* 对不可信调用者直接拒绝 /proc/kcore */
    return true;
}
EXPORT_SYMBOL_GPL(ksu_kcore_block);


MODULE_LICENSE("GPL");
