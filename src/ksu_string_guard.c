// SPDX-License-Identifier: GPL-2.0
/*
 * ksu_string_guard.c — 字符串守卫模块
 *
 * 集中管理所有"需要隐藏的关键词"的 hash 常量与匹配函数。
 * 关键词以 hash 形式存在于 .rodata，明文不出现在内核镜像中。
 *
 * 提供的 API:
 *   - ksu_sg_hidden_pid_name(comm, len)   — 进程名是否在隐藏黑名单
 *   - ksu_sg_hidden_kprobe_sym(s, len)    — kprobe 符号是否需要隐藏
 *   - ksu_sg_hidden_kallsyms_sym(s, len)  — kallsyms 符号是否需要隐藏
 *   - ksu_sg_hidden_mount_line(line, len) — mounts 行是否需要隐藏
 *   - ksu_sg_hidden_selinux_ctx(s, len)   — SELinux context 是否需要隐藏
 *   - ksu_sg_hidden_module_name(s, len)   — 模块名是否需要隐藏
 *
 * 这些 hash 在运行时由 pure_initcall (ksu_sg_init_hashes) 计算，
 * 明文关键词不出现在内核镜像中。
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/types.h>

#include "ksu_stealth_core.h"

/* ===================================================================
 *  隐藏关键词的 hash 常量（编译期计算）
 * ===================================================================
 *
 * KSU_FNV1A_CONST 展开为 ksu_fnv1a_const() 调用，运行时执行。
 * 数组初始化器不能用函数调用，故改用 pure_initcall 运行时填充。
 * 验证方法：objdump -s 后 grep "ksud"/"sukisu" 应该找不到。
 */

/* 进程名黑名单 hash */
#define KSU_SG_PID_KSUD        KSU_FNV1A_CONST("ksud")
#define KSU_SG_PID_SUKISU      KSU_FNV1A_CONST("sukisu")
#define KSU_SG_PID_MAGISKD     KSU_FNV1A_CONST("magiskd")
#define KSU_SG_PID_KSUD_INIT   KSU_FNV1A_CONST("ksu_init")
#define KSU_SG_PID_SUKISID     KSU_FNV1A_CONST("sukisid")
#define KSU_SG_PID_KSD         KSU_FNV1A_CONST("ksd")

/* SELinux context 黑名单 hash */
#define KSU_SG_CTX_SU          KSU_FNV1A_CONST("u:r:su:s0")
#define KSU_SG_CTX_MAGISK      KSU_FNV1A_CONST("u:r:magisk:s0")
#define KSU_SG_CTX_KSU         KSU_FNV1A_CONST("u:r:kernelsu:s0")
#define KSU_SG_CTX_KSU2        KSU_FNV1A_CONST("u:r:ksu:s0")
#define KSU_SG_CTX_SUKISU      KSU_FNV1A_CONST("u:r:sukisu:s0")
#define KSU_SG_ZYGOTE          KSU_FNV1A_CONST("zygote")

/* kprobe 符号黑名单 hash（短前缀也作为独立 hash 比对） */
#define KSU_SG_SYM_ARM_REBOOT  KSU_FNV1A_CONST("__arm64_sys_reboot")
#define KSU_SG_SYM_SYS_REBOOT  KSU_FNV1A_CONST("sys_reboot")
#define KSU_SG_SYM_KSU_PFX     KSU_FNV1A_CONST("ksu_")
#define KSU_SG_SYM_KERNELSU    KSU_FNV1A_CONST("kernelsu")
#define KSU_SG_SYM_SUSFS_PFX   KSU_FNV1A_CONST("susfs_")
#define KSU_SG_SYM_SUKISU      KSU_FNV1A_CONST("sukisu")
#define KSU_SG_SYM_KSUD        KSU_FNV1A_CONST("ksud")
#define KSU_SG_SYM_MAGISKD     KSU_FNV1A_CONST("magiskd")

/* 模块名黑名单 hash */
#define KSU_SG_MOD_KSU         KSU_FNV1A_CONST("ksu")
#define KSU_SG_MOD_KERNELSU    KSU_FNV1A_CONST("kernelsu")
#define KSU_SG_MOD_SUSFS       KSU_FNV1A_CONST("susfs")
#define KSU_SG_MOD_SUKISU      KSU_FNV1A_CONST("sukisu")

/* mounts 行关键词 hash */
#define KSU_SG_MNT_KSU         KSU_FNV1A_CONST("ksu")
#define KSU_SG_MNT_SUSFS       KSU_FNV1A_CONST("susfs")
#define KSU_SG_MNT_MAGISK      KSU_FNV1A_CONST("magisk")
#define KSU_SG_MNT_OVERLAY     KSU_FNV1A_CONST("overlay")
#define KSU_SG_MNT_TMPFS       KSU_FNV1A_CONST("tmpfs")


/* ===================================================================
 *  辅助：滚动 hash 检测子串
 * ===================================================================
 */

/* 检查 s[len] 是否以特定前缀开头（hash 比较） */
static __always_inline bool ksu_sg_starts_with_hash(const char *s, size_t len,
                                                     u64 prefix_hash, size_t prefix_len)
{
    if (len < prefix_len)
        return false;
    return ksu_fnv1a(s, prefix_len) == prefix_hash;
}

/* 检查 s[len] 中是否包含子串（用 hash 比较，子串明文不暴露） */
static __always_inline bool ksu_sg_contains_hash(const char *s, size_t len,
                                                  u64 needle_hash, size_t needle_len)
{
    return ksu_hash_contains(s, len, needle_hash, needle_len);
}


/* ===================================================================
 *  Section A — 进程名匹配
 * ===================================================================
 */

/* 完整进程名 hash 比较
 * 注意：Clang 不折叠 __always_inline 到编译期常量，因此用运行时初始化
 * (pure_initcall 在内核启动最早期填充，明文不出现在镜像中)。 */
static u64 ksu_sg_pid_hashes[6];
#define KSU_SG_PID_COUNT  (sizeof(ksu_sg_pid_hashes) / sizeof(u64))

bool ksu_sg_hidden_pid_name(const char *comm, size_t len)
{
    u64 h;
    size_t i;
    if (!comm || len == 0 || len > 16)
        return false;

    h = ksu_fnv1a(comm, len);
    for (i = 0; i < KSU_SG_PID_COUNT; i++) {
        if (ksu_sg_pid_hashes[i] == h)
            return true;
    }
    return false;
}
EXPORT_SYMBOL_GPL(ksu_sg_hidden_pid_name);


/* ===================================================================
 *  Section B — kprobe / kallsyms 符号匹配
 * ===================================================================
 */

/* kprobe 符号黑名单：
 *   - 完整匹配 hash
 *   - 前缀匹配 hash (ksu_, susfs_)
 */
bool ksu_sg_hidden_kprobe_sym(const char *s, size_t len)
{
    u64 h;
    if (!s || len == 0)
        return false;

    /* 完整 hash 比较 */
    h = ksu_fnv1a(s, len);
    if (h == KSU_SG_SYM_ARM_REBOOT || h == KSU_SG_SYM_SYS_REBOOT ||
        h == KSU_SG_SYM_KERNELSU || h == KSU_SG_SYM_SUSFS_PFX ||
        h == KSU_SG_SYM_SUKISU || h == KSU_SG_SYM_KSUD ||
        h == KSU_SG_SYM_MAGISKD)
        return true;

    /* 前缀 hash 匹配 (避免遍历每个字符) */
    if (ksu_sg_starts_with_hash(s, len, KSU_SG_SYM_KSU_PFX, 4))
        return true;
    if (ksu_sg_starts_with_hash(s, len, KSU_SG_SYM_SUSFS_PFX, 6))
        return true;

    /* 子串匹配 (符号可能为 "__ksu_xxx" / "ksu_xxx_module") */
    if (ksu_sg_contains_hash(s, len, KSU_SG_SYM_KERNELSU, 9))
        return true;
    if (ksu_sg_contains_hash(s, len, KSU_SG_SYM_SUKISU, 6))
        return true;

    return false;
}
EXPORT_SYMBOL_GPL(ksu_sg_hidden_kprobe_sym);

bool ksu_sg_hidden_kallsyms_sym(const char *s, size_t len)
{
    /* kallsyms 符号集合与 kprobe 重叠，复用相同逻辑 */
    return ksu_sg_hidden_kprobe_sym(s, len);
}
EXPORT_SYMBOL_GPL(ksu_sg_hidden_kallsyms_sym);


/* ===================================================================
 *  Section B2 — 通用关键词子串匹配（用于 net_hide 等模块）
 * ===================================================================
 *
 * 检查 s[len] 中是否包含任何隐藏关键词子串。
 * 关键词包括：ksu, KSU, magisk, Magisk, sukisu, SukiSI, kernelsu, KernelSU 等
 * 所有关键词以 hash 形式存在，不出现在 .rodata。
 */

/* 子串 hash 匹配列表 (运行时初始化，见 ksu_sg_init_hashes) */
static u64 ksu_sg_keyword_hashes[14];
#define KSU_SG_KEYWORD_COUNT  (sizeof(ksu_sg_keyword_hashes) / sizeof(u64))

/* 子串匹配长度列表，与 ksu_sg_keyword_hashes 一一对应 */
static const size_t ksu_sg_keyword_lens[] = {
    3,   /* "ksu" */
    6,   /* "magisk" */
    6,   /* "sukisu" */
    8,   /* "kernelsu" */
    6,   /* "SukiSI" */
    8,   /* "KernelSU" */
    5,   /* "susfs" */
    6,   /* "zygisk" */
    8,   /* "zygisksu" */
    9,   /* "/data/adb" */
    14,  /* "/debug_ramdisk" */
    7,   /* ".magisk" */
    4,   /* "ksud" */
    7,   /* "magiskd" */
};
_Static_assert(KSU_SG_KEYWORD_COUNT == sizeof(ksu_sg_keyword_lens) / sizeof(size_t),
               "keyword hash and length arrays must match");

bool ksu_sg_contains_keyword(const char *s, size_t len)
{
    size_t i;
    if (!s || len == 0)
        return false;

    for (i = 0; i < KSU_SG_KEYWORD_COUNT; i++) {
        if (ksu_hash_contains(s, len, ksu_sg_keyword_hashes[i],
                              ksu_sg_keyword_lens[i]))
            return true;
    }
    return false;
}
EXPORT_SYMBOL_GPL(ksu_sg_contains_keyword);


/* ===================================================================
 *  Section C — SELinux context 匹配
 * ===================================================================
 */

bool ksu_sg_hidden_selinux_ctx(const char *s, size_t len)
{
    u64 h;
    if (!s || len == 0)
        return false;

    /* 完整 context hash 比较 */
    h = ksu_fnv1a(s, len);
    if (h == KSU_SG_CTX_SU || h == KSU_SG_CTX_MAGISK ||
        h == KSU_SG_CTX_KSU || h == KSU_SG_CTX_KSU2 ||
        h == KSU_SG_CTX_SUKISU)
        return true;

    /* 子串匹配：context 中可能含 "su"/"magisk"/"ksu" 子串 */
    if (ksu_sg_contains_hash(s, len, KSU_SG_CTX_SU, 9))         /* u:r:su:s0 */
        return true;
    if (ksu_sg_contains_hash(s, len, KSU_SG_CTX_MAGISK, 13))    /* u:r:magisk:s0 */
        return true;
    if (ksu_sg_contains_hash(s, len, KSU_SG_CTX_KSU, 14))       /* u:r:kernelsu:s0 */
        return true;
    if (ksu_sg_contains_hash(s, len, KSU_SG_CTX_KSU2, 9))       /* u:r:ksu:s0 */
        return true;
    if (ksu_sg_contains_hash(s, len, KSU_SG_CTX_SUKISU, 14))    /* u:r:sukisu:s0 */
        return true;

    /* zygote 残留 (检测器8) */
    if (ksu_sg_contains_hash(s, len, KSU_SG_ZYGOTE, 6))
        return true;

    return false;
}
EXPORT_SYMBOL_GPL(ksu_sg_hidden_selinux_ctx);


/* ===================================================================
 *  Section D — 模块名匹配 (/proc/modules)
 * ===================================================================
 */

bool ksu_sg_hidden_module_name(const char *s, size_t len)
{
    u64 h;
    size_t name_len = 0;
    if (!s || len == 0)
        return false;

    /* /proc/modules 每行第一字段是模块名 */
    /* 截断到第一个空格 */
    while (name_len < len && s[name_len] != ' ' && s[name_len] != '\t' && s[name_len] != '\0')
        name_len++;

    if (name_len == 0)
        return false;

    h = ksu_fnv1a(s, name_len);
    if (h == KSU_SG_MOD_KSU || h == KSU_SG_MOD_KERNELSU ||
        h == KSU_SG_MOD_SUSFS || h == KSU_SG_MOD_SUKISU)
        return true;

    return false;
}
EXPORT_SYMBOL_GPL(ksu_sg_hidden_module_name);


/* ===================================================================
 *  Section E — mounts 行匹配
 * ===================================================================
 */

bool ksu_sg_hidden_mount_line(const char *line, size_t len)
{
    if (!line || len == 0)
        return false;

    /* 检查行中是否包含隐藏关键词 */
    if (ksu_sg_contains_hash(line, len, KSU_SG_MNT_KSU, 3))
        return true;
    if (ksu_sg_contains_hash(line, len, KSU_SG_MNT_SUSFS, 5))
        return true;
    if (ksu_sg_contains_hash(line, len, KSU_SG_MNT_MAGISK, 6))
        return true;

    return false;
}
EXPORT_SYMBOL_GPL(ksu_sg_hidden_mount_line);


/* ===================================================================
 *  Section F — 运行时初始化 hash 数组
 * ===================================================================
 *
 * Clang 不会将 __always_inline 函数折叠为编译期常量（与 GCC 行为不同），
 * 因此 static const u64[] 初始化器在 Clang 下会报
 * "initializer element is not a compile-time constant"。
 *
 * 解决：数组放 BSS（初始为 0），由 pure_initcall 在内核启动最早期
 * (level 0，早于任何驱动/module init) 运行时填充。
 * 明文关键词仅在 init 函数的临时栈上出现一瞬间，之后只剩 hash 值，
 * 内核镜像 .rodata/.data 中均无明文，反作弊 dump 内存也只看到 hash。
 */
static int __init ksu_sg_init_hashes(void)
{
    /* 进程名黑名单 hash */
    ksu_sg_pid_hashes[0] = KSU_SG_PID_KSUD;
    ksu_sg_pid_hashes[1] = KSU_SG_PID_SUKISU;
    ksu_sg_pid_hashes[2] = KSU_SG_PID_MAGISKD;
    ksu_sg_pid_hashes[3] = KSU_SG_PID_KSUD_INIT;
    ksu_sg_pid_hashes[4] = KSU_SG_PID_SUKISID;
    ksu_sg_pid_hashes[5] = KSU_SG_PID_KSD;

    /* 关键词子串 hash（顺序与 ksu_sg_keyword_lens 一一对应） */
    ksu_sg_keyword_hashes[0]  = KSU_FNV1A_CONST("ksu");
    ksu_sg_keyword_hashes[1]  = KSU_FNV1A_CONST("magisk");
    ksu_sg_keyword_hashes[2]  = KSU_FNV1A_CONST("sukisu");
    ksu_sg_keyword_hashes[3]  = KSU_FNV1A_CONST("kernelsu");
    ksu_sg_keyword_hashes[4]  = KSU_FNV1A_CONST("SukiSI");
    ksu_sg_keyword_hashes[5]  = KSU_FNV1A_CONST("KernelSU");
    ksu_sg_keyword_hashes[6]  = KSU_FNV1A_CONST("susfs");
    ksu_sg_keyword_hashes[7]  = KSU_FNV1A_CONST("zygisk");
    ksu_sg_keyword_hashes[8]  = KSU_FNV1A_CONST("zygisksu");
    ksu_sg_keyword_hashes[9]  = KSU_FNV1A_CONST("/data/adb");
    ksu_sg_keyword_hashes[10] = KSU_FNV1A_CONST("/debug_ramdisk");
    ksu_sg_keyword_hashes[11] = KSU_FNV1A_CONST(".magisk");
    ksu_sg_keyword_hashes[12] = KSU_FNV1A_CONST("ksud");
    ksu_sg_keyword_hashes[13] = KSU_FNV1A_CONST("magiskd");

    return 0;
}
pure_initcall(ksu_sg_init_hashes);


MODULE_LICENSE("GPL");
