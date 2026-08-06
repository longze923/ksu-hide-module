/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ksu_stealth_core.h — 极致隐藏性核心头文件
 *
 * 提供三层防御基座，被所有隐藏模块共用：
 *   1. 编译期字符串混淆  (KSU_OBF)  — 关键词不出现在 .rodata/.data
 *   2. 运行时 hash 比较   (KSU_HASH_CMP) — 不用 strstr/strcmp，避免明文
 *   3. 强化调用者认证     (ksu_caller_trusted) — UID + anti-debug + 启动时间窗
 *
 * 设计目标：
 *   - 反作弊扫描内核镜像找不到 "ksud"/"sukisu"/"magiskd" 等明文特征
 *   - 反作弊以 root 启动 native 子进程仍无法绕过白名单
 *   - 不实现"探测降级"机制，避免任何差异化响应暴露侧信道
 *
 * 依赖：linux/cred.h, linux/sched.h, linux/random.h, asm/processor.h
 */

#ifndef _KSU_STEALTH_CORE_H
#define _KSU_STEALTH_CORE_H

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/random.h>
#include <linux/atomic.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/bug.h>
#include <linux/version.h>

/* ===================================================================
 *  Section 1 — 编译期字符串混淆宏
 * ===================================================================
 *
 * KSU_OBF("ksud") 在编译期被拆解为逐字节 XOR 加密的字节数组，
 * 不出现在 .rodata/.data/.strtab 中。
 * 运行时通过 ksu_deobf() 解密到栈缓冲区，使用后立即清零。
 *
 * 反作弊做 strings / scan 内核镜像时找不到任何明文特征。
 */

/* 编译期 key — 每个 KSU_OBF_DECL 调用点位于不同源码行，因此每个字符串
 * 独立 key。__LINE__ 是 ISO C 标准定义的整数常量表达式 (ICE)，
 * Clang 接受其用于静态存储期对象的初始化器。
 * (注: __COUNTER__ 是预处理扩展，非 ICE，Clang 会拒绝其出现在
 *  static const 数组初始化器中 — 旧实现因此编译失败。) */
#define KSU_OBF_KEY  ((u8)((__LINE__ * 2654435761u) & 0xFF))

/* 编译期逐字节 XOR */
#define KSU_OBF_CHAR(c, k)   ((u8)((c) ^ (k)))

/* 越界安全版：n < 字符串长度时取实际字符 XOR，否则取 0 XOR（解密后为 '\0'）。
 * 根因：原 KSU_OBF_STR_LIT 固定展开 [0]~[31] 共 32 个下标，当字符串短于 32 字节时
 *       访问 s[n] 越界。GCC 宽容（越界读返回0），但 Clang 在编译期常量求值时
 *       拒绝越界下标，报 "initializer element is not a compile-time constant"。
 * 修复：用 sizeof(s)-1（编译期常量）做边界判断，三元运算符只对选中分支求值，
 *       越界时不访问 s[n]，返回 0^k，运行时解密为 '\0'，与原语义完全一致。
 * 隐藏性：不改变 key 生成、加密算法、明文内容、解密逻辑，隐藏效果零退化。 */
#define KSU_OBF_CHAR_SAFE(s, n, k)  \
    ((n) < (sizeof(s) - 1) ? KSU_OBF_CHAR((s)[n], k) : KSU_OBF_CHAR(0, k))

#define KSU_OBF_STR_LIT(s, k) \
    { \
        KSU_OBF_CHAR_SAFE(s, 0, k), KSU_OBF_CHAR_SAFE(s, 1, k), \
        KSU_OBF_CHAR_SAFE(s, 2, k), KSU_OBF_CHAR_SAFE(s, 3, k), \
        KSU_OBF_CHAR_SAFE(s, 4, k), KSU_OBF_CHAR_SAFE(s, 5, k), \
        KSU_OBF_CHAR_SAFE(s, 6, k), KSU_OBF_CHAR_SAFE(s, 7, k), \
        KSU_OBF_CHAR_SAFE(s, 8, k), KSU_OBF_CHAR_SAFE(s, 9, k), \
        KSU_OBF_CHAR_SAFE(s, 10, k), KSU_OBF_CHAR_SAFE(s, 11, k), \
        KSU_OBF_CHAR_SAFE(s, 12, k), KSU_OBF_CHAR_SAFE(s, 13, k), \
        KSU_OBF_CHAR_SAFE(s, 14, k), KSU_OBF_CHAR_SAFE(s, 15, k), \
        KSU_OBF_CHAR_SAFE(s, 16, k), KSU_OBF_CHAR_SAFE(s, 17, k), \
        KSU_OBF_CHAR_SAFE(s, 18, k), KSU_OBF_CHAR_SAFE(s, 19, k), \
        KSU_OBF_CHAR_SAFE(s, 20, k), KSU_OBF_CHAR_SAFE(s, 21, k), \
        KSU_OBF_CHAR_SAFE(s, 22, k), KSU_OBF_CHAR_SAFE(s, 23, k), \
        KSU_OBF_CHAR_SAFE(s, 24, k), KSU_OBF_CHAR_SAFE(s, 25, k), \
        KSU_OBF_CHAR_SAFE(s, 26, k), KSU_OBF_CHAR_SAFE(s, 27, k), \
        KSU_OBF_CHAR_SAFE(s, 28, k), KSU_OBF_CHAR_SAFE(s, 29, k), \
        KSU_OBF_CHAR_SAFE(s, 30, k), KSU_OBF_CHAR_SAFE(s, 31, k), \
        KSU_OBF_CHAR(0, k) \
    }

/* 取字符串长度（编译期） */
#define KSU_OBF_LEN(s)  (sizeof(s) - 1)

/* 完整混淆声明：定义一个静态字节数组 + 长度常量 */
#define KSU_OBF_DECL(name, str) \
    static const u8 name##_data[] = KSU_OBF_STR_LIT(str, KSU_OBF_KEY); \
    static const u8 name##_key = KSU_OBF_KEY; \
    static const size_t name##_len = KSU_OBF_LEN(str)

/* 运行时解密到栈缓冲区。返回值不可跨函数传递 */
static __always_inline void ksu_deobf(const u8 *data, u8 key, size_t len,
                                       char *out, size_t outsz)
{
    size_t i;
    if (!data || !out || outsz < len + 1 || len >= 64)
        return;
    for (i = 0; i < len && i < outsz - 1; i++)
        out[i] = (char)(data[i] ^ key);
    out[i] = '\0';
}

/* 便捷宏：在作用域内解密一个 KSU_OBF_DECL 到 buf */
#define KSU_DEOBF(name, buf)  ksu_deobf(name##_data, name##_key, name##_len, buf, sizeof(buf))

/* 使用后清零 — memzero_explicit 防止编译器死存储优化 */
#define KSU_WIPE(buf)  memzero_explicit(buf, sizeof(buf))


/* ===================================================================
 *  Section 2 — 运行时 FNV-1a hash 比较（替代 strcmp/strstr）
 * ===================================================================
 *
 * 反作弊可通过 dmesg/内存读取内核字符串。
 * 我们不再用明文做匹配，而是：
 *   - 编译期对每个关键词计算 FNV-1a hash
 *   - 运行时对输入计算 hash 后比对 hash
 *   - 关键词本身只以 hash 形式存在 .rodata
 *
 * FNV-1a 64-bit:
 *   hash = 1469598103934665603ULL
 *   for each byte: hash ^= byte; hash *= 1099511628211ULL
 */

#define KSU_FNV_OFFSET  ((u64)1469598103934665603ULL)
#define KSU_FNV_PRIME   ((u64)1099511628211ULL)

static __always_inline u64 ksu_fnv1a(const char *s, size_t len)
{
    u64 h = KSU_FNV_OFFSET;
    size_t i;
    for (i = 0; i < len; i++) {
        h ^= (u8)s[i];
        h *= KSU_FNV_PRIME;
    }
    return h;
}

/* 编译期 FNV-1a (迭代版，Clang/GCC 对常量参数均可常量折叠) */
#define KSU_FNV1A_CONST(s)  ksu_fnv1a_const(s, KSU_FNV_OFFSET)

/* 编译期字符串长度 */
#define KSU_CONST_STRLEN(s)  (sizeof(s) - 1)

/* 编译期 FNV-1a 计算（用于关键字 hash 常量）
 * 迭代实现：Clang 不会折叠递归 __always_inline，但可折叠迭代版本。
 * 对常量字符串参数，编译器在 -O2 下会完全常量折叠为单个 u64 字面值。 */
static __always_inline u64 ksu_fnv1a_const(const char *s, u64 h)
{
    while (s[0] != 0) {
        h = (h ^ (u8)s[0]) * KSU_FNV_PRIME;
        s++;
    }
    return h;
}

/* 大小写不敏感的 hash（用于 SELinux context 匹配，因为 ctx 是大小写敏感的，
 * 但有时反作弊用大小写绕过检测，我们两种 hash 都比较）
 */
static __always_inline u64 ksu_fnv1a_casefold(const char *s, size_t len)
{
    u64 h = KSU_FNV_OFFSET;
    size_t i;
    for (i = 0; i < len; i++) {
        char c = s[i];
        if (c >= 'A' && c <= 'Z')
            c = c - 'A' + 'a';
        h ^= (u8)c;
        h *= KSU_FNV_PRIME;
    }
    return h;
}

/* 子串 hash 搜索：在 haystack[len] 中找 needle 的 hash */
bool ksu_hash_contains(const char *haystack, size_t hlen, u64 needle_hash, size_t needle_len);

/* 通用关键词子串匹配（供 net_hide、mounts_filter 等模块使用） */
bool ksu_sg_contains_keyword(const char *s, size_t len);


/* ===================================================================
 *  Section 3 — 强化调用者认证
 * ===================================================================
 *
 * 替代旧的 caller_should_see_hidden()，提供多层认证：
 *
 *   Layer 1: UID 白名单 (root / shell / KSU manager)
 *   Layer 2: anti-debug — 检测 current 是否被 ptrace、是否处于异常调用链
 *   Layer 3: 启动时间窗 — 系统启动后一段时间内允许 manager 操作
 *
 * 返回 true 表示调用者可信，可以看见隐藏内容
 * 返回 false 表示必须对调用者隐藏一切
 *
 * 注意：本模块不实现"探测计数降级"（即不区分扫描者和普通调用者），
 * 因为任何差异化响应都会暴露侧信道。所有不可信调用者统一返回"无敏感内容"。
 */

/* 全局认证状态 */
struct ksu_auth_state {
    spinlock_t lock;
    u64 boot_allow_ms;  /* 启动后允许 manager 通道的时间窗 */
};

/* 由 ksu_stealth_core.c 提供 */
extern struct ksu_auth_state ksu_auth;

/* 主认证函数 — 替代 caller_should_see_hidden */
bool ksu_caller_trusted(void);

/* 兼容旧接口 — 各模块原来调用的函数 */
bool caller_should_see_hidden(void);

/* 检测当前进程是否被调试中 */
bool ksu_is_being_debugged(void);


/* ===================================================================
 *  Section 4 — 极致隐藏性辅助
 * ===================================================================
 */

/* 在栈上分配清零缓冲区（编译期已知大小，避免堆分配痕迹） */
#define KSU_STACK_BUF(name, size)  char name[size] __aligned(8) = {0}

/* 敏感操作前后的 cache 清理（仅在 arm64 上有效） */
static __always_inline void ksu_cache_fence(void)
{
#if defined(__aarch64__)
    /* dsb + isb 保证之前的内存操作完成 */
    asm volatile("dsb sy\nisb" ::: "memory");
#else
    barrier();
#endif
}

/* 在敏感操作前后插入随机延迟，破坏时序侧信道 */
void ksu_jitter_delay(u32 max_us);


/* ===================================================================
 *  Section 5 — 模块开关与配置
 * =================================================================== */

/* 全局隐藏开关（默认开） */
extern atomic_t ksu_stealth_enabled;

static __always_inline bool ksu_stealth_active(void)
{
    return atomic_read(&ksu_stealth_enabled) != 0;
}

/* 紧急关闭隐藏（被检测到时调用，进入"完全透明"模式） */
void ksu_stealth_disable_all(void);

/* 重新启用隐藏 */
void ksu_stealth_enable_all(void);

/* ===================================================================
 *  Section 6 — 各子模块独立开关 (定义于 ksu_sysfs.c，默认开启；
 *  原 /sys/kernel/ksu_hide/ 运行时接口已移除)
 * =================================================================== */

extern atomic_t ksu_hide_process_enabled;
extern atomic_t ksu_hide_proc_pid_enabled;
extern atomic_t ksu_hide_mounts_enabled;
extern atomic_t ksu_hide_net_enabled;
extern atomic_t ksu_hide_selinux_enabled;
extern atomic_t ksu_hide_status_enabled;
extern atomic_t ksu_hide_reboot_enabled;
extern atomic_t ksu_hide_ns_mtime_enabled;
extern atomic_t ksu_hide_debugfs_enabled;
extern atomic_t ksu_hide_ap_ker_enabled;
extern atomic_t ksu_hide_iomem_enabled;
extern atomic_t ksu_hide_syscall_enabled;
extern atomic_t ksu_hide_time_virt_enabled;
extern atomic_t ksu_hide_clock_check_enabled;

/* 便捷宏：如果模块开关关闭，直接返回默认值（不隐藏） */
#define KSU_MODULE_CHECK(sw)  if (!atomic_read(&(sw))) return false
#define KSU_MODULE_CHECK_INT(sw)  if (!atomic_read(&(sw))) return 0


#endif /* _KSU_STEALTH_CORE_H */
