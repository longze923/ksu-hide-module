// /proc/self/status 伪装模块
//
// 目标：
// 1. TracerPid: 对目标进程返回 0（隐藏 ptrace / 反调试检测）
// 2. CapEff/CapPrm: 对目标进程隐藏 root 进程的额外能力
// 3. Uid/Gid: 如果隐藏进程的 uid=0，伪装为普通 uid
// 4. /proc/self/cmdline: 对隐藏进程返回伪装的 comm
//
// 同时覆盖 /proc/<pid>/stat 的相关字段
//
// 所有关键词使用编译期混淆宏，明文不出现在 .rodata

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "ksu_stealth_core.h"

// 外部符号
extern bool caller_should_see_hidden(void);
extern bool is_hidden_pid(pid_t pid);

// 编译期混淆的字符串常量
// "TracerPid:\t0\n" — 长度 15
KSU_OBF_DECL(ksu_tracerpid_zero, "TracerPid:\t0\n");
// "CapEff:\t0000000000000000\n" — 长度 27
KSU_OBF_DECL(ksu_capeff_zero, "CapEff:\t0000000000000000\n");

// ---- 1. TracerPid 伪装 ----
// 在 /proc/self/status 的 TracerPid 行输出前调用
// 如果被隐藏进程正在被 ptrace（如 ksud 做 ptrace 注入），
// 对目标进程返回 TracerPid: 0
bool ksu_spoof_tracer_pid(pid_t tracer_pid, pid_t target_pid)
{
    KSU_MODULE_CHECK(ksu_hide_status_enabled);

    if (caller_should_see_hidden())
        return false;

    // 如果 tracer 是隐藏进程，或 target 是隐藏进程
    if (tracer_pid > 0 && (is_hidden_pid(tracer_pid) || is_hidden_pid(target_pid)))
        return true;  // true = 应该伪装 TracerPid 为 0

    return false;
}
EXPORT_SYMBOL_GPL(ksu_spoof_tracer_pid);

// ---- 2. /proc/self/status 行级过滤 ----
// 对 status 的每一行做关键词过滤
// 过滤的内容包括：
//   - TracerPid: 非零值 → 改为 0
//   - 含隐藏进程 PID 的行
//   - CapEff/CapPrm 异常值（root 进程的全能位）
bool ksu_status_line_filter(const char *line, size_t len, char **replacement)
{
    char buf[32];

    KSU_MODULE_CHECK(ksu_hide_status_enabled);

    if (caller_should_see_hidden())
        return false;
    if (!line || len == 0)
        return false;

    if (replacement)
        *replacement = NULL;

    // TracerPid: 非零 → 伪造为 0
    // 用 hash 比较，避免明文 "TracerPid:" 出现在 .rodata
    if (len >= 10) {
        u64 line_hash = ksu_fnv1a(line, 10);
        if (line_hash == KSU_FNV1A_CONST("TracerPid:")) {
            // 检查是否有非零 TracerPid
            const char *p = line + 10;
            while (*p == ' ' || *p == '\t')
                p++;
            if (*p != '0') {
                // 非零 TracerPid，替换
                if (replacement) {
                    KSU_DEOBF(ksu_tracerpid_zero, buf);
                    *replacement = kstrdup(buf, GFP_KERNEL);
                    KSU_WIPE(buf);
                }
                return true;
            }
        }
    }

    // CapEff: 如果是全能位 (0xffffffffffffffff) → 伪装为普通进程的能力
    if (len >= 7) {
        u64 line_hash = ksu_fnv1a(line, 7);
        if (line_hash == KSU_FNV1A_CONST("CapEff:")) {
            const char *p = line + 7;
            bool all_f;
            int count;
            const char *q;
            while (*p == ' ' || *p == '\t')
                p++;
            // 检查是否全 f（root 全能）；只接受 f/F 字符
            all_f = true;
            count = 0;
            q = p;
            while (*q && *q != '\n' && count < 20) {
                if (*q != 'f' && *q != 'F') {
                    all_f = false;
                    break;
                }
                q++;
                count++;
            }
            if (all_f && count >= 16) {
                // 伪装为普通 app 的 CapEff (0x0000000000000000)
                if (replacement) {
                    KSU_DEOBF(ksu_capeff_zero, buf);
                    *replacement = kstrdup(buf, GFP_KERNEL);
                    KSU_WIPE(buf);
                }
                return true;
            }
        }
    }

    return false;
}
EXPORT_SYMBOL_GPL(ksu_status_line_filter);

// ---- 3. /proc/<pid>/stat 字段伪装 ----
// 隐藏进程的 CPU 时间保留真实值，避免与 /proc/stat 总量不对称
// 只伪装 num_threads（隐藏多线程 daemon 的真实线程数）
bool ksu_stat_field_spoof(pid_t pid, u64 *utime, u64 *stime,
                          u64 *cutime, u64 *cstime,
                          int *num_threads)
{
    KSU_MODULE_CHECK(ksu_hide_status_enabled);

    if (caller_should_see_hidden())
        return false;

    if (!is_hidden_pid(pid))
        return false;

    /* CPU 时间保留真实值 — 归零会导致所有进程 CPU 时间之和
     * 与 /proc/stat 报告的总量不一致，形成可检测的统计不对称 */
    (void)utime;
    (void)stime;
    (void)cutime;
    (void)cstime;

    if (num_threads) *num_threads = 1;  // 伪装为单线程

    return true;
}
EXPORT_SYMBOL_GPL(ksu_stat_field_spoof);

// ---- 4. /proc/<pid>/comm 伪装 ----
// 隐藏进程的 comm 改为普通系统进程名
// 假进程名使用编译期混淆，不出现在 .rodata
KSU_OBF_DECL(ksu_fake_comm_0, "kworker/u8:2");
KSU_OBF_DECL(ksu_fake_comm_1, "kworker/0:1H");
KSU_OBF_DECL(ksu_fake_comm_2, "system_server");

bool ksu_comm_spoof(pid_t pid, char *comm, size_t comm_len)
{
    char buf[24];
    static atomic_t fake_idx = ATOMIC_INIT(0);
    int idx;

    KSU_MODULE_CHECK(ksu_hide_status_enabled);

    if (caller_should_see_hidden())
        return false;

    if (!is_hidden_pid(pid))
        return false;

    if (!comm || comm_len == 0)
        return false;

    idx = atomic_inc_return(&fake_idx) - 1;

    switch (idx % 3) {
    case 0:
        KSU_DEOBF(ksu_fake_comm_0, buf);
        break;
    case 1:
        KSU_DEOBF(ksu_fake_comm_1, buf);
        break;
    case 2:
        KSU_DEOBF(ksu_fake_comm_2, buf);
        break;
    }
    strncpy(comm, buf, comm_len - 1);
    comm[comm_len - 1] = '\0';
    KSU_WIPE(buf);

    return true;
}
EXPORT_SYMBOL_GPL(ksu_comm_spoof);

MODULE_LICENSE("GPL");
