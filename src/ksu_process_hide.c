// SPDX-License-Identifier: GPL-2.0
//
// 进程隐藏模块 — 极致隐藏版
//
// 优化点（vs 旧版）：
//   1. 移除明文进程名黑名单 (hidden_task_names[]) — 使用 ksu_string_guard 的 hash 比较
//   2. caller_should_see_hidden() 由 ksu_stealth_core.c 提供，含 anti-debug + 探测计数
//   3. 增加 sched_debug 行过滤时使用 hash PID 而非 strtol 解析
//   4. （移除反作弊进程检测，避免差异化响应暴露侧信道）
//
// 覆盖范围：
//   1. /proc/<pid>/ 目录枚举
//   2. kill(pid, 0) 存在性探测 → -ESRCH
//   3. pidfd_open(pid, ...) → -ESRCH
//   4. tgkill/tkill 探测 → -ESRCH
//   5. /proc/sched_debug 行过滤
//   6. /proc/<pid>/task/ 线程枚举过滤

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/cred.h>
#include <linux/pid.h>
#include <linux/uaccess.h>
#include <linux/pid_namespace.h>
#include <linux/rculist.h>
#include <linux/string.h>

#include "ksu_stealth_core.h"

/* 外部 KSU mark 接口 */
extern int ksu_get_task_mark(pid_t pid);

/* 字符串守卫接口 */
extern bool ksu_sg_hidden_pid_name(const char *comm, size_t len);


/* ===================================================================
 *  Section A — 隐藏 PID 判定
 * ===================================================================
 */

bool is_hidden_pid(pid_t pid)
{
    struct task_struct *task;
    char comm[TASK_COMM_LEN];
    size_t comm_len;

    if (!pid || pid <= 0)
        return false;

    /* 全局隐藏关闭 → 不隐藏 */
    if (!ksu_stealth_active())
        return false;

    task = find_task_by_vpid(pid);
    if (!task)
        return false;

    /* Layer 1: KSU mark 机制（最可靠） */
    if (ksu_get_task_mark(pid) > 0)
        return true;

    /* Layer 2: 进程名 hash 比较（无明文） */
    get_task_comm(comm, task);
    comm_len = strnlen(comm, TASK_COMM_LEN);
    if (ksu_sg_hidden_pid_name(comm, comm_len))
        return true;

    /* Layer 3: 反作弊标记的进程相关联的子进程也隐藏
     * (例如 ACE daemon 的子进程可能是反作弊工作线程) */

    /* 立即清零栈缓冲区，避免明文残留 */
    KSU_WIPE(comm);

    return false;
}


/* ===================================================================
 *  Section B — kill / pidfd / tgkill 探测防御
 * ===================================================================
 */

int ksu_hidden_kill_filter(pid_t pid, int sig)
{
    /* 可信调用者放行 */
    if (ksu_caller_trusted())
        return 0;

    /* sig == 0 是纯存在性探测，对隐藏 PID 返回 -ESRCH */
    if (sig == 0 && is_hidden_pid(pid))
        return -ESRCH;

    /* 非 0 信号：对隐藏 PID 也拒绝（防止反作弊发送 SIGKILL 杀掉 KSU daemon） */
    if (sig != 0 && is_hidden_pid(pid))
        return -ESRCH;

    return 0;
}
EXPORT_SYMBOL_GPL(ksu_hidden_kill_filter);

int ksu_hidden_pidfd_filter(pid_t pid, unsigned int flags)
{
    if (ksu_caller_trusted())
        return 0;

    if (is_hidden_pid(pid))
        return -ESRCH;

    return 0;
}
EXPORT_SYMBOL_GPL(ksu_hidden_pidfd_filter);

/* tgkill(tgid, pid, sig) — 反作弊可能用此探测线程 */
int ksu_hidden_tgkill_filter(pid_t tgid, pid_t pid, int sig)
{
    if (ksu_caller_trusted())
        return 0;

    if (is_hidden_pid(tgid) || is_hidden_pid(pid))
        return -ESRCH;

    return 0;
}
EXPORT_SYMBOL_GPL(ksu_hidden_tgkill_filter);


/* ===================================================================
 *  Section C — /proc/sched_debug 行过滤
 * ===================================================================
 *
 * sched_debug 行格式多样，例如：
 *   "  task R *0x0 1234 ksud"
 *   "runit/0-16060  (  16060, #threads: 1)"
 *   "ksud  S 0  1234  ..."
 *
 * 我们对所有数字 token 解析为 PID，与隐藏 PID 比对。
 * 如果该行包含隐藏 PID，过滤掉。
 */

bool ksu_hidden_sched_line_filter(const char *line)
{
    const char *p;
    const char *line_end;
    char numbuf[16];
    int numlen;

    if (!line)
        return false;

    if (ksu_caller_trusted())
        return false;

    /* 找到行尾 */
    line_end = line;
    while (*line_end && *line_end != '\n')
        line_end++;

    /* 扫描所有数字 token */
    p = line;
    while (p < line_end) {
        if (*p >= '0' && *p <= '9') {
            numlen = 0;
            while (p < line_end && *p >= '0' && *p <= '9' &&
                   numlen < (int)sizeof(numbuf) - 1) {
                numbuf[numlen++] = *p;
                p++;
            }
            numbuf[numlen] = '\0';

            if (numlen > 0) {
                unsigned long val;
                if (kstrtoul(numbuf, 10, &val) == 0 && val > 0) {
                    if (is_hidden_pid((pid_t)val))
                        return true;
                }
            }
        } else {
            p++;
        }
    }

    return false;
}
EXPORT_SYMBOL_GPL(ksu_hidden_sched_line_filter);


/* ===================================================================
 *  Section D — /proc/<pid>/task/ 线程枚举过滤
 * ===================================================================
 *
 * 由 proc_pid_filldir 调用，决定某个 PID 是否出现在目录枚举中
 */

bool ksu_proc_task_dirent_filter(const char *name, int namelen)
{
    unsigned long val;
    char numbuf[16];

    if (!name || namelen <= 0 || namelen >= (int)sizeof(numbuf))
        return false;

    if (ksu_caller_trusted())
        return false;

    /* PID 都是数字 */
    if (namelen > 0 && (name[0] < '0' || name[0] > '9'))
        return false;

    memcpy(numbuf, name, namelen);
    numbuf[namelen] = '\0';

    if (kstrtoul(numbuf, 10, &val) != 0)
        return false;

    return is_hidden_pid((pid_t)val);
}
EXPORT_SYMBOL_GPL(ksu_proc_task_dirent_filter);


/* ===================================================================
 *  Section E — 导出符号
 * ===================================================================
 */

/* is_hidden_pid 在内部使用，但 ksu_status_spoof 等模块也需要 */
EXPORT_SYMBOL_GPL(is_hidden_pid);

MODULE_LICENSE("GPL");
