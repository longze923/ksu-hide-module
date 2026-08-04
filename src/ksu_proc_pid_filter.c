// /proc PID 枚举过滤 patch (通过修改 fs/proc/base.c 和 fs/readdir.c 注入)
// 方案：在 proc_pid_readdir 的 filldir 回调之前过滤隐藏 PID
//
// 这个 patch 通过 apply_custom_patches 步骤注入到内核源码 fs/proc/ 目录
// 并在 Kbuild / Makefile 中编译

#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/namei.h>
#include <linux/pid.h>
#include <linux/rculist.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

// 外部符号 (从 ksu_process_hide.c 导出)
extern bool is_hidden_pid(pid_t pid);
extern bool caller_should_see_hidden(void);

// 检测 dirent name 是否是纯数字 PID 目录
static bool dirent_is_pid(const char *name, int len, pid_t *out_pid)
{
    int i;
    long val;
    if (!name || len <= 0 || len > 10)
        return false;
    for (i = 0; i < len; i++) {
        if (name[i] < '0' || name[i] > '9')
            return false;
    }
    val = simple_strtol(name, NULL, 10);
    if (val <= 0 || val > 0x7FFFFFFF)
        return false;
    *out_pid = (pid_t)val;
    return true;
}

// 包装 filldir 回调：对隐藏 PID 的 dirent 返回"已跳过"
//
// 用法：在 proc_pid_readdir 中，把 iter->actor 替换为 ksu_wrapped_filldir，
// 保存原 ctx->actor，在包装器内先过滤再调用原 actor
//
// 为了简化 patch，这里提供通用的过滤函数：
// 如果该 dirent 代表被隐藏的 PID，返回 true（跳过），否则返回 false
bool ksu_proc_pid_dirent_filter(const char *name, int namelen)
{
    pid_t pid;

    if (caller_should_see_hidden())
        return false;

    if (!dirent_is_pid(name, namelen, &pid))
        return false;

    return is_hidden_pid(pid);
}

EXPORT_SYMBOL_GPL(ksu_proc_pid_dirent_filter);
