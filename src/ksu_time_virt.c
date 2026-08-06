// SPDX-License-Identifier: GPL-2.0
//
// 时间源多时钟一致性补丁 — 极致隐藏版
//
// 优化点（vs 旧版）：
//   1. 固定 0.95/92% 缩放系数 → 动态随机化（每次启动不同的系数 + 慢漂移）
//   2. 加入低频噪声，破坏统计学检测
//   3. 加入 jitter，破坏时序侧信道
//   4. 加入"自校准"机制：基线快照在 KSU daemon 启动前取，保证干净
//   5. 使用 ksu_caller_trusted() 替代 caller_should_see_hidden()
//
// 防御的检测向量：
//   - /proc/uptime 的 idle 比例异常 (旧版固定 92%，统计学可识别)
//   - /proc/stat 的 ctxt / processes 异常增长
//   - CLOCK_MONOTONIC vs CLOCK_BOOTTIME 的 drift
//   - 长时间采样的统计偏差

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/time.h>
#include <linux/timekeeping.h>
#include <linux/sched.h>
#include <linux/sched/stat.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/tick.h>
#include <linux/random.h>
#include <linux/version.h>
#include <linux/string.h>

#include "ksu_stealth_core.h"

/* ===================================================================
 *  基线快照 + 动态参数
 * ===================================================================
 */

struct ksu_time_baseline {
    bool initialized;
    struct timespec64 boot_time;
    unsigned long long baseline_ctxt;
    unsigned long long baseline_processes;
    struct timespec64 baseline_uptime;
    u64 baseline_monotonic_raw_ns;
    u64 baseline_boottime_ns;
    u64 monotonic_to_boottime_offset_ns;

    /* 增量法基线 — 保证 fake idle 单调递增 */
    u64 baseline_real_uptime_ns;  /* 基线时刻真实 uptime (ns) */
    u64 baseline_fake_idle_ns;   /* 基线时刻 fake idle (ns) */

    /* 动态随机参数 — 每次启动不同 */
    u32 idle_ratio_bp;        /* idle 比例基点 (9000 = 90%)，启动时随机 8800-9500 */
    u32 ctxt_keep_ratio_bp;   /* ctxt 保留比例基点 (9300 = 93%)，启动时随机 9000-9700 */
    u32 proc_keep_ratio_bp;   /* processes 保留比例基点 */
    u32 noise_amplitude_bp;   /* 噪声幅度基点 (50 = 0.5%)，每次查询叠加 ±0.5% 噪声 */
    u32 drift_phase;          /* 慢漂移相位 (用于周期性微调) */
};

static struct ksu_time_baseline g_baseline;
static DEFINE_SPINLOCK(ksu_time_lock);

static void ksu_init_baseline_if_needed(void)
{
    struct timespec64 ts;
    unsigned long flags;
    u32 rnd_seed, idle_rnd, ctxt_rnd, proc_rnd, noise_rnd, drift_rnd;

    /* 快速路径：已初始化则直接返回，不加锁 */
    if (g_baseline.initialized)
        return;

    /* 在锁外生成所有随机数 — get_random_bytes 可能睡眠，
     * 绝不能在 spin_lock_irqsave 内调用 */
    get_random_bytes(&rnd_seed, sizeof(rnd_seed));
    idle_rnd = rnd_seed % 700;
    get_random_bytes(&rnd_seed, sizeof(rnd_seed));
    ctxt_rnd = rnd_seed % 300;
    get_random_bytes(&rnd_seed, sizeof(rnd_seed));
    proc_rnd = rnd_seed % 300;
    get_random_bytes(&rnd_seed, sizeof(rnd_seed));
    noise_rnd = rnd_seed % 70;
    get_random_bytes(&drift_rnd, sizeof(drift_rnd));

    spin_lock_irqsave(&ksu_time_lock, flags);
    if (g_baseline.initialized) {
        spin_unlock_irqrestore(&ksu_time_lock, flags);
        return;
    }

    /* 取一次性基线 */
    ktime_get_boottime_ts64(&ts);
    g_baseline.boot_time = ts;
    /* baseline_ctxt 改为懒初始化:在 ksu_fake_proc_stat 首次调用时
     * 用传入的真实 ctxt 作基线。原因:nr_context_switches() 在 5.15 GKI
     * 中是 kernel/sched/core.c 的 static 函数,不通过 sched/stat.h 导出,
     * 外部模块无法链接。懒初始化语义更准确:基线 = KSU 首次伪造时的真实值 */
    g_baseline.baseline_ctxt = 0;
    g_baseline.baseline_processes = total_forks;

    ktime_get_real_ts64(&ts);
    g_baseline.baseline_uptime = ts;

    g_baseline.baseline_monotonic_raw_ns = ktime_get_raw_ns();
    g_baseline.baseline_boottime_ns = ktime_get_boottime_ns();
    g_baseline.monotonic_to_boottime_offset_ns =
        g_baseline.baseline_boottime_ns - g_baseline.baseline_monotonic_raw_ns;

    /* 随机化缩放参数 — 每次启动不同，防止反作弊预计算阈值 */
    g_baseline.idle_ratio_bp = 8800 + idle_rnd;  /* 88.00% - 94.99% */

    /* 增量法基线：记录基线时刻的真实 uptime 和对应的 fake idle
     * 后续 fake_idle = baseline_fake_idle + delta * ratio
     * delta 始终为正 → fake_idle 单调递增 */
    g_baseline.baseline_real_uptime_ns = g_baseline.baseline_boottime_ns;
    g_baseline.baseline_fake_idle_ns = div_u64(
        g_baseline.baseline_real_uptime_ns * g_baseline.idle_ratio_bp, 10000);

    g_baseline.ctxt_keep_ratio_bp = 9700 + ctxt_rnd;  /* 97.00% - 99.99% */
    g_baseline.proc_keep_ratio_bp = 9700 + proc_rnd;  /* 97.00% - 99.99% */
    g_baseline.noise_amplitude_bp = 30 + noise_rnd;  /* 0.3% - 0.99% */
    g_baseline.drift_phase = drift_rnd;

    g_baseline.initialized = true;
    spin_unlock_irqrestore(&ksu_time_lock, flags);
}

/* 动态噪声：每次调用返回 ±noise_amplitude_bp 范围内的随机偏移 */
static s32 ksu_time_noise(void)
{
    u32 rnd;
    s32 offset;

    if (g_baseline.noise_amplitude_bp == 0)
        return 0;

    get_random_bytes(&rnd, sizeof(rnd));
    /* rnd 映射到 [-noise_amplitude_bp, +noise_amplitude_bp] */
    offset = (s32)(rnd % (2 * g_baseline.noise_amplitude_bp + 1)) -
             (s32)g_baseline.noise_amplitude_bp;
    return offset;
}

/* 慢漂移：以分钟为周期的正弦波动，幅度 ±0.2%
 * 防止长时间采样发现恒定偏差
 */
static s32 ksu_time_drift(void)
{
    u64 now_ms = ktime_to_ms(ktime_get_boottime_ns());
    u64 minutes = div_u64(now_ms, 60000);
    /* 用 minutes 做近似的正弦波动 (用 hash 替代 sin) */
    u32 phase = (minutes * 7919 + g_baseline.drift_phase) & 0xFF;
    /* 映射到 [-20, +20] 基点 (±0.2%) */
    return (s32)phase - 128;
}


/* ===================================================================
 *  Section A — /proc/uptime 伪造
 * ===================================================================
 *
 * 旧版固定 92% idle → 统计学可识别
 * 新版：基线 idle_ratio (88-95%) + 慢漂移 (±0.2%) + 噪声 (±0.3-1%)
 */

void ksu_fake_uptime(u64 *real_sec, u64 *real_nsec,
                     u64 *idle_sec, u64 *idle_nsec)
{
    u64 current_real_ns, delta_ns, fake_idle_ns;
    s32 effective_ratio_bp;

    if (!atomic_read(&ksu_hide_time_virt_enabled))
        return;

    if (ksu_caller_trusted())
        return;

    ksu_init_baseline_if_needed();

    /* effective = baseline + drift + noise */
    effective_ratio_bp = (s32)g_baseline.idle_ratio_bp +
                         ksu_time_drift() +
                         ksu_time_noise();

    /* 钳位到合理范围 */
    if (effective_ratio_bp < 7000)
        effective_ratio_bp = 7000;  /* 至少 70% idle */
    if (effective_ratio_bp > 9900)
        effective_ratio_bp = 9900;  /* 至多 99% idle */

    /* 增量法：fake_idle = baseline_fake_idle + delta * ratio
     * delta = 当前真实 uptime - 基线真实 uptime，始终为正（时间单调递增）
     * ratio 钳位到 7000-9900，始终为正
     * → fake_idle 必然单调递增，噪声只影响增长速率不影响方向 */
    current_real_ns = *real_sec * NSEC_PER_SEC + *real_nsec;

    if (current_real_ns >= g_baseline.baseline_real_uptime_ns) {
        delta_ns = current_real_ns - g_baseline.baseline_real_uptime_ns;
        fake_idle_ns = g_baseline.baseline_fake_idle_ns +
                       div_u64(delta_ns * (u32)effective_ratio_bp, 10000);
    } else {
        /* 异常情况（时间回退），使用基线值 */
        fake_idle_ns = g_baseline.baseline_fake_idle_ns;
    }

    *idle_sec = div_u64(fake_idle_ns, NSEC_PER_SEC);
    *idle_nsec = fake_idle_ns - *idle_sec * NSEC_PER_SEC;

    /* 插入 jitter，破坏时序侧信道 */
    ksu_jitter_delay(2);
}
EXPORT_SYMBOL_GPL(ksu_fake_uptime);


/* ===================================================================
 *  Section B — /proc/stat btime / ctxt / processes 伪造
 * ===================================================================
 *
 * 旧版固定 0.95 → 统计学可识别
 * 新版：动态保留比例 + 慢漂移 + 噪声
 */

void ksu_fake_proc_stat(unsigned long long *ctxt,
                        unsigned long long *processes,
                        long *btime)
{
    unsigned long long real_ctxt, real_proc;
    unsigned long long delta_ctxt, delta_proc;
    u32 ctxt_ratio, proc_ratio;
    s32 eff_ctxt_bp, eff_proc_bp;

    if (!atomic_read(&ksu_hide_time_virt_enabled))
        return;

    if (ksu_caller_trusted())
        return;

    ksu_init_baseline_if_needed();

    real_ctxt = *ctxt;
    real_proc = *processes;

    /* baseline_ctxt 懒初始化:首次伪造时用真实值作锚点。
     * 0 表示未初始化(系统启动后 ctxt 不可能为 0) */
    if (g_baseline.baseline_ctxt == 0)
        g_baseline.baseline_ctxt = real_ctxt;

    /* 动态系数 */
    eff_ctxt_bp = (s32)g_baseline.ctxt_keep_ratio_bp + ksu_time_drift() + ksu_time_noise();
    eff_proc_bp = (s32)g_baseline.proc_keep_ratio_bp + ksu_time_drift() + ksu_time_noise();

    /* 钳位 — 与 ratio 97-100% 匹配,避免 drift+noise 叠加后过度偏离 */
    if (eff_ctxt_bp < 9500) eff_ctxt_bp = 9500;
    if (eff_ctxt_bp > 10000) eff_ctxt_bp = 10000;
    if (eff_proc_bp < 9500) eff_proc_bp = 9500;
    if (eff_proc_bp > 10000) eff_proc_bp = 10000;

    ctxt_ratio = (u32)eff_ctxt_bp;
    proc_ratio = (u32)eff_proc_bp;

    if (real_ctxt > g_baseline.baseline_ctxt) {
        delta_ctxt = real_ctxt - g_baseline.baseline_ctxt;
        *ctxt = g_baseline.baseline_ctxt + div_u64(delta_ctxt * ctxt_ratio, 10000);
    }

    if (real_proc > g_baseline.baseline_processes) {
        delta_proc = real_proc - g_baseline.baseline_processes;
        *processes = g_baseline.baseline_processes + div_u64(delta_proc * proc_ratio, 10000);
    }

    /* btime: 强制对齐基线启动时间 */
    if (btime && g_baseline.boot_time.tv_sec > 0)
        *btime = g_baseline.boot_time.tv_sec;
}
EXPORT_SYMBOL_GPL(ksu_fake_proc_stat);


/* ===================================================================
 *  Section B2 — /proc/stat 缓冲区过滤（5.15 适配）
 * ===================================================================
 * 5.15 的 show_stat() 直接调用 nr_context_switches()/total_forks 等，
 * 无法通过指针修改，因此在 show_stat 末尾对整个 seq 缓冲区逐行过滤：
 *   - "ctxt <real>"     按动态比例伪装
 *   - "processes <real>" 按动态比例伪装
 *   - btime 保持真实（与 /proc/uptime total / CLOCK_BOOTTIME 一致）
 */

static u64 ksu_parse_u64(const char *s, size_t len)
{
    u64 val = 0;
    size_t i;

    for (i = 0; i < len; i++) {
        if (s[i] < '0' || s[i] > '9')
            break;
        if (val > (~0ULL - (u64)(s[i] - '0')) / 10)
            break;
        val = val * 10 + (u64)(s[i] - '0');
    }
    return val;
}

static u64 ksu_fake_stat_counter(u64 real, u64 baseline, u32 ratio_bp)
{
    u64 delta;

    if (real <= baseline)
        return real;

    delta = real - baseline;
    return baseline + div_u64(delta * ratio_bp, 10000);
}

void ksu_stat_buffer_filter(char *buf, size_t *count)
{
    size_t src = 0;
    size_t dst = 0;

    if (!buf || !count)
        return;

    if (!atomic_read(&ksu_hide_time_virt_enabled))
        return;

    if (ksu_caller_trusted())
        return;

    ksu_init_baseline_if_needed();

    while (src < *count) {
        size_t eol = src;
        size_t line_len;
        u64 real = 0;
        bool rewrite = false;
        char tmp[48];
        int n = 0;

        while (eol < *count && buf[eol] != '\n')
            eol++;
        if (eol < *count)
            eol++;
        line_len = eol - src;

        if (line_len > 6 && memcmp(buf + src, "ctxt ", 5) == 0) {
            real = ksu_parse_u64(buf + src + 5, line_len - 5);
            if (real > 0) {
                s32 eff = (s32)g_baseline.ctxt_keep_ratio_bp +
                          ksu_time_drift() + ksu_time_noise();
                u64 fake;

                if (eff < 9500) eff = 9500;
                if (eff > 10000) eff = 10000;

                if (g_baseline.baseline_ctxt == 0)
                    g_baseline.baseline_ctxt = real;
                fake = ksu_fake_stat_counter(real,
                        g_baseline.baseline_ctxt, (u32)eff);
                n = snprintf(tmp, sizeof(tmp), "ctxt %llu\n", fake);
                rewrite = true;
            }
        } else if (line_len > 12 && memcmp(buf + src, "processes ", 10) == 0) {
            real = ksu_parse_u64(buf + src + 10, line_len - 10);
            if (real > 0) {
                s32 eff = (s32)g_baseline.proc_keep_ratio_bp +
                          ksu_time_drift() + ksu_time_noise();
                u64 fake;

                if (eff < 9500) eff = 9500;
                if (eff > 10000) eff = 10000;

                if (g_baseline.baseline_processes == 0)
                    g_baseline.baseline_processes = real;
                fake = ksu_fake_stat_counter(real,
                        g_baseline.baseline_processes, (u32)eff);
                n = snprintf(tmp, sizeof(tmp), "processes %llu\n", fake);
                rewrite = true;
            }
        }

        if (rewrite && n > 0 && (size_t)n <= sizeof(tmp)) {
            memmove(buf + dst, tmp, (size_t)n);
            dst += (size_t)n;
        } else {
            memmove(buf + dst, buf + src, line_len);
            dst += line_len;
        }

        src = eol;
    }

    *count = dst;
}
EXPORT_SYMBOL_GPL(ksu_stat_buffer_filter);


/* ===================================================================
 *  Section C — clock_gettime 多时钟一致性检查
 * ===================================================================
 *
 * 维持 CLOCK_MONOTONIC / CLOCK_MONOTONIC_RAW / CLOCK_BOOTTIME 之间的固定偏移
 */

void ksu_check_clock_consistency(const clockid_t which_clock,
                                 struct timespec64 *ts)
{
    if (!atomic_read(&ksu_hide_clock_check_enabled))
        return;

    if (ksu_caller_trusted())
        return;

    ksu_init_baseline_if_needed();

    /* CLOCK_BOOTTIME 必须与 /proc/uptime 的 total 保持一致。
     * /proc/uptime 的 total 来自真实 boottime，所以不做覆盖，
     * 仅插入轻微 jitter 破坏时序侧信道。
     * 伪造 idle 比例和 ctxt/processes 统计已在其他函数中处理。 */
    if (which_clock == CLOCK_BOOTTIME) {
        ksu_jitter_delay(1);
    }
}
EXPORT_SYMBOL_GPL(ksu_check_clock_consistency);


MODULE_LICENSE("GPL");
