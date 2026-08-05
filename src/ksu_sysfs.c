// SPDX-License-Identifier: GPL-2.0
/*
 * ksu_sysfs.c — 隐藏模块运行时开关变量
 *
 * 原 /sys/kernel/ksu_hide/ 运行时接口已移除（该接口的 module_init 曾被
 * 怀疑导致部分设备（小米 android13-5.15）开机卡第一屏，经二分定位后
 * 按用户要求直接删除）。
 *
 * 本文件仅保留各子模块的 atomic 开关定义，默认全部开启；
 * 如需运行时调节，需重新实现 sysfs 接口并排查与设备启动的兼容性。
 */

#include <linux/atomic.h>
#include <linux/module.h>

/* 各子模块开关变量（默认开启） */
atomic_t ksu_hide_process_enabled    = ATOMIC_INIT(1);
atomic_t ksu_hide_proc_pid_enabled   = ATOMIC_INIT(1);
atomic_t ksu_hide_mounts_enabled     = ATOMIC_INIT(1);
atomic_t ksu_hide_net_enabled        = ATOMIC_INIT(1);
atomic_t ksu_hide_selinux_enabled    = ATOMIC_INIT(1);
atomic_t ksu_hide_status_enabled     = ATOMIC_INIT(1);
atomic_t ksu_hide_reboot_enabled     = ATOMIC_INIT(1);
atomic_t ksu_hide_ns_mtime_enabled   = ATOMIC_INIT(1);
atomic_t ksu_hide_debugfs_enabled    = ATOMIC_INIT(1);
atomic_t ksu_hide_ap_ker_enabled     = ATOMIC_INIT(1);
atomic_t ksu_hide_iomem_enabled      = ATOMIC_INIT(1);
atomic_t ksu_hide_syscall_enabled    = ATOMIC_INIT(1);
atomic_t ksu_hide_time_virt_enabled  = ATOMIC_INIT(0); /* 虚拟时源保持停用 */

MODULE_LICENSE("GPL");
