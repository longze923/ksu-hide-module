# SPDX-License-Identifier: GPL-2.0
#
# KSU Stealth Hide Module — Makefile
#
# 所有子模块编译为 built-in (obj-y)，在内核启动早期初始化。
# 依赖 KernelSU 提供的 ksu_is_manager() / ksu_get_task_mark() 等符号。

ccflags-y := -Wno-implicit-function-declaration -Wno-incompatible-pointer-types

# === 核心模块 (必须) ===
obj-$(CONFIG_KSU_HIDE_STEALTH_CORE)   += ksu_stealth_core.o
obj-$(CONFIG_KSU_HIDE_STRING_GUARD)   += ksu_string_guard.o

# === 功能模块 ===
obj-$(CONFIG_KSU_HIDE_PROCESS)        += ksu_process_hide.o
obj-$(CONFIG_KSU_HIDE_PROC_PID)       += ksu_proc_pid_filter.o
obj-$(CONFIG_KSU_HIDE_MOUNTS)         += ksu_mounts_filter.o
obj-$(CONFIG_KSU_HIDE_NET)            += ksu_net_hide.o
obj-$(CONFIG_KSU_HIDE_SELINUX)        += ksu_selinux_spoof.o
obj-$(CONFIG_KSU_HIDE_STATUS)         += ksu_status_spoof.o
obj-$(CONFIG_KSU_HIDE_REBOOT)         += ksu_reboot_stealth.o
obj-$(CONFIG_KSU_HIDE_NS_MTIME)       += ksu_ns_mtime_align.o
obj-$(CONFIG_KSU_HIDE_DEBUGFS)        += ksu_debugfs_cleanup.o
obj-$(CONFIG_KSU_HIDE_AP_KER)         += ksu_ap_ker_guard.o
obj-$(CONFIG_KSU_HIDE_IOMEM)          += ksu_iomem_cmdline_spoof.o
obj-$(CONFIG_KSU_HIDE_SYSCALL)        += ksu_syscall_integrity.o
obj-$(CONFIG_KSU_HIDE_TIME)           += ksu_time_virt.o
