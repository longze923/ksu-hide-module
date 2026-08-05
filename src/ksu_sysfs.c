// SPDX-License-Identifier: GPL-2.0
/*
 * ksu_sysfs.c — KSU Stealth Hide 模块运行时开关
 *
 * 通过 /sys/kernel/ksu_hide/ 目录暴露每个子模块的独立开关。
 * 每个文件可读写 0/1，0 表示关闭该模块的隐藏功能。
 *
 * 路径列表:
 *   /sys/kernel/ksu_hide/process_hide
 *   /sys/kernel/ksu_hide/proc_pid_filter
 *   /sys/kernel/ksu_hide/mounts_filter
 *   /sys/kernel/ksu_hide/net_hide
 *   /sys/kernel/ksu_hide/selinux_spoof
 *   /sys/kernel/ksu_hide/status_spoof
 *   /sys/kernel/ksu_hide/reboot_stealth
 *   /sys/kernel/ksu_hide/ns_mtime_align
 *   /sys/kernel/ksu_hide/debugfs_cleanup
 *   /sys/kernel/ksu_hide/ap_ker_guard
 *   /sys/kernel/ksu_hide/iomem_spoof
 *   /sys/kernel/ksu_hide/syscall_integrity
 *   /sys/kernel/ksu_hide/time_virt
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/atomic.h>
#include <linux/string.h>

/* ===================================================================
 *  各模块开关变量 (默认全部开启)
 * =================================================================== */

/* 诊断模式：所有子开关默认关闭，仅用于定位开机问题；确认后恢复 1 */
atomic_t ksu_hide_process_enabled    = ATOMIC_INIT(0);
atomic_t ksu_hide_proc_pid_enabled   = ATOMIC_INIT(0);
atomic_t ksu_hide_mounts_enabled     = ATOMIC_INIT(0);
atomic_t ksu_hide_net_enabled        = ATOMIC_INIT(0);
atomic_t ksu_hide_selinux_enabled    = ATOMIC_INIT(0);
atomic_t ksu_hide_status_enabled     = ATOMIC_INIT(0);
atomic_t ksu_hide_reboot_enabled     = ATOMIC_INIT(0);
atomic_t ksu_hide_ns_mtime_enabled   = ATOMIC_INIT(0);
atomic_t ksu_hide_debugfs_enabled    = ATOMIC_INIT(0);
atomic_t ksu_hide_ap_ker_enabled     = ATOMIC_INIT(0);
atomic_t ksu_hide_iomem_enabled      = ATOMIC_INIT(0);
atomic_t ksu_hide_syscall_enabled    = ATOMIC_INIT(0);
atomic_t ksu_hide_time_virt_enabled  = ATOMIC_INIT(0);

/* 主开关引用 ksu_stealth_core.c 中定义的全局变量 */
extern atomic_t ksu_stealth_enabled;

/* ===================================================================
 *  sysfs show/store 模板
 * =================================================================== */

struct ksu_switch_attr {
	struct kobj_attribute attr;
	atomic_t *value;
};

#define to_ksu_switch(a) container_of(a, struct ksu_switch_attr, attr)

static ssize_t ksu_switch_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	struct ksu_switch_attr *sa = to_ksu_switch(attr);
	return scnprintf(buf, PAGE_SIZE, "%d\n", atomic_read(sa->value));
}

static ssize_t ksu_switch_store(struct kobject *kobj,
				 struct kobj_attribute *attr,
				 const char *buf, size_t count)
{
	struct ksu_switch_attr *sa = to_ksu_switch(attr);
	int val;

	if (kstrtoint(buf, 0, &val) != 0)
		return -EINVAL;
	atomic_set(sa->value, val ? 1 : 0);
	return count;
}

/* ===================================================================
 *  定义所有开关属性
 * =================================================================== */

#define KSU_SWITCH_ATTR(_name, _var) \
	static struct ksu_switch_attr ksu_switch_##_name = { \
		.attr  = __ATTR(_name, 0664, ksu_switch_show, ksu_switch_store), \
		.value = &_var, \
	}

KSU_SWITCH_ATTR(process_hide,      ksu_hide_process_enabled);
KSU_SWITCH_ATTR(proc_pid_filter,   ksu_hide_proc_pid_enabled);
KSU_SWITCH_ATTR(mounts_filter,     ksu_hide_mounts_enabled);
KSU_SWITCH_ATTR(net_hide,          ksu_hide_net_enabled);
KSU_SWITCH_ATTR(selinux_spoof,     ksu_hide_selinux_enabled);
KSU_SWITCH_ATTR(status_spoof,      ksu_hide_status_enabled);
KSU_SWITCH_ATTR(reboot_stealth,    ksu_hide_reboot_enabled);
KSU_SWITCH_ATTR(ns_mtime_align,    ksu_hide_ns_mtime_enabled);
KSU_SWITCH_ATTR(debugfs_cleanup,   ksu_hide_debugfs_enabled);
KSU_SWITCH_ATTR(ap_ker_guard,      ksu_hide_ap_ker_enabled);
KSU_SWITCH_ATTR(iomem_spoof,       ksu_hide_iomem_enabled);
KSU_SWITCH_ATTR(syscall_integrity, ksu_hide_syscall_enabled);
KSU_SWITCH_ATTR(time_virt,         ksu_hide_time_virt_enabled);
KSU_SWITCH_ATTR(master,            ksu_stealth_enabled);

/* ===================================================================
 *  sysfs 属性列表
 * =================================================================== */

static struct attribute *ksu_hide_attrs[] = {
	&ksu_switch_master.attr.attr,
	&ksu_switch_process_hide.attr.attr,
	&ksu_switch_proc_pid_filter.attr.attr,
	&ksu_switch_mounts_filter.attr.attr,
	&ksu_switch_net_hide.attr.attr,
	&ksu_switch_selinux_spoof.attr.attr,
	&ksu_switch_status_spoof.attr.attr,
	&ksu_switch_reboot_stealth.attr.attr,
	&ksu_switch_ns_mtime_align.attr.attr,
	&ksu_switch_debugfs_cleanup.attr.attr,
	&ksu_switch_ap_ker_guard.attr.attr,
	&ksu_switch_iomem_spoof.attr.attr,
	&ksu_switch_syscall_integrity.attr.attr,
	&ksu_switch_time_virt.attr.attr,
	NULL,
};

static const struct attribute_group ksu_hide_attr_group = {
	.name = "ksu_hide",
	.attrs = ksu_hide_attrs,
};

/* ===================================================================
 *  注册 & 注销
 * =================================================================== */

static struct kobject *ksu_hide_kobj;

static int __init ksu_sysfs_init(void)
{
	int ret;

	/* 在内核 kobject 下创建 ksu_hide 目录 */
	ksu_hide_kobj = kobject_create_and_add("ksu_hide", kernel_kobj);
	if (!ksu_hide_kobj)
		return -ENOMEM;

	ret = sysfs_create_group(ksu_hide_kobj, &ksu_hide_attr_group);
	if (ret) {
		kobject_put(ksu_hide_kobj);
		return ret;
	}

	pr_info("ksu_hide: sysfs interface ready at /sys/kernel/ksu_hide/\n");
	return 0;
}

static void __exit ksu_sysfs_exit(void)
{
	sysfs_remove_group(ksu_hide_kobj, &ksu_hide_attr_group);
	kobject_put(ksu_hide_kobj);
}

module_init(ksu_sysfs_init);
module_exit(ksu_sysfs_exit);

MODULE_LICENSE("GPL");
