#!/usr/bin/env bash
# ============================================================================
# ABK 自定义外部模块: KSU Stealth Hide Module
# ============================================================================
#
# 三层防御架构的极致隐藏性内核模块，为 KernelSU/SukiSU/ReSukiSU 提供全面反检测。
#
# 使用方式: 在 ABK App 或 GitHub Actions 中指定:
#   https://github.com/<your>/ksu-hide-module;after_patch
#
# 注意: 必须使用 after_patch 阶段，因为该模块依赖 KernelSU 符号
# (ksu_is_manager, ksu_get_task_mark)，需要在 KernelSU 集成之后编译。
#
# ============================================================================
set -euo pipefail

# --- 环境变量检查 ---
echo "================================================"
echo " KSU Stealth Hide Module - setup.sh"
echo "================================================"
echo "Kernel root:   ${KERNEL_ROOT:-<未设置>}"
echo "Defconfig:     ${DEFCONFIG:-<未设置>}"
echo "Config:        ${CONFIG:-<未设置>}"
echo "Workspace:     ${GITHUB_WORKSPACE:-$(pwd)}"
echo "================================================"

# 检查必要环境变量
if [ -z "${KERNEL_ROOT:-}" ]; then
    echo "ERROR: KERNEL_ROOT is not set. This module must run in 'after_patch' stage."
    exit 1
fi

if [ -z "${DEFCONFIG:-}" ]; then
    echo "ERROR: DEFCONFIG is not set."
    exit 1
fi

# --- 目录定义 ---
MODULE_SRC_DIR="$(cd "$(dirname "$0")" && pwd)/src"
KERNEL_DRIVERS_DIR="${KERNEL_ROOT}/common/drivers"
KSU_HIDE_TARGET_DIR="${KERNEL_DRIVERS_DIR}/ksu_hide"

echo ""
echo "[1/6] Checking source files..."

# 检查源文件
REQUIRED_FILES=(
    "ksu_stealth_core.h"
    "ksu_stealth_core.c"
    "ksu_string_guard.c"
    "ksu_process_hide.c"
    "ksu_proc_pid_filter.c"
    "ksu_mounts_filter.c"
    "ksu_net_hide.c"
    "ksu_selinux_spoof.c"
    "ksu_status_spoof.c"
    "ksu_reboot_stealth.c"
    "ksu_ns_mtime_align.c"
    "ksu_debugfs_cleanup.c"
    "ksu_ap_ker_guard.c"
    "ksu_iomem_cmdline_spoof.c"
    "ksu_syscall_integrity.c"
    "ksu_time_virt.c"
)

for f in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "${MODULE_SRC_DIR}/${f}" ]; then
        echo "ERROR: Missing source file: ${MODULE_SRC_DIR}/${f}"
        exit 1
    fi
done
echo "  All 16 source files present."

# --- [2/6] 创建目标目录 ---
echo ""
echo "[2/6] Creating target directory: ${KSU_HIDE_TARGET_DIR}"
mkdir -p "${KSU_HIDE_TARGET_DIR}"

# --- [3/6] 复制源码 ---
echo ""
echo "[3/6] Copying source files..."
cp -v "${MODULE_SRC_DIR}/"*.c "${MODULE_SRC_DIR}/"*.h "${KSU_HIDE_TARGET_DIR}/" 2>&1 | while read line; do
    echo "  ${line}"
done

# --- [4/6] 复制 Kconfig 和 Makefile ---
echo ""
echo "[4/6] Copying Kconfig and Makefile..."
MODULE_ROOT="$(cd "$(dirname "$0")" && pwd)"
cp -v "${MODULE_ROOT}/Kconfig" "${KSU_HIDE_TARGET_DIR}/"
cp -v "${MODULE_ROOT}/Makefile" "${KSU_HIDE_TARGET_DIR}/"

# --- [5/6] 注册到内核构建系统 ---
echo ""
echo "[5/6] Registering in kernel build system..."

# 5a. 在 drivers/Kconfig 末尾添加 source (幂等)
DRIVERS_KCONFIG="${KERNEL_DRIVERS_DIR}/Kconfig"
KCONFIG_LINE='source "drivers/ksu_hide/Kconfig"'

if [ -f "${DRIVERS_KCONFIG}" ]; then
    if ! grep -qF "${KCONFIG_LINE}" "${DRIVERS_KCONFIG}"; then
        echo "  Adding to drivers/Kconfig..."
        echo "${KCONFIG_LINE}" >> "${DRIVERS_KCONFIG}"
    else
        echo "  drivers/Kconfig already has ksu_hide entry (skipping)"
    fi
else
    echo "  WARNING: ${DRIVERS_KCONFIG} not found, creating minimal Kconfig"
    echo "${KCONFIG_LINE}" > "${DRIVERS_KCONFIG}"
fi

# 5b. 在 drivers/Makefile 末尾添加 obj-y (幂等)
DRIVERS_MAKEFILE="${KERNEL_DRIVERS_DIR}/Makefile"
MAKEFILE_LINE='obj-$(CONFIG_KSU_HIDE) += ksu_hide/'

if [ -f "${DRIVERS_MAKEFILE}" ]; then
    if ! grep -qF "${MAKEFILE_LINE}" "${DRIVERS_MAKEFILE}"; then
        echo "  Adding to drivers/Makefile..."
        echo "${MAKEFILE_LINE}" >> "${DRIVERS_MAKEFILE}"
    else
        echo "  drivers/Makefile already has ksu_hide entry (skipping)"
    fi
else
    echo "  ERROR: ${DRIVERS_MAKEFILE} not found!"
    exit 1
fi

# --- [6/6] 启用内核配置 ---
echo ""
echo "[6/6] Enabling kernel config options..."

if [ ! -f "${DEFCONFIG}" ]; then
    echo "  ERROR: defconfig not found at ${DEFCONFIG}"
    exit 1
fi

# 要启用的配置项 (CONFIG_KSU_HIDE 会级联启用所有子项)
CONFIG_OPTIONS=(
    "CONFIG_KSU_HIDE=y"
    "CONFIG_KSU_HIDE_STEALTH_CORE=y"
    "CONFIG_KSU_HIDE_STRING_GUARD=y"
    "CONFIG_KSU_HIDE_PROCESS=y"
    "CONFIG_KSU_HIDE_PROC_PID=y"
    "CONFIG_KSU_HIDE_MOUNTS=y"
    "CONFIG_KSU_HIDE_NET=y"
    "CONFIG_KSU_HIDE_SELINUX=y"
    "CONFIG_KSU_HIDE_STATUS=y"
    "CONFIG_KSU_HIDE_REBOOT=y"
    "CONFIG_KSU_HIDE_NS_MTIME=y"
    "CONFIG_KSU_HIDE_DEBUGFS=y"
    "CONFIG_KSU_HIDE_AP_KER=y"
    "CONFIG_KSU_HIDE_IOMEM=y"
    "CONFIG_KSU_HIDE_SYSCALL=y"
    "CONFIG_KSU_HIDE_TIME=y"
)

for opt in "${CONFIG_OPTIONS[@]}"; do
    opt_name="${opt%%=*}"
    if grep -q "^${opt_name}=" "${DEFCONFIG}"; then
        # 已存在，替换值
        sed -i "s/^${opt_name}=.*/${opt}/" "${DEFCONFIG}"
        echo "  Updated: ${opt}"
    else
        # 不存在，追加
        echo "${opt}" >> "${DEFCONFIG}"
        echo "  Added:   ${opt}"
    fi
done

# --- 完成 ---
echo ""
echo "================================================"
echo " KSU Stealth Hide Module — setup complete!"
echo "================================================"
echo ""
echo "Verified directory structure:"
ls -la "${KSU_HIDE_TARGET_DIR}/" | while read line; do
    echo "  ${line}"
done
echo ""
echo "Module will be compiled as built-in (obj-y) in the kernel."
echo "================================================"
