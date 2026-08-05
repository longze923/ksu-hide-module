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
KERNEL_COMMON="${KERNEL_ROOT}/common"

echo ""
echo "[1/7] Checking source files..."

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
    "ksu_sysfs.c"
)

for f in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "${MODULE_SRC_DIR}/${f}" ]; then
        echo "ERROR: Missing source file: ${MODULE_SRC_DIR}/${f}"
        exit 1
    fi
done
echo "  All ${#REQUIRED_FILES[@]} source files present."

# --- [2/7] 创建目标目录 ---
echo ""
echo "[2/7] Creating target directory: ${KSU_HIDE_TARGET_DIR}"
mkdir -p "${KSU_HIDE_TARGET_DIR}"

# --- [3/7] 复制源码 ---
echo ""
echo "[3/7] Copying source files..."
cp -v "${MODULE_SRC_DIR}/"*.c "${MODULE_SRC_DIR}/"*.h "${KSU_HIDE_TARGET_DIR}/" 2>&1 | while read line; do
    echo "  ${line}"
done

# --- [4/7] 复制 Kconfig 和 Makefile ---
echo ""
echo "[4/7] Copying Kconfig and Makefile..."
MODULE_ROOT="$(cd "$(dirname "$0")" && pwd)"
cp -v "${MODULE_ROOT}/Kconfig" "${KSU_HIDE_TARGET_DIR}/"
cp -v "${MODULE_ROOT}/Makefile" "${KSU_HIDE_TARGET_DIR}/"

# --- [5/7] 注册到内核构建系统 ---
echo ""
echo "[5/7] Registering in kernel build system..."

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

# --- [6/7] 启用内核配置 ---
echo ""
echo "[6/7] Enabling kernel config options..."

if [ ! -f "${DEFCONFIG}" ]; then
    echo "  ERROR: defconfig not found at ${DEFCONFIG}"
    exit 1
fi

# 要启用的配置项
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
    "CONFIG_KSU_HIDE_SYSFS=y"
)

for opt in "${CONFIG_OPTIONS[@]}"; do
    opt_name="${opt%%=*}"
    if grep -q "^${opt_name}=" "${DEFCONFIG}"; then
        sed -i "s/^${opt_name}=.*/${opt}/" "${DEFCONFIG}"
        echo "  Updated: ${opt}"
    else
        echo "${opt}" >> "${DEFCONFIG}"
        echo "  Added:   ${opt}"
    fi
done

# ============================================================================
# [7/7] 注入调用点 — 将导出函数挂到内核路径
# ============================================================================
echo ""
echo "[7/7] Injecting hook calls into kernel source..."
echo "================================================"

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

# --- 辅助函数 ---------------------------------------------------------------
# 在文件的最后一行 #include 之后插入 extern 声明
add_extern() {
    local file="$1"
    local decl="$2"
    local check="$3"

    if [ ! -f "$file" ]; then
        echo "  [WARN] add_extern: file not found, skipping: $file"
        return 0
    fi
    if grep -qF "$check" "$file" 2>/dev/null; then
        return 0
    fi
    local last_inc
    last_inc=$(grep -n '^#include' "$file" 2>/dev/null | tail -1 | cut -d: -f1)
    if [ -n "$last_inc" ]; then
        sed -i "${last_inc}a\\${decl}" "$file"
    fi
    return 0
}

# 在指定锚点行之后插入代码，并验证
inject_code() {
    local file="$1"
    local anchor="$2"
    local code="$3"
    local check="$4"
    local name="$5"

    if [ ! -f "$file" ]; then
        echo "  [MISS] $name — file not found: $file"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        return 0
    fi

    if grep -qF "$check" "$file" 2>/dev/null; then
        echo "  [SKIP] $name — already injected"
        SKIP_COUNT=$((SKIP_COUNT + 1))
        return 0
    fi

    # 尝试注入
    if sed -i "/${anchor}/a\\${code}" "$file" 2>/dev/null; then
        if grep -qF "$check" "$file"; then
            echo "  [OK]   $name"
            PASS_COUNT=$((PASS_COUNT + 1))
            return 0
        fi
    fi

    echo "  [FAIL] $name — anchor not found or injection failed"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    return 0
}

# ===========================================================================
# 注入规则: add_extern 的 check 用函数签名片段(含参数类型)
#           inject_code 的 check 用函数调用片段(含实参)
#           两者不能相同，否则 add_extern 插入 extern 声明后 inject_code
#           会误判为"已注入"而跳过。
# ===========================================================================

# --- 1. 进程隐藏 — fs/proc/base.c (proc_pid_readdir) ------------------------
PROC_BASE="${KERNEL_COMMON}/fs/proc/base.c"
add_extern "$PROC_BASE" \
    'extern bool ksu_proc_pid_dirent_filter(const char *name, int namelen);' \
    'ksu_proc_pid_dirent_filter(const char'

inject_code "$PROC_BASE" \
    'dir_emit(ctx, name, len,' \
    'if (ksu_proc_pid_dirent_filter(name, len)) continue;' \
    'ksu_proc_pid_dirent_filter(name, len)' \
    'proc_pid_readdir (PID hiding)'

# --- 线程枚举过滤 — proc_task_readdir ---------------------------------------
add_extern "$PROC_BASE" \
    'extern bool ksu_proc_task_dirent_filter(const char *name, int namelen);' \
    'ksu_proc_task_dirent_filter(const char'

inject_code "$PROC_BASE" \
    'proc_task_readdir' \
    'if (ksu_proc_task_dirent_filter(name, len)) continue;' \
    'ksu_proc_task_dirent_filter(name, len)' \
    'proc_task_readdir (thread hiding)'

# --- 2. 挂载隐藏 — fs/proc_namespace.c (show_vfsmnt) ------------------------
PROC_NS="${KERNEL_COMMON}/fs/proc_namespace.c"
add_extern "$PROC_NS" \
    'extern bool ksu_mounts_line_filter(const char *line, size_t len);' \
    'ksu_mounts_line_filter(const char'

inject_code "$PROC_NS" \
    'show_vfsmnt' \
    'if (ksu_mounts_line_filter(seq_buf_str(m->buf), seq_buf_used(m->buf))) return 0;' \
    'ksu_mounts_line_filter(seq_buf_str' \
    'show_vfsmnt (mounts hiding)'

# --- 3. 网络隐藏 — net/unix/af_unix.c ---------------------------------------
UNIX_FILE="${KERNEL_COMMON}/net/unix/af_unix.c"
add_extern "$UNIX_FILE" \
    'extern bool ksu_net_unix_line_filter(const char *sun_path, struct sock *sk);' \
    'ksu_net_unix_line_filter(const char'

inject_code "$UNIX_FILE" \
    'unix_seq_show' \
    'if (ksu_net_unix_line_filter(NULL, s)) return 0;' \
    'ksu_net_unix_line_filter(NULL' \
    'unix_seq_show (socket hiding)'

# --- 4. TCP socket 隐藏 — net/ipv4/tcp_ipv4.c -------------------------------
TCP_FILE="${KERNEL_COMMON}/net/ipv4/tcp_ipv4.c"
add_extern "$TCP_FILE" \
    'extern bool ksu_net_proc_line_filter(const char *line, struct sock *sk);' \
    'ksu_net_proc_line_filter(const char'

inject_code "$TCP_FILE" \
    'tcp4_seq_show' \
    'if (ksu_net_proc_line_filter(NULL, sk)) return 0;' \
    'ksu_net_proc_line_filter(NULL' \
    'tcp4_seq_show (TCP hiding)'

# --- 5. kallsyms 隐藏 — kernel/kallsyms.c -----------------------------------
KALLSYMS="${KERNEL_COMMON}/kernel/kallsyms.c"
add_extern "$KALLSYMS" \
    'extern bool ksu_kallsyms_filter(const char *sym_name);' \
    'ksu_kallsyms_filter(const char'

inject_code "$KALLSYMS" \
    'static int s_show' \
    'if (ksu_kallsyms_filter(buf)) return 0;' \
    'ksu_kallsyms_filter(buf)' \
    'kallsyms s_show (symbol hiding)'

# --- 6. /proc/modules 隐藏 — kernel/module/main.c ---------------------------
MOD_MAIN="${KERNEL_COMMON}/kernel/module/main.c"
add_extern "$MOD_MAIN" \
    'extern bool ksu_proc_modules_filter(const char *line);' \
    'ksu_proc_modules_filter(const char'

inject_code "$MOD_MAIN" \
    'static int m_show' \
    'if (ksu_proc_modules_filter(buf)) return 0;' \
    'ksu_proc_modules_filter(buf)' \
    'modules m_show (module hiding)'

# --- 7. /proc/stat 伪装 — fs/proc/stat.c ------------------------------------
PROC_STAT="${KERNEL_COMMON}/fs/proc/stat.c"
add_extern "$PROC_STAT" \
    'extern void ksu_fake_proc_stat(unsigned long long *ctxt, unsigned long long *processes, long *btime);' \
    'ksu_fake_proc_stat(unsigned long'

inject_code "$PROC_STAT" \
    'show_stat' \
    'ksu_fake_proc_stat(&ctxt, &processes, &btime);' \
    'ksu_fake_proc_stat(&ctxt' \
    'show_stat (stat spoofing)'

# --- 8. /proc/uptime 伪装 — fs/proc/uptime.c ---------------------------------
PROC_UPTIME="${KERNEL_COMMON}/fs/proc/uptime.c"
add_extern "$PROC_UPTIME" \
    'extern void ksu_fake_uptime(u64 *real_sec, u64 *real_nsec, u64 *idle_sec, u64 *idle_nsec);' \
    'ksu_fake_uptime(u64'

inject_code "$PROC_UPTIME" \
    'uptime_proc_show' \
    'ksu_fake_uptime(&uptime, &idle, &idle, &idle_nsec);' \
    'ksu_fake_uptime(&uptime' \
    'uptime_proc_show (uptime spoofing)'

# --- 9. /proc/cmdline 伪装 — fs/proc/cmdline.c -------------------------------
PROC_CMDLINE="${KERNEL_COMMON}/fs/proc/cmdline.c"
add_extern "$PROC_CMDLINE" \
    'extern const char *ksu_get_safe_cmdline(void);' \
    'ksu_get_safe_cmdline(void'

inject_code "$PROC_CMDLINE" \
    'cmdline_proc_show' \
    'const char *safe = ksu_get_safe_cmdline(); if (safe) { seq_printf(m, "%s\n", safe); return 0; }' \
    'safe = ksu_get_safe_cmdline()' \
    'cmdline_proc_show (cmdline spoofing)'

# --- 10. /proc/version 伪装 — fs/proc/version.c ------------------------------
PROC_VERSION="${KERNEL_COMMON}/fs/proc/version.c"
add_extern "$PROC_VERSION" \
    'extern const char *ksu_get_safe_version(void);' \
    'ksu_get_safe_version(void'

inject_code "$PROC_VERSION" \
    'version_proc_show' \
    'const char *safe_ver = ksu_get_safe_version(); if (safe_ver) { seq_printf(m, "%s\n", safe_ver); return 0; }' \
    'safe_ver = ksu_get_safe_version()' \
    'version_proc_show (version spoofing)'

# --- 11. /proc/iomem 隐藏 — kernel/resource.c --------------------------------
RESOURCE="${KERNEL_COMMON}/kernel/resource.c"
add_extern "$RESOURCE" \
    'extern bool ksu_iomem_line_filter(const char *line, size_t len);' \
    'ksu_iomem_line_filter(const char'

inject_code "$RESOURCE" \
    'static int r_show' \
    'if (ksu_iomem_line_filter(seq_buf_str(m->buf), seq_buf_used(m->buf))) return 0;' \
    'ksu_iomem_line_filter(seq_buf_str' \
    'resource r_show (iomem hiding)'

# --- 12. kprobes list 隐藏 — 由 ksu_debugfs_cleanup 的 kallsyms 过滤覆盖 ---

# --- 13. SELinux enforce 伪装 — security/selinux/selinuxfs.c -----------------
SELINUXFS="${KERNEL_COMMON}/security/selinux/selinuxfs.c"
add_extern "$SELINUXFS" \
    'extern int ksu_spoof_enforce(int real_enforce);' \
    'ksu_spoof_enforce(int'

inject_code "$SELINUXFS" \
    'sel_read_enforce' \
    'enforce = ksu_spoof_enforce(enforce);' \
    'ksu_spoof_enforce(enforce)' \
    'sel_read_enforce (SELinux spoofing)'

# --- 14. /proc/self/attr/current 伪装 — fs/proc/base.c ----------------------
add_extern "$PROC_BASE" \
    'extern char *ksu_spoof_selinux_context(const char *original);' \
    'ksu_spoof_selinux_context(const char'

inject_code "$PROC_BASE" \
    'proc_pid_attr_read' \
    'char *spoofed = ksu_spoof_selinux_context(buf); if (spoofed) { len = strlen(spoofed); memcpy(buf, spoofed, len); buf[len] = 0; kfree(spoofed); }' \
    'ksu_spoof_selinux_context(buf)' \
    'proc_pid_attr_read (SELinux context spoofing)'

# --- 15. /proc/self/status 伪装 — fs/proc/array.c ----------------------------
PROC_ARRAY="${KERNEL_COMMON}/fs/proc/array.c"
add_extern "$PROC_ARRAY" \
    'extern bool ksu_status_line_filter(const char *line, size_t len, char **replacement);' \
    'ksu_status_line_filter(const char'

inject_code "$PROC_ARRAY" \
    'proc_pid_status' \
    'char *replacement = NULL; if (ksu_status_line_filter(seq_buf_str(m->buf), seq_buf_used(m->buf), &replacement)) { if (replacement) { seq_puts(m, replacement); kfree(replacement); } return 0; }' \
    'ksu_status_line_filter(seq_buf_str' \
    'proc_pid_status (status spoofing)'

# --- 16. reboot 隐蔽 — 由 ksu_reboot_stealth.c 的 kprobe 实现 ----------------

# ===========================================================================
# 结果汇总
# ===========================================================================
echo ""
echo "================================================"
echo " Injection summary:"
echo "   Passed:  ${PASS_COUNT}"
echo "   Failed:  ${FAIL_COUNT}"
echo "   Skipped: ${SKIP_COUNT}"
echo "================================================"

if [ "$FAIL_COUNT" -gt 0 ]; then
    echo ""
    echo "WARNING: ${FAIL_COUNT} injection(s) failed."
    echo "This usually means the kernel source anchor line changed."
    echo "The module will still compile, but the failed hooks won't be active."
    echo "Check the build log above for [FAIL] entries."
fi

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