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
set -eu

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
# 自动检测多行函数签名：
#   - 如果锚点看起来像函数签名（含类型关键字），在 { 之后插入
#   - 如果锚点是函数体内的代码，直接在锚点行后插入
# { 匹配模式：独占一行 ^{$} 或 行末 ) { 形式
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

    # 找到锚点行号
    local anchor_line
    anchor_line=$(grep -nF "$anchor" "$file" 2>/dev/null | head -1 | cut -d: -f1)
    if [ -z "$anchor_line" ]; then
        dump_context "$file" "$anchor" line
        echo "  [FAIL] $name — anchor not found"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        return 0
    fi

    # 判断锚点是否像函数签名（含类型关键字或 static 修饰符）
    local anchor_text
    anchor_text=$(sed -n "${anchor_line}p" "$file")
    local is_func_sig=0
    if echo "$anchor_text" | grep -qE '(static\s+)?(int|void|bool|ssize_t|size_t|long|unsigned|struct|const|char|u64|u32|s32|extern|enum)\s+\w+\s*\('; then
        is_func_sig=1
    fi

    if [ "$is_func_sig" -eq 1 ]; then
        # 函数签名：找 {（独占一行 或 行末 ) { 形式）
        local brace_off
        brace_off=$(tail -n +${anchor_line} "$file" | grep -n -E '^\{[[:space:]]*$|\)[[:space:]]*\{[[:space:]]*$' | head -1 | cut -d: -f1)

        if [ -n "$brace_off" ] && [ "$brace_off" -le 10 ]; then
            # 在 { 之后插入 (brace_off 从 tail+grep 输出，1-indexed)
            local insert_line=$((anchor_line + brace_off - 1))
            sed -i "${insert_line}a\\${code}" "$file"
        else
            # 没找到 {，直接插入锚点行后
            sed -i "${anchor_line}a\\${code}" "$file"
        fi
    else
        # 函数体内锚点：直接插入锚点行后
        sed -i "${anchor_line}a\\${code}" "$file"
    fi

    if grep -qF "$check" "$file"; then
        echo "  [OK]   $name"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo "  [FAIL] $name — injection failed"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    return 0
}

# 在指定锚点行之前插入代码（用于在 dir_emit 等调用前插入过滤逻辑）
inject_before() {
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

    local anchor_line
    anchor_line=$(grep -nF "$anchor" "$file" 2>/dev/null | head -1 | cut -d: -f1)
    if [ -z "$anchor_line" ]; then
        dump_context "$file" "$anchor" line
        echo "  [FAIL] $name — anchor not found"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        return 0
    fi

    # 在锚点行之前插入
    sed -i "${anchor_line}i\\${code}" "$file"

    if grep -qF "$check" "$file"; then
        echo "  [OK]   $name"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo "  [FAIL] $name — injection failed"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    return 0
}

# 自动适配注入：找到目标函数，跳过所有变量声明，在最后一个声明后注入
# 用法: inject_after_decls file func_sig_pattern code check name
# 工作原理：
#   1. 用 func_sig_pattern 匹配函数签名行
#   2. 找到 { 括号
#   3. 从 { 之后逐行扫描，用类型关键字正则识别变量声明
#   4. 遇到第一个非声明行停止，在最后一个声明行之后注入
# 能正确处理 C89 声明必须在代码之前的规则，不依赖任何硬编码锚点。

# 当锚点找不到时，输出目标文件的相关源码上下文，方便直接修复
# 用法: dump_context file pattern mode
# mode: func (搜索函数签名) | line (搜索代码行)
dump_context() {
    local file="$1"
    local pattern="$2"
    local mode="$3"

    echo "  [DUMP] ═══ context from $(basename "$file") ═══"

    case "$mode" in
        func)
            # 提取函数名（去掉返回值类型和参数）
            local func_name
            func_name=$(echo "$pattern" | sed -E 's/^(static\s+)?(inline\s+)?(const\s+)?(int\s+|void\s+|bool\s+|ssize_t\s+|size_t\s+|long\s+|unsigned\s+|char\s+|u64\s+|u32\s+|s32\s+|struct\s+\w+\s+)?([a-zA-Z_][a-zA-Z0-9_]*)\s*\(.*/\5/')
            echo "  [DUMP] Searching for function: $func_name"
            local func_line
            func_line=$(grep -n "$func_name\s*(" "$file" 2>/dev/null | head -3)
            if [ -n "$func_line" ]; then
                echo "  [DUMP] Candidate functions:"
                echo "$func_line" | while IFS= read -r ln; do
                    echo "  [DUMP]   $ln"
                done
                # 对第一个候选函数输出前30行上下文
                local first_line
                first_line=$(echo "$func_line" | head -1 | cut -d: -f1)
                if [ -n "$first_line" ]; then
                    echo "  [DUMP] First 30 lines from line $first_line:"
                    sed -n "${first_line},$((first_line + 30))p" "$file" 2>/dev/null | head -30 | while IFS= read -r ln; do
                        echo "  [DUMP]   $ln"
                    done
                fi
            else
                echo "  [DUMP] No function matching '$func_name' found"
                echo "  [DUMP] First 30 lines of file:"
                head -30 "$file" 2>/dev/null | while IFS= read -r ln; do
                    echo "  [DUMP]   $ln"
                done
            fi
            ;;
        line)
            # 提取关键字（前几个词）
            local keyword
            keyword=$(echo "$pattern" | sed 's/\*/\\*/g' | awk '{print $1, $2, $3}' | sed 's/ $//')
            echo "  [DUMP] Searching for: $keyword"
            local matches
            matches=$(grep -n "$keyword" "$file" 2>/dev/null | head -5)
            if [ -n "$matches" ]; then
                echo "  [DUMP] Related lines:"
                echo "$matches" | while IFS= read -r ln; do
                    echo "  [DUMP]   $ln"
                done
                # 对第一个匹配行输出上下文
                local first_line
                first_line=$(echo "$matches" | head -1 | cut -d: -f1)
                if [ -n "$first_line" ]; then
                    local start=$((first_line - 5))
                    [ "$start" -lt 1 ] && start=1
                    echo "  [DUMP] Context (lines $start-$((first_line + 10))):"
                    sed -n "${start},$((first_line + 10))p" "$file" 2>/dev/null | while IFS= read -r ln; do
                        echo "  [DUMP]   $ln"
                    done
                fi
            else
                echo "  [DUMP] No matches for '$keyword'"
            fi
            ;;
    esac
    echo "  [DUMP] ═══ end context ═══"
}

inject_after_decls() {
    local file="$1"
    local func_sig="$2"
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

    # 1. 找到函数签名行
    local func_line
    func_line=$(grep -n "$func_sig" "$file" 2>/dev/null | head -1 | cut -d: -f1)
    if [ -z "$func_line" ]; then
        dump_context "$file" "$func_sig" func
        echo "  [FAIL] $name — function not found ($func_sig)"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        return 0
    fi

    # 2. 找到 { 行（在函数签名后10行内）
    local brace_off
    brace_off=$(tail -n +${func_line} "$file" | grep -n -E '^\{[[:space:]]*$|\)[[:space:]]*\{[[:space:]]*$' | head -1 | cut -d: -f1)
    if [ -z "$brace_off" ]; then
        dump_context "$file" "$func_sig" func
        echo "  [FAIL] $name — brace not found"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        return 0
    fi
    local brace_line=$((func_line + brace_off - 1))

    # 3. 从 { 之后逐行扫描，识别变量声明
    local last_decl_line=$brace_line
    local line=$((brace_line + 1))
    local max_scan=60
    # 匹配 C 变量声明行：以类型关键字开头（可选 static/const/extern/volatile 等修饰符）
    local decl_pattern='^\s*(static\s+|extern\s+|const\s+|volatile\s+|register\s+|__user\s+|__kernel\s+|__force\s+|__iomem\s+|__rcu\s+)*(struct\s+|union\s+|enum\s+|int\s+|char\s+|void\s+|bool\s+|unsigned\s+|long\s+|short\s+|double\s+|float\s+|size_t\s+|ssize_t\s+|u[0-9]+\s+|s[0-9]+\s+|uint[0-9]+_t\s+|int[0-9]+_t\s+|typeof\s+|__typeof__\s+|atomic_t\s+|spinlock_t\s+|mutex\s+|rwlock_t\s+|loff_t\s+|gfp_t\s+|pid_t\s+|uid_t\s+|gid_t\s+|umode_t\s+|dev_t\s+|ino_t\s+|off_t\s+|time64_t\s+|ktime_t\s+|seqcount_t\s+|\w+_t\s+)'

    while [ "$line" -le $((brace_line + max_scan)) ]; do
        local line_text
        line_text=$(sed -n "${line}p" "$file" 2>/dev/null)

        # 跳过空行
        if [ -z "$(echo "$line_text" | tr -d '[:space:]')" ]; then
            line=$((line + 1))
            continue
        fi

        # 跳过注释行
        if echo "$line_text" | grep -qE '^\s*(/\*|\*|//)'; then
            line=$((line + 1))
            continue
        fi

        # 跳过预处理器指令
        if echo "$line_text" | grep -qE '^\s*#'; then
            line=$((line + 1))
            continue
        fi

        # 跳过标签 (如 out:)
        if echo "$line_text" | grep -qE '^\s*[a-zA-Z_][a-zA-Z0-9_]*\s*:'; then
            line=$((line + 1))
            continue
        fi

        # 检查是否是变量声明（匹配类型关键字，且不是 for 循环）
        if echo "$line_text" | grep -qE "$decl_pattern" && ! echo "$line_text" | grep -qE '^\s*for\s*\('; then
            last_decl_line=$line

            # 处理多行声明（struct initializer 跨行，含 { 但无 };）
            if echo "$line_text" | grep -q '{' && ! echo "$line_text" | grep -qE '\};[[:space:]]*$'; then
                local inner=$((line + 1))
                while [ "$inner" -le $((brace_line + max_scan)) ]; do
                    local inner_text
                    inner_text=$(sed -n "${inner}p" "$file" 2>/dev/null)
                    if echo "$inner_text" | grep -qE '\};'; then
                        last_decl_line=$inner
                        line=$inner
                        break
                    fi
                    if echo "$inner_text" | grep -q ';' && ! echo "$inner_text" | grep -q '{'; then
                        last_decl_line=$inner
                        line=$inner
                        break
                    fi
                    inner=$((inner + 1))
                done
            fi

            line=$((line + 1))
            continue
        fi

        # 不是声明也不是空行/注释 — 停止扫描
        break
    done

    # 4. 在最后一个声明行之后注入
    sed -i "${last_decl_line}a\\${code}" "$file"

    if grep -qF "$check" "$file"; then
        echo "  [OK]   $name (auto, after line $last_decl_line)"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo "  [FAIL] $name — injection failed"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    return 0
}

# ===========================================================================
# 注入规则: add_extern 的 check 用函数签名片段(含参数类型)
#           inject_code 的 check 用函数调用片段(含实参)
#           两者不能相同，否则 add_extern 插入 extern 声明后 inject_code
#           会误判为"已注入"而跳过。
# ===========================================================================

# --- 1. 进程隐藏 — fs/proc/base.c (proc_pid_readdir) ------------------------
# Android 5.15 实际源码: ctx->pos = iter.tgid + TGID_OFFSET; (line 6060)
# 在 snprintf 之后、proc_fill_cache 之前注入过滤逻辑
PROC_BASE="${KERNEL_COMMON}/fs/proc/base.c"
add_extern "$PROC_BASE" \
    'extern bool ksu_proc_pid_dirent_filter(const char *name, int namelen);' \
    'ksu_proc_pid_dirent_filter(const char'

inject_code "$PROC_BASE" \
    'snprintf(name, sizeof(name), "%u", iter.tgid)' \
    'if (ksu_proc_pid_dirent_filter(name, len)) continue;' \
    'ksu_proc_pid_dirent_filter(name, len)' \
    'proc_pid_readdir (PID hiding)'

# --- 线程枚举过滤 — proc_task_readdir ---------------------------------------
# Android 5.15 实际源码: 无 dir_emit，使用 snprintf(..., "%u", tid) (line 6681)
# 在 snprintf 之后、proc_fill_cache 之前注入过滤逻辑
add_extern "$PROC_BASE" \
    'extern bool ksu_proc_task_dirent_filter(const char *name, int namelen);' \
    'ksu_proc_task_dirent_filter(const char'

inject_code "$PROC_BASE" \
    'snprintf(name, sizeof(name), "%u", tid)' \
    'if (ksu_proc_task_dirent_filter(name, len)) continue;' \
    'ksu_proc_task_dirent_filter(name, len)' \
    'proc_task_readdir (thread hiding)'

# --- 2. 挂载隐藏 — fs/proc_namespace.c (show_vfsmnt) ------------------------
# 5.15 内核注意：show_vfsmnt 有 5 个局部变量声明，不能注入在 { 之后
# 锚点改为第一个执行语句 if (sb->s_op->show_devname)，确保在所有声明之后
PROC_NS="${KERNEL_COMMON}/fs/proc_namespace.c"
add_extern "$PROC_NS" \
    'extern bool ksu_mounts_line_filter(const char *line, size_t len);' \
    'ksu_mounts_line_filter(const char'

inject_before "$PROC_NS" \
    'if (sb->s_op->show_devname)' \
    'if (ksu_mounts_line_filter(m->buf, m->count)) return 0;' \
    'ksu_mounts_line_filter(m->buf' \
    'show_vfsmnt (mounts hiding)'

# --- 3. 网络隐藏 — net/unix/af_unix.c ---------------------------------------
# s 在 else{} 块内声明，不能用 inject_after_decls（会注入到函数顶导致 s 未声明）
# 必须用 inject_code 紧贴 struct sock *s = v; 锚点注入
UNIX_FILE="${KERNEL_COMMON}/net/unix/af_unix.c"
add_extern "$UNIX_FILE" \
    'extern bool ksu_net_unix_line_filter(const char *sun_path, struct sock *sk);' \
    'ksu_net_unix_line_filter(const char'

inject_code "$UNIX_FILE" \
    'struct unix_sock *u = unix_sk(s);' \
    'if (ksu_net_proc_line_filter(NULL, s)) return 0;' \
    'ksu_net_proc_line_filter(NULL' \
    'unix_seq_show (socket hiding)'

# --- 4. TCP socket 隐藏 — net/ipv4/tcp_ipv4.c -------------------------------
# 安全起见用 inject_code 紧贴 struct sock *sk = v; 锚点注入
TCP_FILE="${KERNEL_COMMON}/net/ipv4/tcp_ipv4.c"
add_extern "$TCP_FILE" \
    'extern bool ksu_net_proc_line_filter(const char *line, struct sock *sk);' \
    'ksu_net_proc_line_filter(const char'

inject_code "$TCP_FILE" \
    'struct sock *sk = v;' \
    'if (ksu_net_proc_line_filter(NULL, sk)) return 0;' \
    'ksu_net_proc_line_filter(NULL' \
    'tcp4_seq_show (TCP hiding)'

# --- 5. kallsyms 隐藏 — kernel/kallsyms.c -----------------------------------
# 使用 inject_after_decls 自动适配，不依赖硬编码锚点
KALLSYMS="${KERNEL_COMMON}/kernel/kallsyms.c"
add_extern "$KALLSYMS" \
    'extern bool ksu_kallsyms_filter(const char *sym_name);' \
    'ksu_kallsyms_filter(const char'

inject_after_decls "$KALLSYMS" \
    'static int s_show(' \
    'if (ksu_kallsyms_filter(iter->name)) return 0;' \
    'ksu_kallsyms_filter(iter->name)' \
    'kallsyms s_show (symbol hiding)'

# --- 6. /proc/modules 隐藏 — kernel/module/main.c (5.17+) 或 kernel/module.c (5.15) ---
# 5.15 内核注意：KSU/SUSFS 补丁会在 m_show 中添加 void *value; 声明
# 且该声明位于 We always ignore unformed modules 注释之后，
# 因此不能使用注释作为锚点。改用 seq_printf(m, "%s %u" 作为锚点，
# 在所有声明之后、模块信息输出之前注入过滤逻辑。
MOD_MAIN="${KERNEL_COMMON}/kernel/module/main.c"
if [ ! -f "$MOD_MAIN" ]; then
    MOD_MAIN="${KERNEL_COMMON}/kernel/module.c"
fi
add_extern "$MOD_MAIN" \
    'extern bool ksu_proc_modules_filter(const char *line);' \
    'ksu_proc_modules_filter(const char'

inject_before "$MOD_MAIN" \
    'seq_printf(m, "%s %u"' \
    'if (ksu_proc_modules_filter(buf)) return 0;' \
    'ksu_proc_modules_filter(buf)' \
    'modules m_show (module hiding)'

# --- 7. /proc/stat 伪装 — 5.15 内核中 ctxt/processes/btime 不是局部变量
#     show_stat() 直接使用 nr_context_switches()/total_forks/boottime.tv_sec
#     无法通过指针修改，需要重写注入策略（暂跳过）
# ===========================================================================

# --- 8. /proc/uptime 伪装 — fs/proc/uptime.c ---------------------------------
# 使用 inject_after_decls 自动适配，不依赖硬编码锚点
PROC_UPTIME="${KERNEL_COMMON}/fs/proc/uptime.c"
add_extern "$PROC_UPTIME" \
    'extern void ksu_fake_uptime(u64 *real_sec, u64 *real_nsec, u64 *idle_sec, u64 *idle_nsec);' \
    'ksu_fake_uptime(u64'

inject_after_decls "$PROC_UPTIME" \
    'static int uptime_proc_show(' \
    'ksu_fake_uptime((u64 *)&uptime.tv_sec, (u64 *)&uptime.tv_nsec, (u64 *)&idle.tv_sec, &idle_nsec);' \
    'ksu_fake_uptime((u64' \
    'uptime_proc_show (uptime spoofing)'

# --- 9. /proc/cmdline 伪装 — fs/proc/cmdline.c -------------------------------
# 使用 inject_after_decls 自动适配，不依赖硬编码锚点
PROC_CMDLINE="${KERNEL_COMMON}/fs/proc/cmdline.c"
add_extern "$PROC_CMDLINE" \
    'extern const char *ksu_get_safe_cmdline(void);' \
    'ksu_get_safe_cmdline(void'

inject_after_decls "$PROC_CMDLINE" \
    'static int cmdline_proc_show(' \
    'const char *safe = ksu_get_safe_cmdline(); if (safe) { seq_printf(m, "%s\\\\n", safe); return 0; }' \
    'safe = ksu_get_safe_cmdline()' \
    'cmdline_proc_show (cmdline spoofing)'

# --- 10. /proc/version 伪装 — fs/proc/version.c ------------------------------
# 使用 inject_after_decls 自动适配，不依赖硬编码锚点
PROC_VERSION="${KERNEL_COMMON}/fs/proc/version.c"
add_extern "$PROC_VERSION" \
    'extern const char *ksu_get_safe_version(void);' \
    'ksu_get_safe_version(void'

inject_after_decls "$PROC_VERSION" \
    'static int version_proc_show(' \
    'const char *safe_ver = ksu_get_safe_version(); if (safe_ver) { seq_printf(m, "%s\\\\n", safe_ver); return 0; }' \
    'safe_ver = ksu_get_safe_version()' \
    'version_proc_show (version spoofing)'

# --- 11. /proc/iomem 隐藏 — kernel/resource.c --------------------------------
# 使用 inject_after_decls 自动适配，不依赖硬编码锚点
RESOURCE="${KERNEL_COMMON}/kernel/resource.c"
add_extern "$RESOURCE" \
    'extern bool ksu_iomem_line_filter(const char *line, size_t len);' \
    'ksu_iomem_line_filter(const char'

inject_after_decls "$RESOURCE" \
    'static int r_show(' \
    'if (ksu_iomem_line_filter(m->buf, m->count)) return 0;' \
    'ksu_iomem_line_filter(m->buf' \
    'resource r_show (iomem hiding)'

# --- 12. kprobes list 隐藏 — 由 ksu_debugfs_cleanup 的 kallsyms 过滤覆盖 ---

# --- 13. SELinux enforce 伪装 — security/selinux/selinuxfs.c -----------------
# Android 5.15 实际源码: sel_read_enforce 使用 enforcing_enabled(fsi->state)
# 而非 selinux_state.enforcing；锚点和注入代码都需要改用 fsi->state
# length = scnprintf(...) 被分成两行，grep -nF 匹配不到，改用 return 行做锚点
SELINUXFS="${KERNEL_COMMON}/security/selinux/selinuxfs.c"
add_extern "$SELINUXFS" \
    'extern int ksu_spoof_enforce(int real_enforce);' \
    'ksu_spoof_enforce(int'

inject_before "$SELINUXFS" \
    'return simple_read_from_buffer' \
    'if (ksu_spoof_enforce(enforcing_enabled(fsi->state)) == 0) length = scnprintf(tmpbuf, TMPBUFLEN, "%d", 0);' \
    'ksu_spoof_enforce(enforcing_enabled(fsi->state))' \
    'sel_read_enforce (SELinux spoofing)'

# --- 14. /proc/self/attr/current 伪装 — 需要修改 ksu_spoof_selinux_context
#     为原地修改接口后才能正确注入，暂时跳过
# ===========================================================================

# --- 15. /proc/self/status 伪装 — fs/proc/array.c ----------------------------
# 使用 inject_after_decls 自动适配，不依赖硬编码锚点
PROC_ARRAY="${KERNEL_COMMON}/fs/proc/array.c"
add_extern "$PROC_ARRAY" \
    'extern bool ksu_status_line_filter(const char *line, size_t len, char **replacement);' \
    'ksu_status_line_filter(const char'

inject_after_decls "$PROC_ARRAY" \
    'int proc_pid_status(' \
    'char *replacement = NULL; if (ksu_status_line_filter(m->buf, m->count, &replacement)) { if (replacement) { seq_puts(m, replacement); kfree(replacement); } return 0; }' \
    'ksu_status_line_filter(m->buf' \
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