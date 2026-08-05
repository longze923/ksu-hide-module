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
    # 只取文件顶部 include 区的最后一个 #include。
    # 不能用全文件的最后一个 #include：部分内核文件（如 kernel/signal.c
    # 的 CONFIG_KGDB_KDB 段）在文件尾部还有 include，会把 extern 插到
    # 使用它的函数之后，导致 -Werror=implicit-function-declaration。
    local last_inc
    last_inc=$(awk '
        /^[[:space:]]*#include/ { last = NR; next }
        /^[[:space:]]*$/ { next }
        /^[[:space:]]*(\/\*|\*|\/\/)/ { next }
        /^[[:space:]]*#/ { next }
        { exit }
        END { if (last) print last }
    ' "$file" 2>/dev/null)
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

# ===========================================================================
# [解决方案] 只启用核心隐藏钩子组（进程/线程枚举、挂载、unix/tcp socket）
# 组1（cmdline/version/selinux）已按用户要求删除；
# 其余钩子（kallsyms/modules/iomem/新钩子组）保持停用，逐个验证后恢复。
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
# 方案：函数入口记录 m->count，本行输出完成后只对"本条新增内容"做关键词过滤，
# 命中则回滚 m->count 并跳过该条。修复旧实现把整个累积缓冲区当一行匹配、
# 导致一条关键词误删后续所有挂载行的问题。
PROC_NS="${KERNEL_COMMON}/fs/proc_namespace.c"
add_extern "$PROC_NS" \
    'extern bool ksu_mounts_line_filter(const char *line, size_t len);' \
    'ksu_mounts_line_filter(const char'

inject_after_decls "$PROC_NS" \
    'static int show_vfsmnt(' \
    'size_t ksu_mount_start = m->count;' \
    'ksu_mount_start = m->count' \
    'show_vfsmnt (mounts line start)'

inject_before "$PROC_NS" \
    'seq_puts(m, " 0 0\n")' \
    'if (!err && ksu_mounts_line_filter(m->buf + ksu_mount_start, m->count - ksu_mount_start)) { m->count = ksu_mount_start; return 0; }' \
    'ksu_mounts_line_filter(m->buf + ksu_mount_start' \
    'show_vfsmnt (mounts line filter)'

# --- 3. 网络隐藏 — net/unix/af_unix.c ---------------------------------------
# s 在 else{} 块内声明，不能用 inject_after_decls（会注入到函数顶导致 s 未声明）
# 必须用 inject_code 紧贴 struct sock *s = v; 锚点注入
UNIX_FILE="${KERNEL_COMMON}/net/unix/af_unix.c"
add_extern "$UNIX_FILE" \
    'extern bool ksu_net_proc_line_filter(const char *line, struct sock *sk);' \
    'ksu_net_proc_line_filter(const char'

add_extern "$UNIX_FILE" \
    'extern bool ksu_net_unix_line_filter(const char *sun_path, struct sock *sk);' \
    'ksu_net_unix_line_filter(const char'

inject_before "$UNIX_FILE" \
    'seq_printf(seq, "%pK: %08X %08X %08X %04X %02X %5lu",' \
    'if (ksu_net_proc_line_filter(NULL, s)) { unix_state_unlock(s); return 0; }' \
    'ksu_net_proc_line_filter(NULL, s))' \
    'unix_seq_show (socket hiding)'

# --- 4. TCP socket 隐藏 — net/ipv4/tcp_ipv4.c -------------------------------
# 安全起见用 inject_code 紧贴 struct sock *sk = v; 锚点注入
TCP_FILE="${KERNEL_COMMON}/net/ipv4/tcp_ipv4.c"
add_extern "$TCP_FILE" \
    'extern bool ksu_net_proc_line_filter(const char *line, struct sock *sk);' \
    'ksu_net_proc_line_filter(const char'

inject_code "$TCP_FILE" \
    'struct sock *sk = v;' \
    'if (v != SEQ_START_TOKEN && ksu_net_proc_line_filter(NULL, sk)) return 0;' \
    'ksu_net_proc_line_filter(NULL, sk))' \
    'tcp4_seq_show (TCP hiding)'

# --- 4b. [诊断停用] unix sun_path 过滤 --------------------------------------
if false; then
inject_before "$UNIX_FILE" \
    'under unix_table_lock here' \
    'if (u->addr && ksu_net_unix_line_filter(u->addr->name->sun_path, s)) { unix_state_unlock(s); return 0; }' \
    'ksu_net_unix_line_filter(u->addr' \
    'unix_seq_show (sun_path hiding)'
fi

# ===========================================================================
# [诊断停用] kallsyms + /proc/modules（价值低，待验证后恢复）
# ===========================================================================
if false; then

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
    'if (ksu_proc_modules_filter(mod->name)) return 0;' \
    'ksu_proc_modules_filter(mod->name)' \
    'modules m_show (module hiding)'
fi

# --- 7. /proc/stat 伪装 — 5.15 内核中 ctxt/processes/btime 不是局部变量
#     show_stat() 直接使用 nr_context_switches()/total_forks/boottime.tv_sec
#     无法通过指针修改，需要重写注入策略（暂跳过）
# ===========================================================================

# --- 8. /proc/uptime 伪装（已停用）------------------------------------------
# 虚拟时源功能按用户要求先停用：不注入 ksu_fake_uptime。
# 待时间虚拟化方案（syscall 层 + proc 层一致性）确认后再启用。

# --- 9-10. /proc/cmdline + /proc/version 伪装（已按用户要求删除）-----------

# ===========================================================================
# [诊断停用] /proc/iomem（root-only，价值低，待验证后恢复）
# ===========================================================================
if false; then
# --- 11. /proc/iomem 隐藏 — kernel/resource.c --------------------------------
# 使用 inject_after_decls 自动适配，不依赖硬编码锚点
RESOURCE="${KERNEL_COMMON}/kernel/resource.c"
add_extern "$RESOURCE" \
    'extern bool ksu_iomem_line_filter(const char *line, size_t len);' \
    'ksu_iomem_line_filter(const char'

inject_after_decls "$RESOURCE" \
    'static int r_show(' \
    'size_t ksu_iomem_start = m->count;' \
    'ksu_iomem_start = m->count' \
    'resource r_show (iomem start)'

inject_code "$RESOURCE" \
    'r->name ? r->name : "<BAD>");' \
    'if (ksu_iomem_line_filter(m->buf + ksu_iomem_start, m->count - ksu_iomem_start)) { m->count = ksu_iomem_start; return 0; }' \
    'ksu_iomem_line_filter(m->buf + ksu_iomem_start' \
    'resource r_show (iomem line filter)'
fi

# --- 12. kprobes list 隐藏 — 由 ksu_debugfs_cleanup 的 kallsyms 过滤覆盖 ---

# --- 13. SELinux enforce 伪装（已按用户要求删除）-----------------------------

# --- 14. /proc/self/attr/current 伪装 — 需要修改 ksu_spoof_selinux_context
#     为原地修改接口后才能正确注入，暂时跳过
# ===========================================================================

# --- 15-21. [诊断停用] 新钩子组 ---------------------------------------------
if false; then

# --- 15. /proc/self/status 伪装 (TracerPid / CapEff) — fs/proc/array.c ------
# 在 proc_pid_status 返回前对整段缓冲区做逐行过滤（原地压缩），
# 非零 TracerPid 伪装为 0、全 f CapEff 伪装为 0。
PROC_ARRAY="${KERNEL_COMMON}/fs/proc/array.c"
add_extern "$PROC_ARRAY" \
    'extern void ksu_status_buffer_filter(char *buf, size_t *count);' \
    'ksu_status_buffer_filter(char'

inject_code "$PROC_ARRAY" \
    'task_context_switch_counts(m, task);' \
    'ksu_status_buffer_filter(m->buf, &m->count);' \
    'ksu_status_buffer_filter(m->buf' \
    'proc_pid_status (status spoofing)'

# --- 16. /proc/<pid>/comm 伪装 — fs/proc/base.c (comm_show) -----------------
add_extern "$PROC_BASE" \
    'extern bool ksu_comm_spoof(pid_t pid, char *comm, size_t comm_len);' \
    'ksu_comm_spoof(pid_t'

inject_before "$PROC_BASE" \
    'proc_task_name(m, p, false);' \
    '{ char ksu_comm_buf[TASK_COMM_LEN]; pid_t ksu_pid = p->pid; if (ksu_comm_spoof(ksu_pid, ksu_comm_buf, sizeof(ksu_comm_buf))) { seq_puts(m, ksu_comm_buf); seq_putc(m, 10); put_task_struct(p); return 0; } }' \
    'ksu_comm_spoof(ksu_pid' \
    'comm_show (comm spoofing)'

# --- 17. /proc/<pid>/wchan 伪装 — fs/proc/base.c (proc_pid_wchan) ------------
add_extern "$PROC_BASE" \
    'extern bool ksu_wchan_filter(const char *wchan_name, size_t len);' \
    'ksu_wchan_filter(const char'

add_extern "$PROC_BASE" \
    'extern void ksu_wchan_spoof(char *out, size_t outsz);' \
    'ksu_wchan_spoof(char'

inject_before "$PROC_BASE" \
    'seq_puts(m, symname);' \
    '{ char ksu_wchan_buf[KSYM_NAME_LEN]; size_t ksu_wchan_len = strnlen(symname, sizeof(symname)); if (ksu_wchan_filter(symname, ksu_wchan_len)) { ksu_wchan_spoof(ksu_wchan_buf, sizeof(ksu_wchan_buf)); seq_puts(m, ksu_wchan_buf); return 0; } }' \
    'ksu_wchan_filter(symname' \
    'proc_pid_wchan (wchan spoofing)'

# --- 18. kill/tgkill 探测防御 — kernel/signal.c ------------------------------
# 在 syscall 实现入口注入过滤，命中隐藏进程返回 -ESRCH。
SIGNAL_FILE="${KERNEL_COMMON}/kernel/signal.c"
add_extern "$SIGNAL_FILE" \
    'extern int ksu_hidden_kill_filter(pid_t pid, int sig);' \
    'ksu_hidden_kill_filter(pid_t'

add_extern "$SIGNAL_FILE" \
    'extern int ksu_hidden_tgkill_filter(pid_t tgid, pid_t pid, int sig);' \
    'ksu_hidden_tgkill_filter(pid_t'

inject_before "$SIGNAL_FILE" \
    'prepare_kill_siginfo(sig, &info);' \
    '{ int ksu_kill_ret = ksu_hidden_kill_filter(pid, sig); if (ksu_kill_ret) return ksu_kill_ret; }' \
    'ksu_hidden_kill_filter(pid, sig)' \
    'sys_kill (kill probing defense)'

inject_before "$SIGNAL_FILE" \
    'if (pid <= 0 || tgid <= 0)' \
    '{ int ksu_tg_ret = ksu_hidden_tgkill_filter(tgid, pid, sig); if (ksu_tg_ret) return ksu_tg_ret; }' \
    'ksu_hidden_tgkill_filter(tgid, pid, sig)' \
    'sys_tgkill (tgkill probing defense)'

# --- 19. pidfd_open 探测防御 — kernel/pid.c ----------------------------------
PID_FILE="${KERNEL_COMMON}/kernel/pid.c"
add_extern "$PID_FILE" \
    'extern int ksu_hidden_pidfd_filter(pid_t pid, unsigned int flags);' \
    'ksu_hidden_pidfd_filter(pid_t'

inject_before "$PID_FILE" \
    'if (flags & ~PIDFD_NONBLOCK)' \
    '{ int ksu_pfd_ret = ksu_hidden_pidfd_filter(pid, flags); if (ksu_pfd_ret) return ksu_pfd_ret; }' \
    'ksu_hidden_pidfd_filter(pid, flags)' \
    'sys_pidfd_open (pidfd probing defense)'

# --- 20. namespace mtime 对齐 — fs/libfs.c (simple_getattr) ------------------
# nsfs inode 使用 simple_getattr，注入后由 ksu_ns_align_mtime 内部按
# NSFS_MAGIC 过滤，仅对齐 namespace inode 的 mtime。
LIBFS="${KERNEL_COMMON}/fs/libfs.c"
add_extern "$LIBFS" \
    'extern bool ksu_ns_align_mtime(struct kstat *stat, struct inode *inode);' \
    'ksu_ns_align_mtime(struct kstat'

inject_code "$LIBFS" \
    'generic_fillattr(&init_user_ns, inode, stat);' \
    'ksu_ns_align_mtime(stat, inode);' \
    'ksu_ns_align_mtime(stat, inode)' \
    'simple_getattr (ns mtime align)'

# --- 21. clock_gettime 一致性检查 — kernel/time/posix-timers.c --------------
# 仅为后续时间虚拟化提供一致性检查钩子；当前不伪造任何时间值。
POSIX_TIMERS="${KERNEL_COMMON}/kernel/time/posix-timers.c"
add_extern "$POSIX_TIMERS" \
    'extern void ksu_check_clock_consistency(const clockid_t which_clock, struct timespec64 *ts);' \
    'ksu_check_clock_consistency(const clockid_t'

inject_code "$POSIX_TIMERS" \
    'error = kc->clock_get_timespec(which_clock, &kernel_tp);' \
    'ksu_check_clock_consistency(which_clock, &kernel_tp);' \
    'ksu_check_clock_consistency(which_clock' \
    'clock_gettime (clock consistency)'
fi

# --- 22. reboot 隐匿 — 由 ksu_reboot_stealth.c 的 kprobe 实现 ----------------
# 在模块内注册 __arm64_sys_reboot kprobe，无需内核源码注入。

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
