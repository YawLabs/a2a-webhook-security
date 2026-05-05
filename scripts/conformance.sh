#!/usr/bin/env bash
# AWSP -- A2A Webhook Security Profile
# Local conformance runner. Executes every reference impl's native test
# suite against test-vectors.json in sequence, then prints a one-screen
# matrix:
#
#   Conformance matrix:
#     typescript: PASS
#     python:     PASS
#     go:         FAIL
#     java:       PASS
#     dotnet:     SKIP   (toolchain not installed)
#
# Exit 0 if every present toolchain passes; exit 1 if any one fails.
# Missing toolchains are SKIPped (not failed) so a contributor with only
# Go installed can still get useful local signal.
#
# We deliberately DO NOT use `set -e` at the top level -- we want to run
# every port even if an earlier one fails, so we capture each result and
# decide the overall exit at the end.

set -u
set -o pipefail

# Repo root resolution: this script lives at <repo>/scripts/conformance.sh
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

# ---- Color setup --------------------------------------------------------
# Color only when stdout is a TTY and the terminal claims to support it.
# Honor NO_COLOR (https://no-color.org/) as an explicit opt-out.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != "dumb" ]; then
    C_GREEN=$'\033[32m'
    C_RED=$'\033[31m'
    C_YELLOW=$'\033[33m'
    C_BOLD=$'\033[1m'
    C_RESET=$'\033[0m'
else
    C_GREEN=""
    C_RED=""
    C_YELLOW=""
    C_BOLD=""
    C_RESET=""
fi

# ---- Result storage -----------------------------------------------------
# Parallel arrays keyed by index. Bash 3.x compatible (macOS still ships
# bash 3.2 by default), so no associative arrays.
LANGS=(typescript python go java dotnet)
RESULTS=()
NOTES=()

record() {
    # record <result> <note>
    RESULTS+=("$1")
    NOTES+=("$2")
}

# ---- Section header helper ----------------------------------------------
section() {
    printf '\n%s==> %s%s\n' "${C_BOLD}" "$1" "${C_RESET}"
}

# ---- typescript ---------------------------------------------------------
section "typescript"
if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
    echo "  node/npm not found -- skipping"
    record SKIP "node/npm not installed"
else
    (
        cd "${REPO_ROOT}/reference/typescript" \
            && npm ci \
            && npm test
    )
    if [ $? -eq 0 ]; then
        record PASS ""
    else
        record FAIL ""
    fi
fi

# ---- python -------------------------------------------------------------
section "python"
# Prefer python3 (Linux/macOS); fall back to python (Windows MSYS, some
# distros). pip resolution mirrors the same precedence.
PY_CMD=""
if command -v python3 >/dev/null 2>&1; then
    PY_CMD=python3
elif command -v python >/dev/null 2>&1; then
    PY_CMD=python
fi
if [ -z "${PY_CMD}" ]; then
    echo "  python not found -- skipping"
    record SKIP "python not installed"
else
    (
        cd "${REPO_ROOT}/reference/python" \
            && "${PY_CMD}" -m pip install -e .[dev] \
            && "${PY_CMD}" -m pytest
    )
    if [ $? -eq 0 ]; then
        record PASS ""
    else
        record FAIL ""
    fi
fi

# ---- go -----------------------------------------------------------------
section "go"
if ! command -v go >/dev/null 2>&1; then
    echo "  go not found -- skipping"
    record SKIP "go not installed"
else
    (
        cd "${REPO_ROOT}/reference/go" \
            && go test ./...
    )
    if [ $? -eq 0 ]; then
        record PASS ""
    else
        record FAIL ""
    fi
fi

# ---- java ---------------------------------------------------------------
section "java"
if ! command -v mvn >/dev/null 2>&1; then
    echo "  mvn not found -- skipping"
    record SKIP "maven not installed"
else
    (
        cd "${REPO_ROOT}/reference/java" \
            && mvn -B test
    )
    if [ $? -eq 0 ]; then
        record PASS ""
    else
        record FAIL ""
    fi
fi

# ---- dotnet -------------------------------------------------------------
section "dotnet"
if ! command -v dotnet >/dev/null 2>&1; then
    echo "  dotnet not found -- skipping"
    record SKIP "dotnet sdk not installed"
else
    (
        cd "${REPO_ROOT}/reference/dotnet" \
            && dotnet test --configuration Release
    )
    if [ $? -eq 0 ]; then
        record PASS ""
    else
        record FAIL ""
    fi
fi

# ---- Final matrix -------------------------------------------------------
echo
echo "${C_BOLD}Conformance matrix:${C_RESET}"

# Width = longest lang name + 1 for the colon. "typescript" is 10 chars.
PAD_TO=11

overall=0
for i in "${!LANGS[@]}"; do
    lang="${LANGS[$i]}"
    result="${RESULTS[$i]}"
    note="${NOTES[$i]}"

    case "${result}" in
        PASS)  color="${C_GREEN}"  ;;
        FAIL)  color="${C_RED}"; overall=1 ;;
        SKIP)  color="${C_YELLOW}" ;;
        *)     color=""            ;;
    esac

    label="${lang}:"
    # Right-pad the label to a stable column.
    printf '  %-*s %s%s%s' "${PAD_TO}" "${label}" "${color}" "${result}" "${C_RESET}"
    if [ -n "${note}" ]; then
        printf '   (%s)' "${note}"
    fi
    printf '\n'
done

echo
exit "${overall}"
