#!/usr/bin/env bash

# 构建 watcher 的可发布二进制文件。
#
# 调用示例:
#   scripts/build_release.sh --target host
#   scripts/build_release.sh --target linux --target windows
#   CARGO_TARGET_DIR=dist scripts/build_release.sh --dry-run --target linux

set -Eeuo pipefail

readonly BINARY_NAME="watcher"
readonly TARGET_HOST="host"
readonly TARGET_LINUX="x86_64-unknown-linux-musl"
readonly TARGET_WINDOWS="x86_64-pc-windows-gnu"

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
readonly MANIFEST_PATH="${PROJECT_ROOT}/Cargo.toml"
readonly LOCKFILE_PATH="${PROJECT_ROOT}/Cargo.lock"
readonly CARGO_BIN="${CARGO:-cargo}"

if [[ -n "${CARGO_TARGET_DIR:-}" ]]; then
    if [[ "${CARGO_TARGET_DIR}" = /* ]]; then
        BUILD_DIR="${CARGO_TARGET_DIR}"
    else
        BUILD_DIR="${PROJECT_ROOT}/${CARGO_TARGET_DIR}"
    fi
else
    BUILD_DIR="${PROJECT_ROOT}/target"
fi
readonly BUILD_DIR

DRY_RUN=false
NORMALIZED_TARGET=""
declare -a TARGETS=()

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Build release binaries for watcher.

Options:
  -t, --target TARGET   Build one target. May be specified multiple times.
                        Accepted values: host, linux, windows, ${TARGET_LINUX},
                        ${TARGET_WINDOWS}.
                        Defaults to linux and windows.
      --dry-run         Print planned build commands without checking toolchains or building.
  -h, --help            Show this help message.

Environment:
  CARGO                 Path to the cargo executable (default: cargo).
  CARGO_TARGET_DIR      Output directory. Relative paths are resolved from the project root.

Artifacts are written below: ${BUILD_DIR}
EOF
}

log() {
    printf '[build-release] %s\n' "$*" >&2
}

fail() {
    log "error: $*"
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

normalize_target() {
    case "$1" in
        host | native)
            NORMALIZED_TARGET="${TARGET_HOST}"
            ;;
        linux | "${TARGET_LINUX}")
            NORMALIZED_TARGET="${TARGET_LINUX}"
            ;;
        windows | "${TARGET_WINDOWS}")
            NORMALIZED_TARGET="${TARGET_WINDOWS}"
            ;;
        *)
            fail "unsupported target: $1"
            ;;
    esac
}

append_target() {
    local target="$1"
    local selected

    for selected in "${TARGETS[@]:-}"; do
        [[ "${selected}" == "${target}" ]] && return
    done

    TARGETS+=("${target}")
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -t | --target)
                [[ $# -ge 2 ]] || fail "missing value for $1"
                normalize_target "$2"
                append_target "${NORMALIZED_TARGET}"
                shift 2
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            -h | --help)
                usage
                exit 0
                ;;
            *)
                fail "unknown argument: $1"
                ;;
        esac
    done

    if [[ ${#TARGETS[@]} -eq 0 ]]; then
        append_target "${TARGET_LINUX}"
        append_target "${TARGET_WINDOWS}"
    fi
}

ensure_project_layout() {
    [[ -f "${MANIFEST_PATH}" ]] || fail "Cargo manifest not found: ${MANIFEST_PATH}"
    [[ -f "${LOCKFILE_PATH}" ]] || fail "Cargo.lock not found: ${LOCKFILE_PATH}"
}

ensure_rust_target_installed() {
    local target="$1"

    [[ "${target}" == "${TARGET_HOST}" ]] && return

    require_command rustup

    if ! rustup target list --installed | grep -Fxq "${target}"; then
        fail "Rust target '${target}' is not installed. Run: rustup target add ${target}"
    fi
}

warn_if_linker_missing() {
    local target="$1"
    local linker=""

    case "${target}" in
        "${TARGET_LINUX}") linker="musl-gcc" ;;
        "${TARGET_WINDOWS}") linker="x86_64-w64-mingw32-gcc" ;;
        *) return ;;
    esac

    if ! command -v "${linker}" >/dev/null 2>&1; then
        log "warning: '${linker}' was not found; the build may require a configured custom linker"
    fi
}

binary_extension() {
    local target="$1"

    if [[ "${target}" == "${TARGET_WINDOWS}" ]] || \
        { [[ "${target}" == "${TARGET_HOST}" ]] && [[ "$(uname -s)" =~ ^(MINGW|MSYS|CYGWIN) ]]; }; then
        printf '.exe\n'
    fi
}

artifact_path() {
    local target="$1"
    local extension

    extension="$(binary_extension "${target}")"
    if [[ "${target}" == "${TARGET_HOST}" ]]; then
        printf '%s/release/%s%s\n' "${BUILD_DIR}" "${BINARY_NAME}" "${extension}"
    else
        printf '%s/%s/release/%s%s\n' "${BUILD_DIR}" "${target}" "${BINARY_NAME}" "${extension}"
    fi
}

print_command() {
    local argument

    printf '[build-release] dry-run:' >&2
    for argument in "$@"; do
        printf ' %q' "${argument}" >&2
    done
    printf '\n' >&2
}

build_target() {
    local target="$1"
    local artifact
    local -a command=(
        "${CARGO_BIN}" build
        --bin "${BINARY_NAME}"
        --manifest-path "${MANIFEST_PATH}"
        --locked
        --release
        --target-dir "${BUILD_DIR}"
    )

    if [[ "${target}" != "${TARGET_HOST}" ]]; then
        command+=(--target "${target}")
    fi
    artifact="$(artifact_path "${target}")"

    log "building ${target}"
    if [[ "${DRY_RUN}" == true ]]; then
        print_command "${command[@]}"
    else
        ensure_rust_target_installed "${target}"
        warn_if_linker_missing "${target}"
        "${command[@]}"
        [[ -f "${artifact}" ]] || fail "build completed but binary is missing: ${artifact}"
    fi

    log "artifact: ${artifact}"
}

main() {
    parse_arguments "$@"
    ensure_project_layout

    if [[ "${DRY_RUN}" != true ]]; then
        require_command "${CARGO_BIN}"
    fi

    log "project root: ${PROJECT_ROOT}"
    log "output directory: ${BUILD_DIR}"

    local target
    for target in "${TARGETS[@]}"; do
        build_target "${target}"
    done
}

main "$@"
