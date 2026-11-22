#!/usr/bin/env bash
# INVARIANT: Cross-platform bootstrap wrapper invoking native Rust carbon-stack installer without mutating the checkout or target config on read-only invocations.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNAME_S="$(uname -s 2>/dev/null || echo unknown)"
IS_WIN_HOST=0
case "${UNAME_S}" in
  MINGW*|MSYS*|CYGWIN*|Windows_NT) IS_WIN_HOST=1 ;;
esac

WITH_TOOLCHAINS=0
IS_DRY_RUN=0
HAS_DIAGNOSE=0
HAS_LIST_BACKUPS=0
HAS_ROLLBACK=0
HAS_FORCE=0
HAS_HELP=0
EFFECTIVE_CFG_DIR="${CARBON_CONFIG_DIR:-${HOME}/.gemini/config}"
FORWARD_ARGS=()

require_non_flag_val() {
  local flag_name="$1"
  local has_next="$2"
  local next_val="$3"
  if [[ "${has_next}" -eq 0 || -z "${next_val}" || "${next_val}" == -* ]]; then
    printf '{"ok":false,"error":"missing_flag_value","flag":"%s","detail":"Argument %s requires a non-flag value"}\n' "${flag_name}" "${flag_name}"
    exit 2
  fi
}

require_non_empty_eq_val() {
  local flag_name="$1"
  local eq_val="$2"
  if [[ -z "${eq_val}" ]]; then
    printf '{"ok":false,"error":"missing_flag_value","flag":"%s","detail":"Argument %s requires a non-empty value"}\n' "${flag_name}" "${flag_name}"
    exit 2
  fi
}

idx=0
args=("$@")
while [[ "${idx}" -lt "${#args[@]}" ]]; do
  arg="${args[${idx}]}"
  case "${arg}" in
    --with-toolchains)
      WITH_TOOLCHAINS=1
      ;;
    --dry-run)
      IS_DRY_RUN=1
      FORWARD_ARGS+=("${arg}")
      ;;
    --diagnose)
      HAS_DIAGNOSE=1
      FORWARD_ARGS+=("${arg}")
      ;;
    --list-backups)
      HAS_LIST_BACKUPS=1
      FORWARD_ARGS+=("${arg}")
      ;;
    --rollback)
      HAS_ROLLBACK=1
      FORWARD_ARGS+=("${arg}")
      if [[ $((idx + 1)) -lt "${#args[@]}" && "${args[$((idx + 1))]}" != -* ]]; then
        idx=$((idx + 1))
        if [[ -z "${args[${idx}]}" ]]; then
          printf '{"ok":false,"error":"missing_flag_value","flag":"--rollback"}\n'
          exit 2
        fi
        FORWARD_ARGS+=("${args[${idx}]}")
      fi
      ;;
    --rollback=*)
      HAS_ROLLBACK=1
      require_non_empty_eq_val "--rollback" "${arg#--rollback=}"
      FORWARD_ARGS+=("${arg}")
      ;;
    --force|--force-foreign)
      HAS_FORCE=1
      FORWARD_ARGS+=("${arg}")
      ;;
    --help|-h)
      HAS_HELP=1
      FORWARD_ARGS+=("${arg}")
      ;;
    --repo-root|--stack-home)
      if [[ $((idx + 1)) -lt "${#args[@]}" ]]; then
        require_non_flag_val "${arg}" 1 "${args[$((idx + 1))]}"
      else
        require_non_flag_val "${arg}" 0 ""
      fi
      idx=$((idx + 1))
      FORWARD_ARGS+=("${arg}" "${args[${idx}]}")
      ;;
    --repo-root=*)
      require_non_empty_eq_val "--repo-root" "${arg#--repo-root=}"
      FORWARD_ARGS+=("${arg}")
      ;;
    --stack-home=*)
      require_non_empty_eq_val "--stack-home" "${arg#--stack-home=}"
      FORWARD_ARGS+=("${arg}")
      ;;
    --target-config-dir|--config-dir)
      if [[ $((idx + 1)) -lt "${#args[@]}" ]]; then
        require_non_flag_val "${arg}" 1 "${args[$((idx + 1))]}"
      else
        require_non_flag_val "${arg}" 0 ""
      fi
      idx=$((idx + 1))
      EFFECTIVE_CFG_DIR="${args[${idx}]}"
      FORWARD_ARGS+=("--target-config-dir" "${EFFECTIVE_CFG_DIR}")
      ;;
    --target-config-dir=*)
      EFFECTIVE_CFG_DIR="${arg#--target-config-dir=}"
      require_non_empty_eq_val "--target-config-dir" "${EFFECTIVE_CFG_DIR}"
      FORWARD_ARGS+=("${arg}")
      ;;
    --config-dir=*)
      EFFECTIVE_CFG_DIR="${arg#--config-dir=}"
      require_non_empty_eq_val "--config-dir" "${EFFECTIVE_CFG_DIR}"
      FORWARD_ARGS+=("--target-config-dir=${EFFECTIVE_CFG_DIR}")
      ;;
    *)
      FORWARD_ARGS+=("${arg}")
      ;;
  esac
  idx=$((idx + 1))
done

if [[ "${HAS_HELP}" -eq 1 ]]; then
  printf 'usage: ./install.sh [--with-toolchains] [--dry-run] [--diagnose] [--list-backups] [--rollback [latest|<id>]] [--force|--force-foreign] [--repo-root <dir>] [--target-config-dir <dir>] [--stack-home <dir>] [--pretty]\n'
  exit 0
fi

NON_INSTALL_MODES=$((HAS_DIAGNOSE + HAS_LIST_BACKUPS + HAS_ROLLBACK))
if [[ "${NON_INSTALL_MODES}" -gt 1 ]] || [[ "${NON_INSTALL_MODES}" -eq 1 && $((IS_DRY_RUN + HAS_FORCE + WITH_TOOLCHAINS)) -gt 0 ]]; then
  printf '{"ok":false,"error":"conflicting_mode_flags","detail":"--diagnose, --list-backups, and --rollback are mutually exclusive and cannot be combined with --dry-run, --force-foreign, or --with-toolchains"}\n'
  exit 2
fi

find_checkout_carbon_bin() {
  local ext=""
  if [[ "${IS_WIN_HOST}" -eq 1 ]]; then
    ext=".exe"
  fi
  for cand in \
    "${SCRIPT_DIR}/plugin/bin/carbon-stack${ext}" \
    "${SCRIPT_DIR}/rust/target/release/carbon-stack${ext}"; do
    if [[ "${IS_WIN_HOST}" -eq 1 && -f "${cand}" ]] || [[ "${IS_WIN_HOST}" -eq 0 && -x "${cand}" ]]; then
      printf '%s\n' "${cand}"
      return 0
    fi
  done
  return 1
}

find_existing_carbon_bin() {
  if find_checkout_carbon_bin; then
    return 0
  fi
  local ext=""
  if [[ "${IS_WIN_HOST}" -eq 1 ]]; then
    ext=".exe"
  fi
  local inst_cand="${EFFECTIVE_CFG_DIR}/plugins/gemini-carbon-stack/bin/carbon-stack${ext}"
  if [[ "${IS_WIN_HOST}" -eq 1 && -f "${inst_cand}" ]] || [[ "${IS_WIN_HOST}" -eq 0 && -x "${inst_cand}" ]]; then
    printf '%s\n' "${inst_cand}"
    return 0
  fi
  if command -v carbon-stack >/dev/null 2>&1; then
    command -v carbon-stack
    return 0
  fi
  return 1
}

IS_READONLY=$((IS_DRY_RUN | HAS_DIAGNOSE | HAS_LIST_BACKUPS))
if [[ "${IS_READONLY}" -eq 1 ]]; then
  if EXISTING_BIN="$(find_existing_carbon_bin)"; then
    exec "${EXISTING_BIN}" install --repo-root "${SCRIPT_DIR}" "${FORWARD_ARGS[@]}"
  fi
  if command -v cargo >/dev/null 2>&1; then
    # SAFETY: Compile into an ephemeral temp target directory so clean checkouts remain unmodified during read-only preview/diagnose/list-backups while executing full Rust preflight and conflict validation.
    TMP_TARGET="$(mktemp -d)"
    trap 'rm -rf "${TMP_TARGET}"' EXIT
    CARGO_TARGET_DIR="${TMP_TARGET}" cargo build --release --locked --manifest-path "${SCRIPT_DIR}/rust/Cargo.toml" >&2
    BIN_EXT=""
    if [[ "${IS_WIN_HOST}" -eq 1 ]]; then BIN_EXT=".exe"; fi
    "${TMP_TARGET}/release/carbon-stack${BIN_EXT}" install --repo-root "${SCRIPT_DIR}" "${FORWARD_ARGS[@]}"
    exit $?
  fi
  printf '{"ok":false,"stage":"bootstrap","error":"carbon-stack binary is not built and cargo was not found on PATH"}\n'
  exit 1
fi

if [[ "${HAS_ROLLBACK}" -eq 1 ]]; then
  if CHECKOUT_BIN="$(find_checkout_carbon_bin)"; then
    exec "${CHECKOUT_BIN}" install --repo-root "${SCRIPT_DIR}" "${FORWARD_ARGS[@]}"
  fi
  if EXISTING_BIN="$(find_existing_carbon_bin)"; then
    if [[ "${IS_WIN_HOST}" -eq 1 ]]; then
      # SAFETY: Copy the installed binary to a temporary directory on Windows so `perform_rollback` never hits an OS image lock when replacing `${EFFECTIVE_CFG_DIR}/plugins/gemini-carbon-stack`.
      TMP_RB_DIR="$(mktemp -d)"
      trap 'rm -rf "${TMP_RB_DIR}"' EXIT
      cp "${EXISTING_BIN}" "${TMP_RB_DIR}/carbon-stack.exe"
      "${TMP_RB_DIR}/carbon-stack.exe" install --repo-root "${SCRIPT_DIR}" "${FORWARD_ARGS[@]}"
      exit $?
    fi
    exec "${EXISTING_BIN}" install --repo-root "${SCRIPT_DIR}" "${FORWARD_ARGS[@]}"
  fi
  if command -v cargo >/dev/null 2>&1; then
    TMP_TARGET="$(mktemp -d)"
    trap 'rm -rf "${TMP_TARGET}"' EXIT
    CARGO_TARGET_DIR="${TMP_TARGET}" cargo build --release --locked --manifest-path "${SCRIPT_DIR}/rust/Cargo.toml" >&2
    BIN_EXT=""
    if [[ "${IS_WIN_HOST}" -eq 1 ]]; then BIN_EXT=".exe"; fi
    "${TMP_TARGET}/release/carbon-stack${BIN_EXT}" install --repo-root "${SCRIPT_DIR}" "${FORWARD_ARGS[@]}"
    exit $?
  fi
  printf '{"ok":false,"stage":"bootstrap","error":"carbon-stack binary is not built and cargo was not found on PATH"}\n'
  exit 1
fi

if [[ "${WITH_TOOLCHAINS}" -eq 1 ]]; then
  if command -v npm >/dev/null 2>&1 && ! command -v tokenade >/dev/null 2>&1; then
    npm install -g @tokenade/cli
  fi
  if command -v tokenade >/dev/null 2>&1; then
    tokenade install --only antigravity --no-wrap-mcps --yes
  fi
  mkdir -p "${HOME}/.gemini/config" "${HOME}/.gemini/antigravity-cli"
  if [[ ! -s "${HOME}/.gemini/config/mcp_config.json" ]]; then
    cp "${SCRIPT_DIR}/templates/mcp_config.json" "${HOME}/.gemini/config/mcp_config.json"
  fi
  if [[ ! -s "${HOME}/.gemini/antigravity-cli/mcp_config.json" ]]; then
    cp "${SCRIPT_DIR}/templates/mcp_config.json" "${HOME}/.gemini/antigravity-cli/mcp_config.json"
  fi
  if [[ ! -f "${HOME}/.gemini/GEMINI.md" ]]; then
    cp "${SCRIPT_DIR}/templates/GEMINI.md" "${HOME}/.gemini/GEMINI.md"
  fi
fi

needs_rust_rebuild() {
  local bin="$1"
  if [[ ! -f "${bin}" ]]; then return 0; fi
  if [[ -n "$(find "${SCRIPT_DIR}/rust/src" "${SCRIPT_DIR}/rust/Cargo.toml" "${SCRIPT_DIR}/rust/Cargo.lock" -type f -newer "${bin}" 2>/dev/null | head -n 1)" ]]; then
    return 0
  fi
  return 1
}

if [[ "${IS_WIN_HOST}" -eq 1 ]]; then
  CARBON_BIN="${SCRIPT_DIR}/plugin/bin/carbon-stack.exe"
  if needs_rust_rebuild "${CARBON_BIN}" && command -v cargo >/dev/null 2>&1; then
    cargo build --release --manifest-path "${SCRIPT_DIR}/rust/Cargo.toml"
    mkdir -p "${SCRIPT_DIR}/plugin/bin"
    cp "${SCRIPT_DIR}/rust/target/release/carbon-stack.exe" "${CARBON_BIN}"
  fi
else
  CARBON_BIN="${SCRIPT_DIR}/plugin/bin/carbon-stack"
  if { [[ ! -x "${CARBON_BIN}" ]] || needs_rust_rebuild "${CARBON_BIN}"; } && command -v cargo >/dev/null 2>&1; then
    cargo build --release --manifest-path "${SCRIPT_DIR}/rust/Cargo.toml"
    mkdir -p "${SCRIPT_DIR}/plugin/bin"
    cp "${SCRIPT_DIR}/rust/target/release/carbon-stack" "${CARBON_BIN}"
    chmod +x "${CARBON_BIN}"
  fi
fi

exec "${CARBON_BIN}" install --repo-root "${SCRIPT_DIR}" "${FORWARD_ARGS[@]}"
