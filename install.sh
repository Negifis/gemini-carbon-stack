#!/usr/bin/env bash
# Cross-platform bootstrap wrapper for Gemini Carbon Engineering Stack.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
if ! command -v "${PYTHON_BIN}" >/dev/null 2>&1; then
  PYTHON_BIN="python"
fi

if [[ "${1:-}" == "--with-toolchains" ]]; then
  shift
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

exec "${PYTHON_BIN}" -X utf8 "${SCRIPT_DIR}/install.py" "$@"
