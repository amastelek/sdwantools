#!/usr/bin/env bash
# =============================================================================
# audit_bash_history.sh
# Reads bash history, sends it to the Claude API, and reports on potential
# cybersecurity risks found in the command history.
#
# Supports: openSUSE Leap 15.6 and Debian Buster (10)
#
# Usage:
#   ** IMPORTANT: Do NOT export your API key directly in the terminal — it will
#   ** appear in bash history and be flagged as a CRITICAL finding by this script.
#   ** Instead, set it securely with:
#
#      read -rs ANTHROPIC_API_KEY && export ANTHROPIC_API_KEY
#      (paste your key and press Enter — silent, no echo, nothing recorded in history)
#
#   bash audit_bash_history.sh [--user <username>] [--history-file <path>]
#
# Options:
#   --user <username>       Audit the history for a specific user
#                           (defaults to the current user; requires root for other users)
#   --history-file <path>   Explicitly supply a history file path
#   --all-users             Audit bash history for ALL users on the system (requires root)
#   --output <file>         Write the report to a file as well as stdout
#   --model <model>         Claude model to use (default: claude-sonnet-4-20250514)
#   --max-lines <n>         Max history lines to send per user (default: 500)
#   --help                  Show this help message
# =============================================================================

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
MODEL="claude-sonnet-4-20250514"
MAX_LINES=500
TARGET_USER=""
HISTORY_FILE=""
ALL_USERS=false
OUTPUT_FILE=""
API_URL="https://api.anthropic.com/v1/messages"

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ── Helpers ───────────────────────────────────────────────────────────────────
log()   { echo -e "${CYAN}[INFO]${RESET}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${RESET}  $*" >&2; }
error() { echo -e "${RED}[ERROR]${RESET} $*" >&2; exit 1; }

usage() {
  sed -n '/^# Usage:/,/^# =\+/p' "$0" | sed 's/^# \?//'
  exit 0
}

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --user)         TARGET_USER="$2";  shift 2 ;;
    --history-file) HISTORY_FILE="$2"; shift 2 ;;
    --all-users)    ALL_USERS=true;    shift   ;;
    --output)       OUTPUT_FILE="$2";  shift 2 ;;
    --model)        MODEL="$2";        shift 2 ;;
    --max-lines)    MAX_LINES="$2";    shift 2 ;;
    --help|-h)      usage ;;
    *) warn "Unknown option: $1"; shift ;;
  esac
done

# ── Pre-flight checks ─────────────────────────────────────────────────────────
command -v curl  >/dev/null 2>&1 || error "curl is required but not installed."
command -v jq    >/dev/null 2>&1 || error "jq is required but not installed.  Install with: apt-get install jq  OR  zypper install jq"

if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
  echo -e "${YELLOW}[WARN]${RESET}  ANTHROPIC_API_KEY is not set."
  echo -e "${YELLOW}[WARN]${RESET}  Do NOT use 'export ANTHROPIC_API_KEY=...' — it will appear in bash"
  echo -e "${YELLOW}[WARN]${RESET}  history and be flagged as a CRITICAL finding by this very script."
  echo ""
  echo -e "${CYAN}[INFO]${RESET}  Set it securely now using the silent prompt below."
  echo -e "${CYAN}[INFO]${RESET}  Paste your key and press Enter (nothing is echoed or recorded):"
  echo ""
  read -rs ANTHROPIC_API_KEY
  export ANTHROPIC_API_KEY
  echo ""
  [[ -z "${ANTHROPIC_API_KEY:-}" ]] && error "No API key entered. Exiting."
  log "API key accepted securely."
fi

# ── Detect distro ─────────────────────────────────────────────────────────────
detect_distro() {
  if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    source /etc/os-release
    echo "${ID:-unknown} ${VERSION_ID:-}"
  else
    echo "unknown"
  fi
}

DISTRO=$(detect_distro)
log "Detected OS: ${DISTRO}"

case "$DISTRO" in
  *opensuse*|*sles*) DISTRO_LABEL="openSUSE/SLES" ;;
  *debian*)          DISTRO_LABEL="Debian"         ;;
  *)                 DISTRO_LABEL="Unknown (continuing anyway)" ;;
esac
log "Distribution label: ${DISTRO_LABEL}"

# ── Collect history files ─────────────────────────────────────────────────────
declare -A USER_HISTORY_MAP   # username -> history file path

collect_for_user() {
  local uname="$1"
  local homedir

  homedir=$(getent passwd "$uname" | cut -d: -f6 2>/dev/null || echo "")
  if [[ -z "$homedir" ]]; then
    warn "Cannot determine home directory for user: $uname"
    return
  fi

  local hfile="${homedir}/.bash_history"
  if [[ -f "$hfile" && -r "$hfile" ]]; then
    USER_HISTORY_MAP["$uname"]="$hfile"
  else
    warn "No readable .bash_history found for user '$uname' at $hfile"
  fi
}

if [[ -n "$HISTORY_FILE" ]]; then
  # Explicit file supplied – use a synthetic username
  [[ -f "$HISTORY_FILE" && -r "$HISTORY_FILE" ]] || error "Cannot read history file: $HISTORY_FILE"
  USER_HISTORY_MAP["custom"]="$HISTORY_FILE"

elif $ALL_USERS; then
  [[ $EUID -ne 0 ]] && error "--all-users requires root privileges."
  while IFS=: read -r uname _ uid _ _ homedir _; do
    # Skip system accounts (UID < 1000) and nologin/false shells
    shell=$(getent passwd "$uname" | cut -d: -f7)
    [[ "$shell" == */nologin || "$shell" == */false ]] && continue
    (( uid < 1000 )) && continue
    collect_for_user "$uname"
  done < /etc/passwd

elif [[ -n "$TARGET_USER" ]]; then
  collect_for_user "$TARGET_USER"

else

  # Default: current user
  collect_for_user "$(whoami)"
fi

[[ ${#USER_HISTORY_MAP[@]} -eq 0 ]] && error "No bash history files found to audit."

# ── Claude API call ───────────────────────────────────────────────────────────
call_claude() {
  local username="$1"
  local history_content="$2"

  local prompt
  prompt=$(cat <<PROMPT
You are a cybersecurity analyst performing a defensive security audit.

Below is the bash command history extracted from a Linux system for user "${username}".
Your task is to analyse each command and identify any entries that represent potential
cybersecurity risks, misconfigurations, or signs of suspicious/malicious activity.

For each finding, provide:
1. SEVERITY  : CRITICAL | HIGH | MEDIUM | LOW | INFO
2. COMMAND   : The exact command (or summary if very long)
3. RISK      : A concise explanation of why this is risky
4. CATEGORY  : e.g. Credential Exposure, Privilege Escalation, Lateral Movement,
               Data Exfiltration, Reconnaissance, Malware/Persistence, Misconfiguration, etc.
4. RECOMMENDATION: What should be done to remediate or investigate

If no issues are found, state that clearly.

Finish with an OVERALL RISK SUMMARY including a risk score from 0 (no risk) to 10 (critical).

--- BASH HISTORY START ---
${history_content}
--- BASH HISTORY END ---
PROMPT
)

  local payload
  payload=$(jq -n \
    --arg model   "$MODEL" \
    --arg content "$prompt" \
    '{
       model:      $model,
       max_tokens: 2048,
       messages: [{ role: "user", content: $content }]
     }')

  local response
  response=$(curl -s -X POST "$API_URL" \
    -H "Content-Type: application/json" \
    -H "x-api-key: ${ANTHROPIC_API_KEY}" \
    -H "anthropic-version: 2023-06-01" \
    -d "$payload")

  # Check for API-level errors
  local api_error
  api_error=$(echo "$response" | jq -r '.error.message // empty' 2>/dev/null || true)
  [[ -n "$api_error" ]] && error "Claude API error: ${api_error}"

  echo "$response" | jq -r '.content[0].text // "No response text returned."'
}

# ── Report helpers ────────────────────────────────────────────────────────────
REPORT_LINES=()

rprint() {
  REPORT_LINES+=("$1")
  echo -e "$1"
}

write_report() {
  if [[ -n "$OUTPUT_FILE" ]]; then
    # Strip ANSI colour codes for the file
    printf '%s\n' "${REPORT_LINES[@]}" | sed 's/\x1b\[[0-9;]*m//g' > "$OUTPUT_FILE"
    log "Report written to: ${OUTPUT_FILE}"
  fi
}

# ── Main audit loop ───────────────────────────────────────────────────────────
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S %Z')
HOSTNAME=$(hostname -f 2>/dev/null || hostname)

rprint ""
rprint "${BOLD}╔══════════════════════════════════════════════════════════════╗${RESET}"
rprint "${BOLD}║        BASH HISTORY CYBERSECURITY AUDIT REPORT              ║${RESET}"
rprint "${BOLD}╚══════════════════════════════════════════════════════════════╝${RESET}"
rprint "  Host      : ${HOSTNAME}"
rprint "  OS        : ${DISTRO_LABEL}"
rprint "  Timestamp : ${TIMESTAMP}"
rprint "  Model     : ${MODEL}"
rprint ""

for uname in "${!USER_HISTORY_MAP[@]}"; do
  hfile="${USER_HISTORY_MAP[$uname]}"

  rprint "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  rprint "${BOLD}  User: ${uname}   |   File: ${hfile}${RESET}"
  rprint "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

  # Read, deduplicate blank lines, and truncate
  HISTORY_CONTENT=$(grep -v '^\s*$' "$hfile" | tail -n "$MAX_LINES")
  LINE_COUNT=$(echo "$HISTORY_CONTENT" | wc -l)
  TOTAL_LINES=$(wc -l < "$hfile")

  rprint "  Lines in file : ${TOTAL_LINES}"
  rprint "  Lines sent    : ${LINE_COUNT}  (last ${MAX_LINES} non-empty)"
  rprint ""

  if [[ -z "$HISTORY_CONTENT" ]]; then
    rprint "${YELLOW}  History file is empty – skipping.${RESET}"
    continue
  fi

  log "Sending history for '${uname}' to Claude API..."
  ANALYSIS=$(call_claude "$uname" "$HISTORY_CONTENT")

  rprint "$ANALYSIS"
  rprint ""
done

rprint "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
rprint "${GREEN}  Audit complete.${RESET}"
rprint "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

write_report
