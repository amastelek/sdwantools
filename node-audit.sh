#!/usr/bin/env bash
# =============================================================================
# UPDATED Bash History + Binaries + Journalctl + auditd/sshguard Audit Script
# Compatible with: Debian Buster (10) and openSUSE Leap 15.6
# CHANGES IN THIS VERSION:
#   • History & journalctl now default to LAST 30 DAYS (timestamp-aware for history)
#   • Full auditd and sshguard log integration (via journalctl)
#   • Reports if sshguard is NOT installed (and recommends it)
#   • Secure VT key prompt (unchanged)
# =============================================================================

set -o pipefail

# ----------------------------- Colors -----------------------------
RED='\033[1;31m'      # CRITICAL
ORANGE='\033[1;33m'   # HIGH
YELLOW='\033[0;33m'   # MEDIUM
GREEN='\033[0;32m'
RESET='\033[0m'

# ----------------------------- CONFIG -----------------------------
VT_API_KEY="${VT_API_KEY:-}"

# 30-day window (used for history timestamps + journalctl)
THIRTY_DAYS_AGO=$(date -d "30 days ago" +%s 2>/dev/null || echo 0)

# ----------------------------- PATTERNS -----------------------------
CRITICAL_PATTERNS=(
    # Reverse shells
    'bash[[:space:]]+-i[[:space:]]+>&[[:space:]]*/dev/tcp/'
    '/dev/tcp/[0-9]{1,3}\.'
    'nc[[:space:]]+(-e|--exec)[[:space:]]+/bin/(sh|bash)'
    'nc[[:space:]]+-l[[:space:]]+(-p|--listen)'
    'mkfifo[[:space:]]'
    'socat[[:space:]].*(TCP|OPENSSL)'
    'openssl[[:space:]]+s_client'
    'perl[[:space:]]+-e.*(socket|IO::Socket)'
    'ruby[[:space:]]+-e.*(TCPSocket|socket)'
    'php[[:space:]]+-r.*fsockopen'
    'python[[:space:]]+-c.*(socket|subprocess).*shell'

    # Credential leaks
    '--password=[^[:space:]]+'
    'token=[^[:space:]]+'
    'apikey=[^[:space:]]+'
    'AKIA[A-Z0-9]{16}'
    'AIza[0-9A-Za-z_-]{35}'

    # Tampering
    'history[[:space:]]+-c'
    'rm[[:space:]]+(-f|--force|-rf)[[:space:]]+.*\.bash_history'
    'unset[[:space:]]+HISTFILE'
    'export[[:space:]]+HISTFILE=/dev/null'
    'HISTSIZE=0'
    'HISTFILESIZE=0'
    'HISTCONTROL=(ignorespace|ignoreboth)'
    'rm[[:space:]]+-rf[[:space:]]+(/|/\*)'
)

HIGH_PATTERNS=(
    'cat[[:space:]]+/etc/shadow'
    'cat[[:space:]]+.*id_rsa'
    'cat[[:space:]]+.*authorized_keys'
    'echo[[:space:]].*(password|passwd|secret).*\|'
)

MEDIUM_PATTERNS=(
    'wget[[:space:]]+https?://'
    'curl[[:space:]]+https?://'
    'curl[[:space:]].*(--insecure|-k)'
    'chmod[[:space:]]+777'
    'nmap[[:space:]]'
    'sudo[[:space:]]+-l'
)

# Journal/auditd/sshguard patterns (30-day window)
J_CRIT_PATTERNS=(
    'Failed password for'
    'authentication failure'
    'PAM: Authentication failure'
    'Invalid user'
    'brute.force'
    'sshd.*disconnect.*preauth'
    'avc: denied'          # auditd SELinux denials
    'sshguard.*(block|blocked)'
)

J_HIGH_PATTERNS=(
    'sudo: .* : command not allowed'
    'sshd.*Accepted password for.*from'
)

# ----------------------------- Functions -----------------------------
get_severity() {
    local cmd="$1"
    for pat in "${CRITICAL_PATTERNS[@]}"; do [[ $cmd =~ $pat ]] && { echo "CRITICAL"; return; }; done
    for pat in "${HIGH_PATTERNS[@]}";     do [[ $cmd =~ $pat ]] && { echo "HIGH"; return; }; done
    for pat in "${MEDIUM_PATTERNS[@]}";   do [[ $cmd =~ $pat ]] && { echo "MEDIUM"; return; }; done
    echo "NONE"
}

get_color() {
    case "$1" in
        CRITICAL) echo -e "$RED" ;;
        HIGH)     echo -e "$ORANGE" ;;
        MEDIUM)   echo -e "$YELLOW" ;;
        *)        echo -e "$RESET" ;;
    esac
}

vt_lookup() {
    local hash="$1" file="$2"
    if [[ -z "$VT_API_KEY" ]]; then
        echo -e "${YELLOW}VT skipped (no key)${RESET}"
        return
    fi
    echo -e "${YELLOW}Querying VT for $file ...${RESET}"
    local resp
    resp=$(curl -s --max-time 15 -H "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/files/$hash" 2>/dev/null)
    if echo "$resp" | grep -q '"code":"NotFound"'; then
        echo -e "${YELLOW}Not analyzed on VT yet${RESET}"; return
    fi
    local malicious=0
    if command -v jq >/dev/null 2>&1; then
        malicious=$(echo "$resp" | jq -r '.data.attributes.last_analysis_stats.malicious // 0' 2>/dev/null || echo 0)
    else
        malicious=$(echo "$resp" | grep -o '"malicious":[[:space:]]*[0-9]*' | grep -o '[0-9]*' || echo 0)
    fi
    if [[ "$malicious" -gt 0 ]]; then
        echo -e "${RED}CRITICAL VT HIT → $malicious engines flagged $file${RESET}"
    else
        echo -e "${GREEN}Clean on VT${RESET}"
    fi
    sleep 15
}

# ----------------------------- SECURE VirusTotal Key Prompt -----------------------------
if [[ -z "$VT_API_KEY" ]]; then
    echo -e "\n${YELLOW}VirusTotal API key not set.${RESET}"
    echo -e "${ORANGE}WARNING: Do NOT use 'export VT_API_KEY=...' — it WILL appear in .bash_history!${RESET}"
    read -rs -p "Paste your VirusTotal API key here (completely invisible): " VT_API_KEY
    echo ""
    if [[ -z "$VT_API_KEY" ]]; then
        echo -e "${YELLOW}No key provided — VT lookups will be skipped.${RESET}"
    else
        export VT_API_KEY
        echo -e "${GREEN}Key accepted securely (session only).${RESET}"
    fi
else
    echo -e "${GREEN}Using existing VT_API_KEY (session only).${RESET}"
fi

# ----------------------------- History Scan (LAST 30 DAYS when timestamps exist) -----------------------------
echo -e "\n${GREEN}=== Scanning Bash History (last 30 days where timestamps are present) ===${RESET}"

HIST_FILES=()
if [[ $EUID -eq 0 ]]; then
    while IFS= read -r -d '' file; do HIST_FILES+=("$file"); done < <(find /root /home -name ".bash_history" -type f 2>/dev/null -print0)
else
    [[ -f "$HOME/.bash_history" ]] && HIST_FILES+=("$HOME/.bash_history")
fi

declare -A COUNTS
COUNTS[CRITICAL]=0 COUNTS[HIGH]=0 COUNTS[MEDIUM]=0

for hist in "${HIST_FILES[@]}"; do
    owner=$(stat -c '%U' "$hist" 2>/dev/null || echo "unknown")
    echo -e "\n${GREEN}=== Auditing ${hist} (owner: ${owner}) ===${RESET}"

    issues=0
    has_timestamps=false
    in_window=true
    while IFS= read -r line || [[ -n $line ]]; do
        if [[ "$line" =~ ^#([0-9]{9,10})$ ]]; then
            has_timestamps=true
            ts="${BASH_REMATCH[1]}"
            if (( ts < THIRTY_DAYS_AGO )); then
                in_window=false
            else
                in_window=true
            fi
            continue
        fi

        [[ -z "$line" ]] && continue
        if [[ "$in_window" == true ]]; then
            severity=$(get_severity "$line")
            if [[ "$severity" != "NONE" ]]; then
                color=$(get_color "$severity")
                echo -e "${color}[${severity}] ${line}${RESET}"
                ((COUNTS[$severity]++))
                ((issues++))
            fi
        fi
    done < "$hist"

    if [[ "$has_timestamps" == false ]]; then
        echo -e "${YELLOW}Note: No timestamps in this history file — entire file was scanned.${RESET}"
        echo -e "${YELLOW}      (Tip: add 'export HISTTIMEFORMAT=\"%F %T \"' to ~/.bashrc for future 30-day filtering)${RESET}"
    fi

    [[ $issues -eq 0 ]] && echo -e "${GREEN}✓ Clean${RESET}" || echo -e "${YELLOW}⚠ ${issues} issue(s)${RESET}"
done

# ----------------------------- Suspicious Binaries + VT -----------------------------
echo -e "\n${GREEN}=== Scanning /tmp and /dev/shm for suspicious binaries + VirusTotal ===${RESET}"
mapfile -t suspicious < <(find /tmp /dev/shm -type f -executable -mtime -30 2>/dev/null)
if [[ ${#suspicious[@]} -eq 0 ]]; then
    echo -e "${GREEN}✓ No suspicious binaries found${RESET}"
else
    for bin in "${suspicious[@]}"; do
        [[ ! -f "$bin" ]] && continue
        hash=$(sha256sum "$bin" 2>/dev/null | cut -d' ' -f1)
        echo -e "\n${ORANGE}Binary: $bin${RESET}"
        echo -e "Size: $(du -h "$bin" | cut -f1) | Owner: $(stat -c '%U' "$bin")"
        vt_lookup "$hash" "$bin"
    done
fi

# ----------------------------- sshguard & auditd Status Check -----------------------------
echo -e "\n${GREEN}=== sshguard & auditd Status Check ===${RESET}"
if command -v sshguard >/dev/null 2>&1; then
    echo -e "${GREEN}✓ sshguard is installed and available${RESET}"
else
    echo -e "${ORANGE}⚠ sshguard is NOT installed${RESET}"
    echo -e "${YELLOW}   Recommendation: apt install sshguard  (Debian) or zypper install sshguard (openSUSE)${RESET}"
fi

if systemctl is-active --quiet auditd 2>/dev/null || [[ -f /var/log/audit/audit.log ]]; then
    echo -e "${GREEN}✓ auditd logging is active${RESET}"
else
    echo -e "${YELLOW}⚠ auditd not detected — some privileged events may be missing${RESET}"
fi

# ----------------------------- Journalctl Security Audit (LAST 30 DAYS) -----------------------------
echo -e "\n${GREEN}=== Journalctl + auditd + sshguard Security Audit (last 30 days) ===${RESET}"
if command -v journalctl >/dev/null 2>&1; then
    LOG_ISSUES=0
    while IFS= read -r line || [[ -n $line ]]; do
        [[ -z "$line" ]] && continue
        severity="NONE"
        for pat in "${J_CRIT_PATTERNS[@]}"; do
            [[ $line =~ $pat ]] && { severity="CRITICAL"; break; }
        done
        if [[ "$severity" == "NONE" ]]; then
            for pat in "${J_HIGH_PATTERNS[@]}"; do
                [[ $line =~ $pat ]] && { severity="HIGH"; break; }
            done
        fi
        if [[ "$severity" != "NONE" ]]; then
            color=$(get_color "$severity")
            echo -e "${color}[${severity} JOURNAL] ${line:0:140}${RESET}"
            ((COUNTS[$severity]++))
            ((LOG_ISSUES++))
        fi
    done < <(journalctl --since "30 days ago" \
             -u ssh -u sshd -u sudo -u systemd-logind -u auditd -u sshguard \
             --no-pager 2>/dev/null | grep -Ei 'Failed|authentication|invalid|brute|sudo|sshd|denied|AVC|sshguard|blocked')

    if [[ $LOG_ISSUES -eq 0 ]]; then
        echo -e "${GREEN}✓ No security events flagged in the last 30 days${RESET}"
    else
        echo -e "${YELLOW}⚠ ${LOG_ISSUES} security events flagged${RESET}"
    fi
else
    echo -e "${YELLOW}journalctl not available — skipping.${RESET}"
fi

# ----------------------------- FINAL SUMMARY -----------------------------
echo -e "\n${GREEN}=== FINAL AUDIT SUMMARY (30-day window) ===${RESET}"
echo -e "CRITICAL : ${RED}${COUNTS[CRITICAL]}${RESET}"
echo -e "HIGH     : ${ORANGE}${COUNTS[HIGH]}${RESET}"
echo -e "MEDIUM   : ${YELLOW}${COUNTS[MEDIUM]}${RESET}"

if [[ ${COUNTS[CRITICAL]} -gt 0 ]]; then
    echo -e "${RED}CRITICAL ISSUES DETECTED — IMMEDIATE ACTION REQUIRED!${RESET}"
elif [[ ${COUNTS[HIGH]} -gt 0 ]]; then
    echo -e "${ORANGE}High-severity issues found.${RESET}"
else
    echo -e "${GREEN}No critical or high-severity issues found.${RESET}"
fi

echo -e "\n${YELLOW}Notes:${RESET}"
echo "• Bash history filtered to last 30 days ONLY when timestamps are present."
echo "• Journalctl, auditd and sshguard logs limited to last 30 days."
echo "• VT key entered securely — never saved to history."
echo "• Install jq for prettier VT output and consider enabling HISTTIMEFORMAT."

exit 0
