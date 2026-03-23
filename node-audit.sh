#!/usr/bin/env bash
# =============================================================================
# FINAL ENHANCED Bash History + Binaries + Logs + Firewall + Remediation Audit
# Compatible with: Debian Buster (10) and openSUSE Leap 15.6
# NEW IN THIS VERSION:
#   • VT API key prompt ONLY when suspicious binaries are found
#   • Double-check that key is not blank after paste
#   • New Systemd Services Audit (last 30 days) — flags created/removed units
#   • All previous features preserved (nftables, sshguard, history remediation, etc.)
# =============================================================================

set -o pipefail

# ----------------------------- Colors -----------------------------
RED='\033[1;31m'      # CRITICAL
ORANGE='\033[1;33m'   # HIGH
YELLOW='\033[0;33m'   # MEDIUM
GREEN='\033[0;32m'
RESET='\033[0m'

# ----------------------------- CONFIG -----------------------------
VT_API_KEY="${VT_API_KEY:-}"          # Only prompted later if binaries exist
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

# Journal patterns
J_CRIT_PATTERNS=(
    'Failed password for'
    'authentication failure'
    'PAM: Authentication failure'
    'Invalid user'
    'brute.force'
    'sshd.*disconnect.*preauth'
    'avc: denied'
)

J_HIGH_PATTERNS=(
    'sudo: .* : command not allowed'
    'sshd.*Accepted password for.*from'
)

# Systemd service change patterns
SYSTEMD_CRIT_PATTERNS=(
    'Created symlink.*\.service.*(tmp|dev/shm|backdoor|miner|c2|reverse)'
    'Unit .* from /tmp'
    'Unit .* from /dev/shm'
    'Changed on-disk state.*\.service'
)

SYSTEMD_HIGH_PATTERNS=(
    'Created symlink.*\.service'
    'Removed symlink.*\.service'
    'Unit .* (started|loaded|changed)'
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
        echo -e "${YELLOW}VT skipped (no key provided)${RESET}"
        return
    fi
    echo -e "${YELLOW}Querying VT for $file ...${RESET}"
    local resp
    resp=$(curl -s --max-time 15 -H "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/files/$hash" 2>/dev/null)
    if echo "$resp" | grep -q '"code":"NotFound"'; then
        echo -e "${YELLOW}Not analyzed on VT yet${RESET}"
        return
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

# ----------------------------- COUNTERS -----------------------------
declare -A COUNTS
COUNTS[CRITICAL]=0
COUNTS[HIGH]=0
COUNTS[MEDIUM]=0

# ----------------------------- Bash History Configuration Audit + Remediation -----------------------------
echo -e "\n${GREEN}=== Bash History Configuration Audit ===${RESET}"

DISABLE_FOUND=false
BAD_LINES=""
SEARCH_PATHS=("/etc/profile" "/etc/bash.bashrc")
if [[ $EUID -eq 0 ]]; then
    for uh in /root /home/*; do
        [[ -d "$uh" ]] && SEARCH_PATHS+=("$uh/.bashrc" "$uh/.profile")
    done
else
    SEARCH_PATHS+=("$HOME/.bashrc" "$HOME/.profile")
fi

for f in "${SEARCH_PATHS[@]}"; do
    [[ -f "$f" ]] || continue
    while IFS= read -r match; do
        [[ -n "$match" ]] && { BAD_LINES+="$f: $match\n"; DISABLE_FOUND=true; }
    done < <(grep -E 'HISTFILE=/dev/null|unset[[:space:]]+HISTFILE|HISTSIZE=0|HISTFILESIZE=0' "$f" 2>/dev/null)
done

if [[ $EUID -eq 0 ]]; then
    while IFS= read -r match; do
        [[ -n "$match" ]] && { BAD_LINES+="$match\n"; DISABLE_FOUND=true; }
    done < <(grep -r -E 'HISTFILE=/dev/null|unset[[:space:]]+HISTFILE|HISTSIZE=0|HISTFILESIZE=0' /etc/profile.d/ 2>/dev/null | grep -v history.sh)
fi

if [[ "$DISABLE_FOUND" == true ]]; then
    echo -e "${RED}[CRITICAL] Bash history is DISABLED!${RESET}"
    printf "%b" "$BAD_LINES" | sed 's/^/  /'
    ((COUNTS[CRITICAL]++))
else
    echo -e "${GREEN}✓ Bash history is NOT disabled${RESET}"
fi

# Create /etc/profile.d/history.sh if missing
if [[ $EUID -eq 0 ]]; then
    if [[ ! -f /etc/profile.d/history.sh ]]; then
        echo -e "${YELLOW}Creating /etc/profile.d/history.sh ...${RESET}"
        cat > /etc/profile.d/history.sh << 'EOF'
export HISTTIMEFORMAT="%F %T "
export HISTSIZE=100000
export HISTFILESIZE=200000
export HISTCONTROL=ignoredups
shopt -s histappend
PROMPT_COMMAND='history -a'
EOF
        chmod 644 /etc/profile.d/history.sh
        echo -e "${GREEN}✓ Created /etc/profile.d/history.sh${RESET}"
    else
        echo -e "${GREEN}✓ /etc/profile.d/history.sh already exists${RESET}"
    fi
else
    echo -e "${YELLOW}Not root — cannot create history.sh${RESET}"
fi

# ----------------------------- History Scan (30 days) -----------------------------
echo -e "\n${GREEN}=== Scanning Bash History (last 30 days) ===${RESET}"
HIST_FILES=()
if [[ $EUID -eq 0 ]]; then
    while IFS= read -r -d '' f; do HIST_FILES+=("$f"); done < <(find /root /home -name ".bash_history" -type f -print0 2>/dev/null)
else
    [[ -f "$HOME/.bash_history" ]] && HIST_FILES+=("$HOME/.bash_history")
fi

for hist in "${HIST_FILES[@]}"; do
    owner=$(stat -c '%U' "$hist" 2>/dev/null || echo "unknown")
    echo -e "\n${GREEN}=== ${hist} (owner: ${owner}) ===${RESET}"
    issues=0
    has_timestamps=false
    in_window=true
    while IFS= read -r line || [[ -n $line ]]; do
        if [[ "$line" =~ ^#([0-9]{9,10})$ ]]; then
            has_timestamps=true
            ts="${BASH_REMATCH[1]}"
            (( ts >= THIRTY_DAYS_AGO )) && in_window=true || in_window=false
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
        echo -e "${YELLOW}Note: No timestamps — full file scanned${RESET}"
    fi
    [[ $issues -eq 0 ]] && echo -e "${GREEN}✓ Clean${RESET}" || echo -e "${YELLOW}⚠ ${issues} issue(s)${RESET}"
done

# ----------------------------- Suspicious Binaries + VT (prompt only here) -----------------------------
echo -e "\n${GREEN}=== Scanning /tmp & /dev/shm for suspicious binaries + VirusTotal ===${RESET}"
mapfile -t suspicious < <(find /tmp /dev/shm -type f -executable -mtime -30 2>/dev/null)

if [[ ${#suspicious[@]} -eq 0 ]]; then
    echo -e "${GREEN}✓ No suspicious binaries found${RESET}"
else
    echo -e "${YELLOW}Found ${#suspicious[@]} suspicious binary(ies)${RESET}"

    # Secure VT key prompt ONLY if binaries exist and key is missing
    if [[ -z "$VT_API_KEY" ]]; then
        echo -e "\n${YELLOW}VirusTotal API key not set.${RESET}"
        echo -e "${ORANGE}WARNING: Never use 'export VT_API_KEY=...' (it appears in history!)${RESET}"
        read -rs -p "Paste your VT API key here (completely invisible): " VT_API_KEY
        echo ""
        if [[ -z "$VT_API_KEY" ]]; then
            echo -e "${YELLOW}No key provided — VT lookups will be skipped.${RESET}"
        else
            export VT_API_KEY
            echo -e "${GREEN}Key accepted securely (session only — never in history).${RESET}"
        fi
    fi

    # Now scan binaries
    for bin in "${suspicious[@]}"; do
        [[ ! -f "$bin" ]] && continue
        hash=$(sha256sum "$bin" 2>/dev/null | cut -d' ' -f1)
        echo -e "\n${ORANGE}Binary: $bin${RESET}"
        echo -e "Size: $(du -h "$bin" | cut -f1) | Owner: $(stat -c '%U' "$bin")"
        vt_lookup "$hash" "$bin"
    done
fi

# ----------------------------- nftables Firewall Review -----------------------------
echo -e "\n${GREEN}=== nftables Firewall Review ===${RESET}"
if command -v nft >/dev/null 2>&1; then
    RULES=$(nft list ruleset 2>/dev/null)
    if [[ -z "$RULES" ]]; then
        echo -e "${RED}[CRITICAL] nftables ruleset empty${RESET}"
        ((COUNTS[CRITICAL]++))
    elif echo "$RULES" | grep -qE 'chain (input|output|forward).*policy accept'; then
        echo -e "${ORANGE}[HIGH] nftables policy accept (insecure)${RESET}"
        ((COUNTS[HIGH]++))
    else
        echo -e "${GREEN}✓ nftables restrictive${RESET}"
    fi
else
    echo -e "${YELLOW}nft not installed${RESET}"
fi

# ----------------------------- sshguard & auditd Status -----------------------------
echo -e "\n${GREEN}=== sshguard & auditd Status ===${RESET}"
if command -v sshguard >/dev/null 2>&1; then
    echo -e "${GREEN}✓ sshguard installed${RESET}"
else
    echo -e "${ORANGE}⚠ sshguard NOT installed${RESET}"
fi
if systemctl is-active --quiet auditd 2>/dev/null || [[ -f /var/log/audit/audit.log ]]; then
    echo -e "${GREEN}✓ auditd active${RESET}"
else
    echo -e "${YELLOW}⚠ auditd not active${RESET}"
fi

# ----------------------------- Journalctl Audit (30 days) -----------------------------
echo -e "\n${GREEN}=== Journalctl + auditd + sshguard (last 30 days) ===${RESET}"
if command -v journalctl >/dev/null 2>&1; then
    LOG_ISSUES=0
    while IFS= read -r line || [[ -n $line ]]; do
        [[ -z "$line" ]] && continue
        if [[ "$line" == *blocking*0*addresses* ]]; then continue; fi
        severity="NONE"
        for pat in "${J_CRIT_PATTERNS[@]}"; do [[ $line =~ $pat ]] && { severity="CRITICAL"; break; }; done
        if [[ "$severity" == "NONE" ]]; then
            for pat in "${J_HIGH_PATTERNS[@]}"; do [[ $line =~ $pat ]] && { severity="HIGH"; break; }; done
        fi
        if [[ "$severity" != "NONE" ]]; then
            color=$(get_color "$severity")
            echo -e "${color}[${severity} JOURNAL] ${line:0:140}${RESET}"
            ((COUNTS[$severity]++))
            ((LOG_ISSUES++))
        fi
    done < <(journalctl --since "30 days ago" -u ssh -u sshd -u sudo -u systemd-logind -u auditd -u sshguard --no-pager 2>/dev/null \
             | grep -Ei 'Failed|authentication|invalid|brute|sudo|sshd|denied|AVC|sshguard|blocked')
    if [[ $LOG_ISSUES -eq 0 ]]; then
        echo -e "${GREEN}✓ No security events${RESET}"
    else
        echo -e "${YELLOW}⚠ ${LOG_ISSUES} events flagged${RESET}"
    fi
else
    echo -e "${YELLOW}journalctl unavailable${RESET}"
fi

# ----------------------------- NEW: Systemd Services Audit (last 30 days) -----------------------------
echo -e "\n${GREEN}=== Systemd Services Audit (created/removed units — last 30 days) ===${RESET}"
if command -v journalctl >/dev/null 2>&1; then
    SYS_ISSUES=0
    while IFS= read -r line || [[ -n $line ]]; do
        [[ -z "$line" ]] && continue
        severity="NONE"
        for pat in "${SYSTEMD_CRIT_PATTERNS[@]}"; do
            [[ $line =~ $pat ]] && { severity="CRITICAL"; break; }
        done
        if [[ "$severity" == "NONE" ]]; then
            for pat in "${SYSTEMD_HIGH_PATTERNS[@]}"; do
                [[ $line =~ $pat ]] && { severity="HIGH"; break; }
            done
        fi
        if [[ "$severity" != "NONE" ]]; then
            color=$(get_color "$severity")
            echo -e "${color}[${severity} SYSTEMD] ${line:0:140}${RESET}"
            ((COUNTS[$severity]++))
            ((SYS_ISSUES++))
        fi
    done < <(journalctl --since "30 days ago" --no-pager -u systemd* 2>/dev/null \
             | grep -E 'Created symlink|Removed symlink|Unit .* (started|loaded|changed|from /tmp|from /dev/shm)')

    if [[ $SYS_ISSUES -eq 0 ]]; then
        echo -e "${GREEN}✓ No suspicious service changes${RESET}"
    else
        echo -e "${YELLOW}⚠ ${SYS_ISSUES} service change(s) flagged${RESET}"
    fi
else
    echo -e "${YELLOW}journalctl unavailable${RESET}"
fi

# ----------------------------- FINAL SUMMARY -----------------------------
echo -e "\n${GREEN}=== FINAL AUDIT SUMMARY (30-day window) ===${RESET}"
echo -e "CRITICAL : ${RED}${COUNTS[CRITICAL]}${RESET}"
echo -e "HIGH     : ${ORANGE}${COUNTS[HIGH]}${RESET}"
echo -e "MEDIUM   : ${YELLOW}${COUNTS[MEDIUM]}${RESET}"

if [[ ${COUNTS[CRITICAL]} -gt 0 ]]; then
    echo -e "${RED}CRITICAL ISSUES FOUND — ACT NOW${RESET}"
elif [[ ${COUNTS[HIGH]} -gt 0 ]]; then
    echo -e "${ORANGE}High-severity issues${RESET}"
else
    echo -e "${GREEN}All clear${RESET}"
fi

echo -e "\n${YELLOW}Notes:${RESET}"
echo -e "• VT key is ONLY asked if suspicious binaries are found"
echo -e "• Key never saved to history (invisible prompt + double-checked for blank)"
echo -e "• Systemd audit flags newly created/removed services (especially suspicious ones)"
echo -e "• Run as root for full coverage"

exit 0
