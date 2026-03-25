#!/usr/bin/env bash
# =============================================================================
# Enhanced Security Audit Script
# Compatible with: Debian Buster (10)+ and openSUSE Leap 15.6
#
# Usage: sudo bash node-audit.sh [--no-remediate]
#
# --no-remediate   Audit-only mode: no files will be created or modified.
#                  Safe for scheduled/automated runs on production systems.
#
# Dependencies (optional but recommended):
#   jq          — richer KEV hit details          (apt/zypper install jq)
#   debsecan    — version-aware CVE scan (Debian)  (apt install debsecan)
#
# Output: all output is tee'd to /var/log/node-audit-YYYYMMDD-HHMMSS.log
# =============================================================================

set -o pipefail

# Require Bash 4+
if [[ ${BASH_VERSINFO[0]} -lt 4 ]]; then
    echo "ERROR: This script requires Bash 4 or higher (running ${BASH_VERSION})" >&2
    exit 1
fi

# ----------------------------- Flags -----------------------------
NO_REMEDIATE=false
for arg in "$@"; do
    [[ "$arg" == "--no-remediate" ]] && NO_REMEDIATE=true
done

# ----------------------------- Logging ---------------------------
# Tee all output to a dated log file if running as root
LOG_FILE=""
if [[ $EUID -eq 0 ]]; then
    LOG_FILE="/var/log/node-audit-$(date +%Y%m%d-%H%M%S).log"
    exec > >(tee -a "$LOG_FILE") 2>&1
    echo "# Audit log: $LOG_FILE"
fi

# ----------------------------- Colors ----------------------------
RED='\033[1;31m'      # CRITICAL
ORANGE='\033[1;33m'   # HIGH
YELLOW='\033[0;33m'   # MEDIUM
GREEN='\033[0;32m'
CYAN='\033[0;36m'     # LOW / Risk Accepted / Under Investigation
RESET='\033[0m'

# ----------------------------- Config ----------------------------
VT_API_KEY="${VT_API_KEY:-}"

# GNU date required for -d; detect early and warn rather than silently break
THIRTY_DAYS_AGO=$(date -d "30 days ago" +%s 2>/dev/null)
if [[ -z "$THIRTY_DAYS_AGO" ]]; then
    echo -e "${YELLOW}WARNING: 'date -d' not supported — timestamp filtering disabled; full history files will be scanned${RESET}"
    THIRTY_DAYS_AGO=0
    TIMESTAMP_FILTER=false
else
    TIMESTAMP_FILTER=true
fi

# Script's own PID — used to exclude self from process scan
SELF_PID=$$

# ----------------------------- Patterns --------------------------

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
    'python[23]?[[:space:]]+-c.*(socket|subprocess).*shell'
    # Encoded payload execution
    'base64[[:space:]]+-d.*\|[[:space:]]*(bash|sh|python|perl)'
    '(curl|wget)[[:space:]].*\|[[:space:]]*(bash|sh)'
    # Credential exposure
    '--password=[^[:space:]]+'
    'token=[^[:space:]]+'
    'apikey=[^[:space:]]+'
    'AKIA[A-Z0-9]{16}'
    'AIza[0-9A-Za-z_-]{35}'
    # Active history tampering
    'history[[:space:]]+-[cw]'
    'history[[:space:]].*>/dev/null'
    # SUID setting
    'chmod[[:space:]].*\+s'
    # Cron tampering
    'crontab[[:space:]]+-[re]'
    '(echo|printf).*>>.*/etc/cron'
    # Disk operations
    'dd[[:space:]].*if=/dev/(sd|nvme|vd|hd)'
)

HIGH_PATTERNS=(
    'cat[[:space:]]+/etc/shadow'
    'cat[[:space:]]+.*id_rsa'
    'cat[[:space:]]+.*authorized_keys'
    'echo[[:space:]].*(password|passwd|secret).*\|'
    # Recon
    'find[[:space:]]+/.*-perm[[:space:]]+-[246]000'
    'find[[:space:]]+/.*-nouser'
)

MEDIUM_PATTERNS=(
    'wget[[:space:]]+https?://'
    'curl[[:space:]]+https?://'
    'curl[[:space:]].*(--insecure|-k)'
    'nmap[[:space:]]'
    'sudo[[:space:]]+-l'
    # Outbound scans / tunnelling
    'ssh[[:space:]]+-[NLRfD]'
    'tcpdump[[:space:]]'
    'wireshark[[:space:]]'
)

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

SUSPICIOUS_PROC_REGEX='nc|ncat|socat|bash -i|python.*socket|perl.*socket|xmrig|minerd|linpeas|pspy|linux-exploit-suggester|dirtycow|cowroot'

# sysctl keys that should be set to specific values for security hardening
# Format: "key expected_value description"
SYSCTL_CHECKS=(
    "kernel.dmesg_restrict 1 Restrict dmesg to root"
    "kernel.kptr_restrict 1 Hide kernel pointers"
    "kernel.randomize_va_space 2 Full ASLR"
    "net.ipv4.conf.all.rp_filter 1 Reverse path filtering"
    "net.ipv4.tcp_syncookies 1 SYN flood protection"
    "net.ipv4.conf.all.accept_redirects 0 Reject ICMP redirects"
    "net.ipv4.conf.all.send_redirects 0 No ICMP redirects sent"
    "net.ipv4.conf.all.accept_source_route 0 Reject source-routed packets"
    "fs.protected_hardlinks 1 Protect hardlinks"
    "fs.protected_symlinks 1 Protect symlinks"
)

# ----------------------------- Functions -------------------------

get_severity() {
    local cmd="$1"
    for pat in "${CRITICAL_PATTERNS[@]}"; do [[ $cmd =~ $pat ]] && { echo "CRITICAL"; return; }; done
    for pat in "${HIGH_PATTERNS[@]}";     do [[ $cmd =~ $pat ]] && { echo "HIGH";     return; }; done
    for pat in "${MEDIUM_PATTERNS[@]}";   do [[ $cmd =~ $pat ]] && { echo "MEDIUM";   return; }; done
    echo "NONE"
}

color_for() {
    case "$1" in
        CRITICAL)              printf '%s' "$RED"    ;;
        HIGH)                  printf '%s' "$ORANGE" ;;
        MEDIUM)                printf '%s' "$YELLOW" ;;
        LOW)                   printf '%s' "$CYAN"   ;;
        "Risk Accepted")       printf '%s' "$CYAN"   ;;
        "Under Investigation") printf '%s' "$CYAN"   ;;
        *)                     printf '%s' "$RESET"  ;;
    esac
}

print_finding() {
    # print_finding SEVERITY "message"
    # CRITICAL and HIGH are accumulated for end-of-run risk register triage.
    # LOW is displayed in cyan and never counted or accumulated.
    local sev="$1" msg="$2"
    local col; col=$(color_for "$sev")
    local fp status comment disp_col label

    if [[ "$sev" == "CRITICAL" || "$sev" == "HIGH" ]]; then
        FINDINGS_THIS_RUN+=("${sev}|${msg}")
        fp=$(fingerprint "$sev" "$msg")
        status=$(register_lookup "$fp" status)
        comment=$(register_lookup "$fp" comment)

        if [[ -n "$status" && "$status" != "Unreviewed" ]]; then
            case "$status" in
                "Risk Accepted")       label="RISK ACCEPTED"; disp_col="$CYAN"  ;;
                "Under Investigation") label="INVESTIGATING";  disp_col="$CYAN"  ;;
                "Remediated")          label="REMEDIATED";     disp_col="$GREEN" ;;
                *)                     label="$status";        disp_col="$col"   ;;
            esac
            echo -e "${disp_col}[${sev} → ${label}] ${msg}${RESET}"
            [[ -n "$comment" ]] && echo -e "  ${disp_col}↳ ${comment}${RESET}"
        else
            echo -e "${col}[${sev}] ${msg}${RESET}"
        fi
    else
        echo -e "${col}[${sev}] ${msg}${RESET}"
    fi

    # LOW is informational only — no counter increment, no accumulation
    [[ "$sev" != "LOW" ]] && ((COUNTS[$sev]++))
}

vt_lookup() {
    local hash="$1" file="$2"
    if [[ -z "$VT_API_KEY" ]]; then
        echo -e "${YELLOW}  VT skipped (no key)${RESET}"
        return
    fi
    echo -e "${YELLOW}  Querying VirusTotal for $(basename "$file") ...${RESET}"
    local resp
    resp=$(curl -s --max-time 15 \
        -H "x-apikey: $VT_API_KEY" \
        "https://www.virustotal.com/api/v3/files/$hash" 2>/dev/null)
    if echo "$resp" | grep -q '"code":"NotFound"'; then
        echo -e "${YELLOW}  Not yet analysed on VirusTotal${RESET}"
        return
    fi
    local malicious=0
    if command -v jq >/dev/null 2>&1; then
        malicious=$(echo "$resp" | jq -r '.data.attributes.last_analysis_stats.malicious // 0' 2>/dev/null || echo 0)
    else
        malicious=$(echo "$resp" | grep -o '"malicious":[[:space:]]*[0-9]*' | grep -o '[0-9]*' | head -1 || echo 0)
    fi
    if [[ "$malicious" -gt 0 ]]; then
        print_finding "CRITICAL" "VirusTotal: $malicious engine(s) flagged $(basename "$file")"
    else
        echo -e "${GREEN}  Clean on VirusTotal${RESET}"
    fi
    sleep 15
}

SECTION_START=0
section() {
    echo -e "\n${GREEN}=== $* ===${RESET}"
    SECTION_START=$(date +%s)
}

section_end() {
    local elapsed=$(( $(date +%s) - SECTION_START ))
    [[ $elapsed -gt 5 ]] && echo -e "${YELLOW}  (section took ${elapsed}s)${RESET}"
}

# ----------------------------- Counters --------------------------
declare -A COUNTS
COUNTS[CRITICAL]=0
COUNTS[HIGH]=0
COUNTS[MEDIUM]=0

# ----------------------------- Risk Register ---------------------
# Findings accumulator — populated by print_finding() during the run.
# Each entry is a pipe-delimited string: SEVERITY|message
FINDINGS_THIS_RUN=()

# Persistent register file — survives between runs.
# TSV columns: FINGERPRINT  SEVERITY  STATUS  COMMENT  FIRST_SEEN  LAST_SEEN
# STATUS values: "Risk Accepted" | "Under Investigation" | "Remediated"
# FINGERPRINT: sha256 of "SEVERITY|message" — stable identity key across runs
RISK_REGISTER_FILE="/var/lib/node-audit/risk-register.tsv"

# Ensure the register directory and file exist (root only)
if [[ $EUID -eq 0 ]]; then
    mkdir -p "$(dirname "$RISK_REGISTER_FILE")"
    [[ ! -f "$RISK_REGISTER_FILE" ]] && touch "$RISK_REGISTER_FILE"
fi

# Helper: compute a stable 16-char fingerprint for a finding
fingerprint() { printf '%s' "$1|$2" | sha256sum | cut -c1-16; }

# Helper: look up a finding's current register entry fields
register_lookup() {
    local fp="$1" field="$2"
    [[ ! -f "$RISK_REGISTER_FILE" ]] && echo "" && return
    local line; line=$(grep -m1 "^${fp}"$'\t' "$RISK_REGISTER_FILE")
    case "$field" in
        status)  echo "$line" | cut -f3 ;;
        comment) echo "$line" | cut -f4 ;;
        first)   echo "$line" | cut -f5 ;;
    esac
}

echo -e "${GREEN}"
echo "============================================================"
echo " Security Audit — $(hostname) — $(date)"
[[ "$NO_REMEDIATE" == true ]] && echo " Mode: AUDIT ONLY (--no-remediate)"
[[ -n "$LOG_FILE" ]]          && echo " Log:  $LOG_FILE"
echo "============================================================"
echo -e "${RESET}"

# =============================================================================
# SECTION: Bash History Configuration
# =============================================================================
section "Bash History Configuration Audit"

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
        [[ -n "$match" ]] && { BAD_LINES+="  $f: $match\n"; DISABLE_FOUND=true; }
    done < <(grep -E 'HISTFILE=/dev/null|unset[[:space:]]+HISTFILE|HISTSIZE=0|HISTFILESIZE=0' "$f" 2>/dev/null)
done

if [[ $EUID -eq 0 ]]; then
    while IFS= read -r match; do
        [[ -n "$match" ]] && { BAD_LINES+="  $match\n"; DISABLE_FOUND=true; }
    done < <(grep -r -E 'HISTFILE=/dev/null|unset[[:space:]]+HISTFILE|HISTSIZE=0|HISTFILESIZE=0' \
             /etc/profile.d/ 2>/dev/null | grep -v history.sh)
fi

if [[ "$DISABLE_FOUND" == true ]]; then
    print_finding "CRITICAL" "Bash history is DISABLED"
    printf "%b" "$BAD_LINES"
else
    echo -e "${GREEN}✓ Bash history is not disabled${RESET}"
fi

if [[ $EUID -eq 0 ]]; then
    if [[ ! -f /etc/profile.d/history.sh ]]; then
        if [[ "$NO_REMEDIATE" == false ]]; then
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
            echo -e "${YELLOW}⚠ /etc/profile.d/history.sh missing (skipping creation — --no-remediate)${RESET}"
        fi
    else
        echo -e "${GREEN}✓ /etc/profile.d/history.sh exists${RESET}"
    fi
else
    echo -e "${YELLOW}Not root — cannot check/create history.sh${RESET}"
fi

section_end

# =============================================================================
# SECTION: Bash History Scan (30 days)
# =============================================================================
section "Bash History Scan (last 30 days)"

HIST_FILES=()
if [[ $EUID -eq 0 ]]; then
    while IFS= read -r -d '' f; do
        HIST_FILES+=("$f")
    done < <(find /root /home -name ".bash_history" -type f -print0 2>/dev/null)
else
    [[ -f "$HOME/.bash_history" ]] && HIST_FILES+=("$HOME/.bash_history")
fi

for hist in "${HIST_FILES[@]}"; do
    owner=$(stat -c '%U' "$hist" 2>/dev/null || echo "unknown")
    echo -e "\n${YELLOW}--- ${hist} (owner: ${owner}) ---${RESET}"
    issues=0
    has_timestamps=false
    in_window=true

    while IFS= read -r line || [[ -n "$line" ]]; do
        # HISTTIMEFORMAT produces timestamp lines like: #1710000000
        if [[ "$line" =~ ^#([0-9]{10})$ ]]; then
            has_timestamps=true
            ts="${BASH_REMATCH[1]}"
            if [[ "$TIMESTAMP_FILTER" == true ]]; then
                (( ts >= THIRTY_DAYS_AGO )) && in_window=true || in_window=false
            fi
            continue
        fi
        [[ -z "$line" ]] && continue
        [[ "$in_window" != true ]] && continue

        severity=$(get_severity "$line")
        if [[ "$severity" != "NONE" ]]; then
            printf '  '
            print_finding "$severity" "$line"
            ((issues++))
        fi
    done < "$hist"

    if [[ "$has_timestamps" == false ]]; then
        echo -e "${YELLOW}  Note: no timestamps found — entire file scanned${RESET}"
    fi
    if [[ $issues -eq 0 ]]; then
        echo -e "${GREEN}  ✓ Clean${RESET}"
    else
        echo -e "${YELLOW}  ⚠ ${issues} finding(s)${RESET}"
    fi
done

[[ ${#HIST_FILES[@]} -eq 0 ]] && echo -e "${YELLOW}No .bash_history files found${RESET}"

section_end

# =============================================================================
# SECTION: Suspicious Binaries in Volatile Paths + VirusTotal
# =============================================================================
section "Suspicious Executables in Volatile Paths (last 30 days)"

# /var/tmp is intentionally included — it survives reboots unlike /tmp
# and is a well-known persistence location specifically because many
# defenders only look at /tmp and /dev/shm.
mapfile -t suspicious < <(find /tmp /dev/shm /var/tmp /run \
    -type f -executable -mtime -30 2>/dev/null | sort)

if [[ ${#suspicious[@]} -eq 0 ]]; then
    echo -e "${GREEN}✓ No suspicious executables found${RESET}"
else
    echo -e "${YELLOW}Found ${#suspicious[@]} executable(s) in volatile paths${RESET}"

    if [[ -z "$VT_API_KEY" ]]; then
        echo -e "\n${YELLOW}VirusTotal API key not set.${RESET}"
        echo -e "${ORANGE}WARNING: Do not use 'export VT_API_KEY=...' — it will appear in bash history${RESET}"
        read -rs -p "Paste VT API key (invisible input): " VT_API_KEY
        echo ""
        if [[ -z "$VT_API_KEY" ]]; then
            echo -e "${YELLOW}No key entered — VT lookups skipped${RESET}"
        else
            export VT_API_KEY
            echo -e "${GREEN}Key accepted (session only)${RESET}"
        fi
    fi

    for bin in "${suspicious[@]}"; do
        [[ ! -f "$bin" ]] && continue
        hash=$(sha256sum "$bin" 2>/dev/null | cut -d' ' -f1)
        echo -e "\n${ORANGE}  File  : $bin${RESET}"
        echo -e "  Size  : $(du -h "$bin" | cut -f1)"
        echo -e "  Owner : $(stat -c '%U:%G' "$bin" 2>/dev/null)"
        echo -e "  SHA256: $hash"
        print_finding "CRITICAL" "Executable in volatile path: $bin"
        vt_lookup "$hash" "$bin"
    done
fi

section_end

# =============================================================================
# SECTION: SUID / SGID Binaries
# =============================================================================
section "SUID / SGID Binary Audit"

if [[ $EUID -eq 0 ]]; then
    echo -e "${YELLOW}Scanning filesystem for unexpected SUID/SGID binaries (may take a moment)...${RESET}"

    # Known-legitimate SUID/SGID paths on Debian and openSUSE
    KNOWN_SUID_PATHS=(
        /bin/su /usr/bin/su
        /bin/sudo /usr/bin/sudo
        /bin/mount /usr/bin/mount
        /bin/umount /usr/bin/umount
        /usr/bin/passwd
        /usr/bin/newgrp
        /usr/bin/chsh
        /usr/bin/chfn
        /usr/bin/gpasswd
        /usr/bin/pkexec
        /usr/bin/crontab
        /usr/bin/ssh-agent
        /usr/lib/openssh/ssh-keysign
        /usr/lib/dbus-1.0/dbus-daemon-launch-helper
        /usr/sbin/unix_chkpwd
        /usr/sbin/pam_timestamp_check
        /sbin/unix_chkpwd
        /usr/lib/polkit-1/polkit-agent-helper-1
        /usr/lib/xorg/Xorg.wrap
        /usr/bin/at
        /usr/bin/wall
        /usr/bin/write
        /usr/bin/screen
        /usr/bin/expiry
        /usr/bin/dotlockfile
        /usr/lib/eject/dmcrypt-get-device
        /usr/lib/pt_chown
        /usr/bin/traceroute6.iputils
        /bin/ping /usr/bin/ping
        /bin/ping6 /usr/bin/ping6
    )

    SUID_ISSUES=0
    while IFS= read -r bin; do
        known=false
        for k in "${KNOWN_SUID_PATHS[@]}"; do
            [[ "$bin" == "$k" ]] && { known=true; break; }
        done
        if [[ "$known" == false ]]; then
            perms=$(stat -c '%A' "$bin" 2>/dev/null)
            owner=$(stat -c '%U:%G' "$bin" 2>/dev/null)
            print_finding "HIGH" "Unexpected SUID/SGID binary: $bin ($perms, owner: $owner)"
            ((SUID_ISSUES++))
        fi
    done < <(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | sort)

    if [[ $SUID_ISSUES -eq 0 ]]; then
        echo -e "${GREEN}✓ No unexpected SUID/SGID binaries found${RESET}"
    else
        echo -e "${YELLOW}⚠ ${SUID_ISSUES} unexpected SUID/SGID binary(ies) — review above${RESET}"
    fi
else
    echo -e "${YELLOW}Not root — SUID/SGID scan skipped${RESET}"
fi

section_end

# =============================================================================
# SECTION: World-Writable Files Outside Volatile Paths
# =============================================================================
section "World-Writable Files Outside Volatile Paths"

if [[ $EUID -eq 0 ]]; then
    WW_ISSUES=0
    while IFS= read -r f; do
        # Exclude sticky-bit directories which are intentionally world-writable
        perms=$(stat -c '%A' "$f" 2>/dev/null)
        [[ "$perms" == *t* ]] && continue
        owner=$(stat -c '%U' "$f" 2>/dev/null)
        print_finding "HIGH" "World-writable: $f (perms: $perms, owner: $owner)"
        ((WW_ISSUES++))
    done < <(find / -xdev \
        \( -path /tmp -o -path /dev/shm -o -path /var/tmp -o -path /proc -o -path /sys \) \
        -prune -o -perm -0002 -not -type l -print 2>/dev/null)

    if [[ $WW_ISSUES -eq 0 ]]; then
        echo -e "${GREEN}✓ No unexpected world-writable files found${RESET}"
    else
        echo -e "${YELLOW}⚠ ${WW_ISSUES} world-writable file(s) found outside volatile paths${RESET}"
    fi
else
    echo -e "${YELLOW}Not root — world-writable scan skipped${RESET}"
fi

section_end

# =============================================================================
# SECTION: Cron and At Jobs
# =============================================================================
section "Cron and At Jobs Audit"

CRON_ISSUES=0

# System-wide cron paths
CRON_PATHS=(
    /etc/crontab
    /etc/cron.d
    /etc/cron.hourly
    /etc/cron.daily
    /etc/cron.weekly
    /etc/cron.monthly
)

for cp in "${CRON_PATHS[@]}"; do
    [[ -e "$cp" ]] || continue
    if [[ -d "$cp" ]]; then
        mapfile -t cron_files < <(find "$cp" -type f 2>/dev/null)
    else
        cron_files=("$cp")
    fi
    for cf in "${cron_files[@]}"; do
        [[ -f "$cf" ]] || continue
        while IFS= read -r line; do
            [[ "$line" =~ ^[[:space:]]*# ]] && continue
            [[ -z "$line" ]] && continue
            if echo "$line" | grep -qE '/tmp/|/dev/shm/|/var/tmp/|\|[[:space:]]*(bash|sh)|base64|-d.*\||(curl|wget).*\|(bash|sh)'; then
                print_finding "CRITICAL" "Suspicious cron entry in $cf: ${line:0:120}"
                ((CRON_ISSUES++))
            elif echo "$line" | grep -qE '(curl|wget)[[:space:]]'; then
                print_finding "HIGH" "Cron entry with download in $cf: ${line:0:120}"
                ((CRON_ISSUES++))
            fi
        done < "$cf"
        # Cron files must not be world-writable
        if [[ $(stat -c '%a' "$cf" 2>/dev/null) =~ [2367]$ ]]; then
            print_finding "HIGH" "Cron file is world-writable: $cf"
            ((CRON_ISSUES++))
        fi
    done
done

# Per-user crontabs (root only)
if [[ $EUID -eq 0 ]]; then
    SPOOL=/var/spool/cron
    [[ -d "$SPOOL/crontabs" ]] && SPOOL="$SPOOL/crontabs"
    if [[ -d "$SPOOL" ]]; then
        while IFS= read -r -d '' ctab; do
            user=$(basename "$ctab")
            while IFS= read -r line; do
                [[ "$line" =~ ^[[:space:]]*# ]] && continue
                [[ -z "$line" ]] && continue
                if echo "$line" | grep -qE '/tmp/|/dev/shm/|/var/tmp/|\|[[:space:]]*(bash|sh)|base64|(curl|wget).*\|(bash|sh)'; then
                    print_finding "CRITICAL" "Suspicious entry in crontab for '$user': ${line:0:120}"
                    ((CRON_ISSUES++))
                fi
            done < "$ctab"
        done < <(find "$SPOOL" -type f -print0 2>/dev/null)
    fi
fi

# at jobs
if command -v atq >/dev/null 2>&1; then
    AT_JOBS=$(atq 2>/dev/null | wc -l)
    if [[ "$AT_JOBS" -gt 0 ]]; then
        print_finding "MEDIUM" "${AT_JOBS} pending at job(s) present — review with: atq && at -c <job_id>"
    else
        echo -e "${GREEN}✓ No pending at jobs${RESET}"
    fi
fi

if [[ $CRON_ISSUES -eq 0 ]]; then
    echo -e "${GREEN}✓ No suspicious cron entries found${RESET}"
else
    echo -e "${YELLOW}⚠ ${CRON_ISSUES} cron finding(s) — review above${RESET}"
fi

section_end

# =============================================================================
# SECTION: User Account Hygiene
# =============================================================================
section "User Account Hygiene"

ACCT_ISSUES=0

# UID 0 accounts other than root
while IFS=: read -r uname _ uid _ _ _ shell; do
    if [[ "$uid" -eq 0 && "$uname" != "root" ]]; then
        print_finding "CRITICAL" "Non-root account with UID 0: $uname (shell: $shell)"
        ((ACCT_ISSUES++))
    fi
done < /etc/passwd

# Accounts with empty passwords
if [[ $EUID -eq 0 && -f /etc/shadow ]]; then
    while IFS=: read -r uname pass _; do
        if [[ -z "$pass" ]]; then
            print_finding "CRITICAL" "Account with empty password: $uname"
            ((ACCT_ISSUES++))
        fi
    done < /etc/shadow
fi

# Service accounts that have an interactive shell when they shouldn't
NON_SHELL_USERS=(daemon bin sys sync games man lp mail news uucp proxy \
    www-data backup list irc gnats nobody _apt systemd-network \
    systemd-resolve messagebus sshd ntp statd)
while IFS=: read -r uname _ uid _ _ _ shell; do
    [[ "$uid" -lt 1000 ]] || continue
    [[ "$uname" == "root" ]] && continue
    if [[ "$shell" == "/bin/bash" || "$shell" == "/bin/sh" || "$shell" == "/bin/zsh" ]]; then
        for ns in "${NON_SHELL_USERS[@]}"; do
            if [[ "$uname" == "$ns" ]]; then
                print_finding "HIGH" "Service account '$uname' (UID $uid) has interactive shell: $shell"
                ((ACCT_ISSUES++))
                break
            fi
        done
    fi
done < /etc/passwd

# Recently modified auth files (newer than /proc/1/exe as a stable reference point)
if [[ $EUID -eq 0 ]]; then
    RECENTLY_MODIFIED=$(find /etc/passwd /etc/shadow /etc/group /etc/sudoers \
        -newer /proc/1/exe 2>/dev/null | tr '\n' ' ')
    if [[ -n "$RECENTLY_MODIFIED" ]]; then
        print_finding "HIGH" "Recently modified auth files: $RECENTLY_MODIFIED"
        ((ACCT_ISSUES++))
    fi
fi

# Login history summary
echo -e "\n${YELLOW}Recent successful logins (last 10):${RESET}"
last -n 10 2>/dev/null | head -12 || echo "  (last unavailable)"

echo -e "\n${YELLOW}Recent failed logins (lastb — root only):${RESET}"
if [[ $EUID -eq 0 ]]; then
    lastb -n 10 2>/dev/null | head -12 || echo "  (lastb unavailable)"
else
    echo "  (requires root)"
fi

if [[ $ACCT_ISSUES -eq 0 ]]; then
    echo -e "\n${GREEN}✓ No account hygiene issues found${RESET}"
else
    echo -e "\n${YELLOW}⚠ ${ACCT_ISSUES} account finding(s) — review above${RESET}"
fi

section_end

# =============================================================================
# SECTION: SSH Server Configuration Audit
# =============================================================================
section "SSH Server Configuration Audit"

SSHD_CONF=""
for candidate in /etc/ssh/sshd_config /usr/etc/ssh/sshd_config; do
    [[ -f "$candidate" ]] && { SSHD_CONF="$candidate"; break; }
done

if [[ -z "$SSHD_CONF" ]]; then
    echo -e "${YELLOW}sshd_config not found — SSH may not be installed${RESET}"
else
    echo -e "${YELLOW}Checking $SSHD_CONF${RESET}"
    SSH_ISSUES=0

    # Get effective value of an sshd_config directive.
    # Merges main config and drop-in directory; last value wins (OpenSSH behaviour).
    get_ssh_val() {
        local key="$1"
        {
            cat "$SSHD_CONF"
            if [[ -d /etc/ssh/sshd_config.d ]]; then
                cat /etc/ssh/sshd_config.d/*.conf 2>/dev/null
            fi
        } | grep -i "^[[:space:]]*${key}[[:space:]]" \
          | tail -1 \
          | awk '{print tolower($2)}'
    }

    # PermitRootLogin
    val=$(get_ssh_val PermitRootLogin)
    if [[ "$val" == "yes" ]]; then
        print_finding "CRITICAL" "SSH: PermitRootLogin yes — direct root login is allowed"
        ((SSH_ISSUES++))
    elif [[ -z "$val" || "$val" == "prohibit-password" ]]; then
        echo -e "${YELLOW}  ⚠ SSH: PermitRootLogin is '${val:-unset/default}' — recommend setting to 'no'${RESET}"
    else
        echo -e "${GREEN}  ✓ PermitRootLogin: $val${RESET}"
    fi

    # PasswordAuthentication
    val=$(get_ssh_val PasswordAuthentication)
    if [[ "$val" == "yes" || -z "$val" ]]; then
        print_finding "HIGH" "SSH: PasswordAuthentication is '${val:-yes (default)}' — key-only auth strongly recommended"
        ((SSH_ISSUES++))
    else
        echo -e "${GREEN}  ✓ PasswordAuthentication: $val${RESET}"
    fi

    # PermitEmptyPasswords
    val=$(get_ssh_val PermitEmptyPasswords)
    if [[ "$val" == "yes" ]]; then
        print_finding "CRITICAL" "SSH: PermitEmptyPasswords yes — passwordless accounts can log in remotely"
        ((SSH_ISSUES++))
    else
        echo -e "${GREEN}  ✓ PermitEmptyPasswords: ${val:-no (default)}${RESET}"
    fi

    # Protocol — SSHv1 is catastrophically broken
    val=$(get_ssh_val Protocol)
    if [[ "$val" == "1" || "$val" == "1,2" ]]; then
        print_finding "CRITICAL" "SSH: Protocol includes SSHv1 — cryptographically broken, disable immediately"
        ((SSH_ISSUES++))
    else
        echo -e "${GREEN}  ✓ Protocol: ${val:-2 (default)}${RESET}"
    fi

    # X11Forwarding
    val=$(get_ssh_val X11Forwarding)
    if [[ "$val" == "yes" ]]; then
        print_finding "MEDIUM" "SSH: X11Forwarding yes — disable unless explicitly required"
        ((SSH_ISSUES++))
    else
        echo -e "${GREEN}  ✓ X11Forwarding: ${val:-no (default)}${RESET}"
    fi

    # Idle timeout
    val=$(get_ssh_val ClientAliveInterval)
    if [[ -z "$val" || "$val" == "0" ]]; then
        print_finding "MEDIUM" "SSH: ClientAliveInterval not set — idle sessions never time out"
        ((SSH_ISSUES++))
    else
        echo -e "${GREEN}  ✓ ClientAliveInterval: ${val}s${RESET}"
    fi

    # AllowUsers / AllowGroups
    val_u=$(get_ssh_val AllowUsers)
    val_g=$(get_ssh_val AllowGroups)
    if [[ -z "$val_u" && -z "$val_g" ]]; then
        echo -e "${YELLOW}  ⚠ SSH: No AllowUsers or AllowGroups — all valid system accounts may authenticate${RESET}"
    else
        echo -e "${GREEN}  ✓ SSH access restricted: AllowUsers='${val_u}' AllowGroups='${val_g}'${RESET}"
    fi

    # MaxAuthTries
    val=$(get_ssh_val MaxAuthTries)
    if [[ -z "$val" || "$val" -gt 4 ]]; then
        print_finding "MEDIUM" "SSH: MaxAuthTries is '${val:-6 (default)}' — recommend 3 or lower"
        ((SSH_ISSUES++))
    else
        echo -e "${GREEN}  ✓ MaxAuthTries: $val${RESET}"
    fi

    if [[ $SSH_ISSUES -eq 0 ]]; then
        echo -e "${GREEN}✓ SSH configuration looks hardened${RESET}"
    else
        echo -e "${YELLOW}⚠ ${SSH_ISSUES} SSH finding(s) — review above${RESET}"
    fi
fi

section_end

# =============================================================================
# SECTION: Sudoers Configuration Audit
# =============================================================================
section "Sudoers Configuration Audit"

SUDO_ISSUES=0

if [[ $EUID -eq 0 ]]; then
    SUDOERS_FILES=()
    [[ -f /etc/sudoers ]] && SUDOERS_FILES+=("/etc/sudoers")
    if [[ -d /etc/sudoers.d ]]; then
        while IFS= read -r -d '' f; do
            SUDOERS_FILES+=("$f")
        done < <(find /etc/sudoers.d -type f -print0 2>/dev/null)
    fi

    for sf in "${SUDOERS_FILES[@]}"; do
        while IFS= read -r line; do
            [[ "$line" =~ ^[[:space:]]*# ]] && continue
            [[ -z "${line// }" ]] && continue

            # NOPASSWD for ALL — critical
            if echo "$line" | grep -qE 'NOPASSWD.*ALL[[:space:]]*$|NOPASSWD.*\(ALL\).*ALL'; then
                print_finding "CRITICAL" "Sudoers NOPASSWD ALL in $sf: ${line:0:120}"
                ((SUDO_ISSUES++))
            # NOPASSWD for specific command — high
            elif echo "$line" | grep -qiE 'NOPASSWD'; then
                print_finding "HIGH" "Sudoers NOPASSWD entry in $sf: ${line:0:120}"
                ((SUDO_ISSUES++))
            # Unrestricted ALL=(ALL) ALL grant
            elif echo "$line" | grep -qE 'ALL[[:space:]]*=[[:space:]]*\(ALL\).*ALL[[:space:]]*$'; then
                print_finding "HIGH" "Unrestricted sudo grant in $sf: ${line:0:120}"
                ((SUDO_ISSUES++))
            fi
        done < "$sf"

        # Sudoers files must be 440 or 400
        perms=$(stat -c '%a' "$sf" 2>/dev/null)
        if [[ ! "$perms" =~ ^(440|400)$ ]]; then
            print_finding "CRITICAL" "Insecure permissions on $sf: $perms (must be 440 or 400)"
            ((SUDO_ISSUES++))
        fi
    done

    if [[ $SUDO_ISSUES -eq 0 ]]; then
        echo -e "${GREEN}✓ No dangerous sudoers entries found${RESET}"
    else
        echo -e "${YELLOW}⚠ ${SUDO_ISSUES} sudoers finding(s) — review above${RESET}"
    fi
else
    echo -e "${YELLOW}Running 'sudo -l' for current user (not root):${RESET}"
    sudo -l 2>/dev/null || echo -e "${YELLOW}  (no sudo access or sudo -l failed)${RESET}"
fi

section_end

# =============================================================================
# SECTION: Listening Ports
# =============================================================================
section "Listening Ports and Unexpected Services"

if command -v ss >/dev/null 2>&1; then
    echo -e "${YELLOW}All TCP/UDP listeners:${RESET}"
    ss -tlnpu 2>/dev/null | grep -v '127.0.0.1\|::1\|^State'

    PORT_ISSUES=0
    # Ports expected on any host
    COMMON_PORTS=(22 80 443 25 587 465 993 995 143 110 53 123 3306 5432)
    # Ports expected on bonding/SD-WAN appliances when /etc/bonding/bonding.conf exists
    BONDING_PORTS=(53 80 67 323 789 1194 7681 546 8003)
    BONDING_ACTIVE=false
    [[ -f /etc/bonding/bonding.conf ]] && BONDING_ACTIVE=true

    while IFS= read -r line; do
        port=$(echo "$line" | awk '{print $4}' | grep -o '[0-9]*$')
        [[ -z "$port" ]] && continue

        known=false
        for cp in "${COMMON_PORTS[@]}"; do
            [[ "$port" -eq "$cp" ]] && { known=true; break; }
        done
        [[ "$known" == true ]] && continue

        bonding_known=false
        if [[ "$BONDING_ACTIVE" == true ]]; then
            for bp in "${BONDING_PORTS[@]}"; do
                [[ "$port" -eq "$bp" ]] && { bonding_known=true; break; }
            done
        fi

        if [[ "$bonding_known" == true ]]; then
            echo -e "${CYAN}[LOW] Expected bonding/SD-WAN port ${port}: ${line}${RESET}"
        else
            print_finding "MEDIUM" "Unexpected externally-facing port ${port}: $line"
            ((PORT_ISSUES++))
        fi
    done < <(ss -tlnpu 2>/dev/null | grep -E '0\.0\.0\.0:|:::' | grep -v '^State')

    if [[ "$BONDING_ACTIVE" == true ]]; then
        echo -e "${CYAN}  ↳ bonding.conf detected — ports 53 67 80 323 546 789 1194 7681 8003 treated as LOW${RESET}"
    fi
    if [[ $PORT_ISSUES -eq 0 ]]; then
        echo -e "${GREEN}✓ No unexpected externally-facing ports detected${RESET}"
    else
        echo -e "${YELLOW}⚠ ${PORT_ISSUES} unexpected port(s) — verify each is intentional${RESET}"
    fi
else
    echo -e "${YELLOW}ss not available — install iproute2${RESET}"
fi

section_end

# =============================================================================
# SECTION: Running Processes
# =============================================================================
section "Running Processes Audit"

PROC_ISSUES=0

# Build PID list of our own process tree to avoid self-flagging
SELF_TREE=$(pstree -p "$SELF_PID" 2>/dev/null \
    | grep -o '([0-9]*)' | tr -d '()' | tr '\n' '|' | sed 's/|$//')
[[ -z "$SELF_TREE" ]] && SELF_TREE="$SELF_PID"

while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    pid=$(echo "$line" | awk '{print $1}')
    echo "$pid" | grep -qE "^(${SELF_TREE})$" && continue
    echo "$line" | grep -qE 'irqbalance.*--foreground' && continue
    if echo "$line" | grep -Eiq "$SUSPICIOUS_PROC_REGEX"; then
        print_finding "CRITICAL" "Suspicious process: $line"
        ((PROC_ISSUES++))
    fi
done < <(ps -eo pid,user,cmd --no-headers 2>/dev/null)

[[ $PROC_ISSUES -eq 0 ]] && echo -e "${GREEN}✓ No suspicious processes found${RESET}"

echo -e "\n${YELLOW}Top 5 CPU-consuming processes:${RESET}"
ps -eo pid,user,%cpu,cmd --sort=-%cpu --no-headers 2>/dev/null \
    | grep -vE "^[[:space:]]*(${SELF_TREE// /|})[[:space:]]" \
    | head -5 \
    | while IFS= read -r p; do echo -e "  ${ORANGE}$p${RESET}"; done

section_end

# =============================================================================
# SECTION: Firewall Review (nftables + iptables detection)
# =============================================================================
section "Firewall Review"

FW_ISSUES=0

# --- nftables ---
if command -v nft >/dev/null 2>&1; then
    RULES=$(nft list ruleset 2>/dev/null)
    if [[ -z "$RULES" ]]; then
        print_finding "CRITICAL" "nftables is installed but ruleset is empty — no firewall rules active"
        ((FW_ISSUES++))
    else
        echo -e "${GREEN}✓ nftables ruleset is present${RESET}"

        if echo "$RULES" | grep -qE 'chain (input|INPUT).*policy accept'; then
            print_finding "HIGH" "nftables INPUT chain default policy is ACCEPT — should be DROP or REJECT"
            ((FW_ISSUES++))
        else
            echo -e "${GREEN}  ✓ INPUT chain default policy is not ACCEPT${RESET}"
        fi

        if ! echo "$RULES" | grep -qE 'tcp.*dport.*22.*limit|limit.*tcp.*dport.*22'; then
            echo -e "${YELLOW}  ⚠ No SSH rate-limiting rule detected — consider adding a limit on port 22${RESET}"
        else
            echo -e "${GREEN}  ✓ SSH rate-limiting rule present${RESET}"
        fi

        if ! echo "$RULES" | grep -qE 'iif.*lo.*accept|iifname.*lo.*accept'; then
            echo -e "${YELLOW}  ⚠ No explicit loopback acceptance rule found${RESET}"
        else
            echo -e "${GREEN}  ✓ Loopback interface accepted${RESET}"
        fi
    fi
else
    print_finding "HIGH" "nftables (nft) is not installed — no modern firewall present"
    ((FW_ISSUES++))
fi

# --- iptables detection ---
# iptables is legacy and must not be used alongside nftables.
# Any active rules indicate an unfinished migration or an unexpected change.
if command -v iptables >/dev/null 2>&1; then
    IPT_RULES=$(iptables -L -n 2>/dev/null \
        | grep -v '^Chain\|^target\|^$\|^pkts\|policy ACCEPT\|policy DROP')
    if [[ -n "$IPT_RULES" ]]; then
        print_finding "CRITICAL" "iptables has active rules — iptables is legacy and must not be used. Migrate all rules to nftables immediately and flush iptables."
        echo "$IPT_RULES" | head -20 | sed 's/^/  /'
        ((FW_ISSUES++))
    else
        echo -e "${GREEN}  ✓ iptables binary present but no active rules${RESET}"
    fi
fi

if [[ $FW_ISSUES -eq 0 ]]; then
    echo -e "${GREEN}✓ Firewall configuration looks healthy${RESET}"
fi

section_end

# =============================================================================
# SECTION: sshguard and auditd
# =============================================================================
section "sshguard and auditd Status"

# sshguard — check installed AND the service is actually running
if command -v sshguard >/dev/null 2>&1; then
    if systemctl is-active --quiet sshguard 2>/dev/null; then
        echo -e "${GREEN}✓ sshguard installed and running${RESET}"
    else
        print_finding "HIGH" "sshguard is installed but not running — run: systemctl enable --now sshguard"
    fi
else
    print_finding "HIGH" "sshguard not installed — brute-force SSH protection absent (apt/zypper install sshguard)"
fi

# auditd — check service active, not just log file presence
if systemctl is-active --quiet auditd 2>/dev/null; then
    echo -e "${GREEN}✓ auditd is running${RESET}"
    if command -v auditctl >/dev/null 2>&1; then
        ARULES=$(auditctl -l 2>/dev/null | grep -vc '^No rules' || echo 0)
        if [[ "$ARULES" -gt 0 ]]; then
            echo -e "${GREEN}  ✓ auditd has $ARULES active rule(s)${RESET}"
        else
            echo -e "${YELLOW}  ⚠ auditd running but no rules loaded — add rules to /etc/audit/rules.d/${RESET}"
        fi
    fi
elif [[ -f /var/log/audit/audit.log ]]; then
    print_finding "HIGH" "auditd log file exists but the service is not running — log may be stale"
else
    echo -e "${YELLOW}⚠ auditd not active${RESET}"
fi

section_end

# =============================================================================
# SECTION: Kernel Security Parameters (sysctl)
# =============================================================================
section "Kernel Security Parameters (sysctl)"

SYSCTL_ISSUES=0
for entry in "${SYSCTL_CHECKS[@]}"; do
    key=$(echo "$entry" | awk '{print $1}')
    expected=$(echo "$entry" | awk '{print $2}')
    desc=$(echo "$entry" | cut -d' ' -f3-)
    actual=$(sysctl -n "$key" 2>/dev/null)
    if [[ -z "$actual" ]]; then
        echo -e "${YELLOW}  ⚠ $key — not available (kernel may not support it)${RESET}"
    elif [[ "$actual" != "$expected" ]]; then
        print_finding "MEDIUM" "sysctl $key = $actual (expected $expected) — $desc"
        ((SYSCTL_ISSUES++))
    else
        echo -e "${GREEN}  ✓ $key = $actual${RESET}"
    fi
done

if [[ $SYSCTL_ISSUES -eq 0 ]]; then
    echo -e "${GREEN}✓ All checked sysctl parameters correctly set${RESET}"
else
    echo -e "${YELLOW}⚠ ${SYSCTL_ISSUES} sysctl value(s) not at recommended setting — persist fixes in /etc/sysctl.d/99-hardening.conf${RESET}"
fi

section_end

# =============================================================================
# SECTION: Journal Security Events (30 days) — summarised
# =============================================================================
section "Journal Security Events (last 30 days)"

if ! command -v journalctl >/dev/null 2>&1; then
    echo -e "${YELLOW}journalctl unavailable${RESET}"
else
    JTMP=$(mktemp)
    journalctl --since "30 days ago" \
        -u ssh -u sshd -u sudo -u systemd-logind -u auditd -u sshguard \
        --no-pager 2>/dev/null \
        | grep -Ei 'Failed|authentication|invalid|brute|sudo|sshd|denied|AVC|sshguard|blocked' \
        > "$JTMP"

    # grep -c returns exit code 1 on zero matches, which triggers || echo 0,
    # producing two tokens ("0\n0") if the subshell already wrote a 0.
    # Force to a single integer with grep_count().
    grep_count() { grep -cE "$1" "$2" 2>/dev/null; echo 0; }
    safe_count() { grep_count "$1" "$2" | head -1; }

    # Failed SSH logins — summarise by source IP, not per-line
    FAIL_TOTAL=$(safe_count 'Failed password|Invalid user' "$JTMP")
    if [[ "$FAIL_TOTAL" -gt 0 ]]; then
        FAIL_IPS=$(grep -E 'Failed password|Invalid user' "$JTMP" \
            | grep -oE 'from [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' \
            | sort | uniq -c | sort -rn | head -10)
        UNIQUE_IPS=$(echo "$FAIL_IPS" | grep -c . || echo 0)
        if [[ "$FAIL_TOTAL" -ge 100 ]]; then
            print_finding "CRITICAL" "SSH brute-force: $FAIL_TOTAL failed login attempts from $UNIQUE_IPS unique IP(s)"
        else
            print_finding "HIGH" "$FAIL_TOTAL failed SSH login attempt(s) from $UNIQUE_IPS unique IP(s)"
        fi
        echo -e "${YELLOW}  Top source IPs:${RESET}"
        echo "$FAIL_IPS" | sed 's/^/    /'
    else
        echo -e "${GREEN}  ✓ No failed SSH logins in journal${RESET}"
    fi

    # Successful password-based logins (as opposed to key auth)
    PW_LOGINS=$(safe_count 'Accepted password for' "$JTMP")
    if [[ "$PW_LOGINS" -gt 0 ]]; then
        print_finding "HIGH" "$PW_LOGINS successful password-based SSH login(s) — key-only auth is recommended"
        grep -E 'Accepted password for' "$JTMP" | tail -5 | sed 's/^/  /'
    else
        echo -e "${GREEN}  ✓ No password-based SSH logins in journal${RESET}"
    fi

    # sudo policy violations
    SUDO_VIOL=$(safe_count 'sudo: .* : command not allowed' "$JTMP")
    if [[ "$SUDO_VIOL" -gt 0 ]]; then
        print_finding "HIGH" "$SUDO_VIOL sudo policy violation(s)"
        grep -E 'sudo: .* : command not allowed' "$JTMP" | tail -5 | sed 's/^/  /'
    else
        echo -e "${GREEN}  ✓ No sudo policy violations in journal${RESET}"
    fi

    # SELinux / AppArmor denials
    AVC_COUNT=$(safe_count 'avc: denied' "$JTMP")
    if [[ "$AVC_COUNT" -gt 0 ]]; then
        print_finding "HIGH" "$AVC_COUNT AVC denial(s) — SELinux/AppArmor blocking activity"
        grep -E 'avc: denied' "$JTMP" | tail -3 | sed 's/^/  /'
    fi

    rm -f "$JTMP"
fi

section_end

# =============================================================================
# SECTION: Systemd Services Audit (last 30 days)
# =============================================================================
section "Systemd Services Audit (last 30 days)"

if ! command -v journalctl >/dev/null 2>&1; then
    echo -e "${YELLOW}journalctl unavailable${RESET}"
else
    SYS_ISSUES=0
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -z "$line" ]] && continue
        severity="NONE"
        for pat in "${SYSTEMD_CRIT_PATTERNS[@]}"; do
            [[ "$line" =~ $pat ]] && { severity="CRITICAL"; break; }
        done
        if [[ "$severity" == "NONE" ]]; then
            for pat in "${SYSTEMD_HIGH_PATTERNS[@]}"; do
                [[ "$line" =~ $pat ]] && { severity="HIGH"; break; }
            done
        fi
        if [[ "$severity" != "NONE" ]]; then
            col=$(color_for "$severity")
            echo -e "${col}  [${severity}] ${line:0:140}${RESET}"
            ((COUNTS[$severity]++))
            ((SYS_ISSUES++))
        fi
    done < <(journalctl --since "30 days ago" --no-pager -u "systemd*" 2>/dev/null \
             | grep -E 'Created symlink|Removed symlink|Unit .* (started|loaded|changed|from /tmp|from /dev/shm)')

    if [[ $SYS_ISSUES -eq 0 ]]; then
        echo -e "${GREEN}✓ No suspicious service changes in journal${RESET}"
    else
        echo -e "${YELLOW}⚠ ${SYS_ISSUES} service change(s) flagged${RESET}"
    fi
fi

section_end

# =============================================================================
# SECTION: CISA Known Exploited Vulnerabilities (KEV)
# =============================================================================
section "CISA Known Exploited Vulnerabilities (KEV) Cross-Reference"

DISTRO="unknown"
if [[ -f /etc/os-release ]]; then
    # shellcheck source=/dev/null
    . /etc/os-release
    case "$ID" in
        debian|ubuntu)       DISTRO="debian"   ;;
        opensuse*|suse|sles) DISTRO="opensuse" ;;
    esac
fi

if [[ "$DISTRO" == "unknown" ]]; then
    echo -e "${YELLOW}Unknown distro — skipping KEV check${RESET}"
else
    echo -e "${YELLOW}Detected: $DISTRO — fetching CISA KEV catalog...${RESET}"

    # Fetch CVE IDs only; jq not required for matching
    KEV_CVES=$(curl -s --max-time 30 \
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" \
        | grep -o '"CVE-[0-9]\{4\}-[0-9]\+' \
        | tr -d '"' \
        | sort -u)

    if [[ -z "$KEV_CVES" ]]; then
        echo -e "${YELLOW}Failed to fetch CISA KEV list — check network or try again later${RESET}"
    else
        KEV_COUNT=$(echo "$KEV_CVES" | wc -l)
        echo -e "${YELLOW}Loaded $KEV_COUNT KEV CVEs. Getting version-aware CVE list from OS...${RESET}"

        OS_CVES=""
        DEBSECAN_FULL=""

        if [[ "$DISTRO" == "debian" ]]; then
            if ! command -v debsecan >/dev/null 2>&1; then
                echo -e "${YELLOW}debsecan not installed — install with: apt install debsecan${RESET}"
                echo -e "${YELLOW}Falling back to apt changelog scan (not version-aware — verify hits manually)${RESET}"
                OS_CVES=$(apt-get changelog \
                    "$(dpkg --get-selections 2>/dev/null | grep '\binstall$' | awk '{print $1}')" \
                    2>/dev/null \
                    | grep -o 'CVE-[0-9]\{4\}-[0-9]\+' \
                    | sort -u)
            else
                DEBSECAN_FULL=$(debsecan --suite "$VERSION_CODENAME" 2>/dev/null)
                OS_CVES=$(echo "$DEBSECAN_FULL" \
                    | grep -o 'CVE-[0-9]\{4\}-[0-9]\+' \
                    | sort -u)
            fi

        elif [[ "$DISTRO" == "opensuse" ]]; then
            if ! command -v zypper >/dev/null 2>&1; then
                echo -e "${YELLOW}zypper not found — skipping${RESET}"
            else
                PC_CVES=$(zypper --non-interactive --xmlout patch-check 2>/dev/null \
                    | grep -o 'CVE-[0-9]\{4\}-[0-9]\+' | sort -u)
                LP_CVES=$(zypper --non-interactive list-patches --cve 2>/dev/null \
                    | grep -o 'CVE-[0-9]\{4\}-[0-9]\+' | sort -u)
                OS_CVES=$(printf '%s\n%s\n' "$PC_CVES" "$LP_CVES" | sort -u)
            fi
        fi

        MATCH_FOUND=0

        if [[ -z "$OS_CVES" ]]; then
            echo -e "${GREEN}✓ No unpatched CVEs detected by OS tooling${RESET}"
        else
            # Fetch full JSON once for detail lookups if jq is available
            KEV_JSON_CACHE=""
            if command -v jq >/dev/null 2>&1; then
                echo -e "${YELLOW}Fetching full KEV catalog for detail lookups...${RESET}"
                KEV_JSON_CACHE=$(curl -s --max-time 30 \
                    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
            fi

            while IFS= read -r cve; do
                [[ -z "$cve" ]] && continue
                if echo "$KEV_CVES" | grep -qx "$cve"; then
                    echo -e "${RED}[CISA KEV HIT] $cve${RESET}"

                    if [[ -n "$DEBSECAN_FULL" ]]; then
                        PKG_CONTEXT=$(echo "$DEBSECAN_FULL" \
                            | grep "$cve" \
                            | awk '{print $1}' \
                            | sort -u | tr '\n' ' ')
                        [[ -n "$PKG_CONTEXT" ]] && echo -e "   Package(s)  : $PKG_CONTEXT"
                    fi

                    if [[ -n "$KEV_JSON_CACHE" ]]; then
                        DETAILS=$(echo "$KEV_JSON_CACHE" \
                            | jq -r --arg cve "$cve" '
                                .vulnerabilities[] |
                                select(.cveID == $cve) |
                                "   Vendor/Product : \(.vendorProject) \(.product)\n   Name           : \(.vulnerabilityName)\n   Due date       : \(.dueDate)\n   Description    : \(.shortDescription)"
                            ' 2>/dev/null)
                        [[ -n "$DETAILS" ]] && echo -e "$DETAILS"
                    else
                        echo -e "   (install jq for full KEV entry details)"
                    fi

                    echo -e "   ${RED}→ Patch immediately or apply vendor mitigation${RESET}"
                    echo ""
                    ((MATCH_FOUND++))
                    ((COUNTS[CRITICAL]++))
                fi
            done <<< "$OS_CVES"

            if [[ $MATCH_FOUND -eq 0 ]]; then
                echo -e "${GREEN}✓ No unpatched CVEs on this host match the CISA KEV catalog${RESET}"
            else
                echo -e "${YELLOW}⚠ $MATCH_FOUND CISA KEV match(es) — unpatched and actively exploited in the wild${RESET}"
            fi
        fi
    fi
fi

section_end

# =============================================================================
# RISK REGISTER — triage new/pending findings, display register
# =============================================================================
section "Risk Register"

NOW=$(date +%Y-%m-%dT%H:%M:%S)

# Triage is required for:
#   - Findings never seen before
#   - Findings previously skipped (Unreviewed)
#   - Findings under investigation (re-prompt every run until resolved)
# Silently carried forward (last_seen updated only):
#   - Risk Accepted
#   - Remediated
TRIAGE_NEEDED=()
CARRIED_FORWARD=()

if [[ ${#FINDINGS_THIS_RUN[@]} -eq 0 ]]; then
    echo -e "${GREEN}✓ No CRITICAL or HIGH findings to triage${RESET}"
else
    for entry in "${FINDINGS_THIS_RUN[@]}"; do
        sev="${entry%%|*}"
        msg="${entry#*|}"
        fp=$(fingerprint "$sev" "$msg")
        status=$(register_lookup "$fp" status)
        case "$status" in
            "Risk Accepted"|"Remediated")
                CARRIED_FORWARD+=("$entry") ;;
            *)
                # Blank, Unreviewed, Under Investigation — all need re-triage
                TRIAGE_NEEDED+=("$entry") ;;
        esac
    done

    # ── Helper: write/update a register entry ────────────────────────────────
    register_write() {
        local fp="$1" sev="$2" st="$3" cmt="$4"
        [[ $EUID -ne 0 ]] && { echo -e "  ${YELLOW}(Not root — not saved)${RESET}"; return; }
        local first; first=$(register_lookup "$fp" first)
        local tmp; tmp=$(mktemp)
        grep -v "^${fp}"$'\t' "$RISK_REGISTER_FILE" > "$tmp"
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$fp" "$sev" "$st" "$cmt" "${first:-$NOW}" "$NOW" >> "$tmp"
        mv "$tmp" "$RISK_REGISTER_FILE"
    }

    # ── Helper: word-wrap a message to fit inside 76-char display width ───────
    wrap_msg() {
        local text="$1" width=76
        local word line="" out=""
        for word in $text; do
            if (( ${#line} + ${#word} + 1 <= width )); then
                [[ -n "$line" ]] && line+=" $word" || line="$word"
            else
                out+="${line}"$'\n'
                line="$word"
            fi
        done
        [[ -n "$line" ]] && out+="$line"
        printf '%s' "$out"
    }

    # ── Interactive triage ────────────────────────────────────────────────────
    if [[ ${#TRIAGE_NEEDED[@]} -gt 0 ]]; then
        if [[ "$NO_REMEDIATE" == true || ! -t 0 ]]; then
            echo -e "${YELLOW}${#TRIAGE_NEEDED[@]} finding(s) pending triage (non-interactive run).${RESET}"
            echo -e "${YELLOW}Run interactively to assign risk decisions.${RESET}"
            for entry in "${TRIAGE_NEEDED[@]}"; do
                sev="${entry%%|*}"
                msg="${entry#*|}"
                fp=$(fingerprint "$sev" "$msg")
                col=$(color_for "$sev")
                echo -e "  ${col}[${sev}] ${msg:0:100}${RESET}"
                status=$(register_lookup "$fp" status)
                [[ -z "$status" ]] && register_write "$fp" "$sev" "Unreviewed" ""
            done
        else
            echo -e "${YELLOW}${#TRIAGE_NEEDED[@]} finding(s) require a risk decision:${RESET}"
            echo -e "${YELLOW}  1  Risk Accepted${RESET}"
            echo -e "${CYAN}  2  Under Investigation${RESET}"
            echo -e "${GREEN}  3  Remediated${RESET}"
            echo    "  4  Skip / decide later"
            echo ""

            idx=0
            for entry in "${TRIAGE_NEEDED[@]}"; do
                ((idx++))
                sev="${entry%%|*}"
                msg="${entry#*|}"
                fp=$(fingerprint "$sev" "$msg")
                col=$(color_for "$sev")
                prev_status=$(register_lookup "$fp" status)
                prev_comment=$(register_lookup "$fp" comment)
                first=$(register_lookup "$fp" first)

                # Wrap message for clean display inside border box
                BORDER="${col}$(printf '━%.0s' {1..80})${RESET}"
                echo -e "$BORDER"
                printf "${col}  Finding %d / %d   [%s]${RESET}\n" \
                    "$idx" "${#TRIAGE_NEEDED[@]}" "$sev"
                echo -e "$BORDER"
                while IFS= read -r mline; do
                    printf "${col}  %s${RESET}\n" "$mline"
                done <<< "$(wrap_msg "$msg")"
                echo -e "$BORDER"
                if [[ -n "$prev_status" && "$prev_status" != "Unreviewed" ]]; then
                    echo -e "  Previous : ${prev_status}"
                    [[ -n "$prev_comment" ]] && echo -e "  Note     : ${prev_comment}"
                fi
                [[ -n "$first" ]] && echo -e "  First seen: ${first}"
                echo ""

                chosen_status=""
                chosen_comment=""

                while true; do
                    read -rp "  Choice [1/2/3/4, default=4]: " choice
                    case "$choice" in
                        1) chosen_status="Risk Accepted";       break ;;
                        2) chosen_status="Under Investigation"; break ;;
                        3) chosen_status="Remediated";          break ;;
                        4|"") chosen_status="${prev_status:-Unreviewed}"; break ;;
                        *) echo "  Invalid — enter 1, 2, 3, or 4" ;;
                    esac
                done

                if [[ "$chosen_status" != "${prev_status:-Unreviewed}" ]]; then
                    read -rp "  Comment (Enter to keep existing): " new_comment
                    [[ -n "$new_comment" ]] && chosen_comment="$new_comment" \
                                            || chosen_comment="$prev_comment"
                else
                    chosen_comment="$prev_comment"
                fi

                register_write "$fp" "$sev" "$chosen_status" "$chosen_comment"
                echo ""
            done
        fi
    fi

    # ── Carried-forward entries — update last_seen timestamp only ─────────────
    for entry in "${CARRIED_FORWARD[@]}"; do
        sev="${entry%%|*}"
        msg="${entry#*|}"
        fp=$(fingerprint "$sev" "$msg")
        status=$(register_lookup "$fp" status)
        comment=$(register_lookup "$fp" comment)
        register_write "$fp" "$sev" "$status" "$comment"
    done
fi

# ── Register summary table ────────────────────────────────────────────────────
if [[ -f "$RISK_REGISTER_FILE" && -s "$RISK_REGISTER_FILE" ]]; then
    echo ""
    TOTAL_REG=$(grep -c .  "$RISK_REGISTER_FILE" 2>/dev/null | head -1 || echo 0)
    RA_COUNT=$(grep -c  $'\tRisk Accepted\t'       "$RISK_REGISTER_FILE" 2>/dev/null | head -1 || echo 0)
    INV_COUNT=$(grep -c $'\tUnder Investigation\t' "$RISK_REGISTER_FILE" 2>/dev/null | head -1 || echo 0)
    REM_COUNT=$(grep -c $'\tRemediated\t'          "$RISK_REGISTER_FILE" 2>/dev/null | head -1 || echo 0)
    UNREV_COUNT=$(grep -c $'\tUnreviewed\t'        "$RISK_REGISTER_FILE" 2>/dev/null | head -1 || echo 0)

    DIV="${GREEN}$(printf '━%.0s' {1..80})${RESET}"
    echo -e "$DIV"
    echo -e "${GREEN}  RISK REGISTER SUMMARY${RESET}"
    echo -e "$DIV"
    printf "  %-24s %s\n"                           "Total entries:"       "$TOTAL_REG"
    printf "  ${CYAN}%-24s %s${RESET}\n"    "Risk Accepted:"       "${RA_COUNT:-0}"
    printf "  ${CYAN}%-24s %s${RESET}\n"    "Under Investigation:" "${INV_COUNT:-0}"
    printf "  ${GREEN}%-24s %s${RESET}\n"   "Remediated:"          "${REM_COUNT:-0}"
    printf "  ${YELLOW}%-24s %s${RESET}\n"  "Unreviewed:"          "${UNREV_COUNT:-0}"
    echo -e "$DIV"

    # Print entries grouped by status, worst first
    for grp_status in "Unreviewed" "Under Investigation" "Risk Accepted" "Remediated"; do
        case "$grp_status" in
            "Unreviewed")          grp_col="$YELLOW" ;;
            "Under Investigation") grp_col="$CYAN"   ;;
            "Risk Accepted")       grp_col="$CYAN"   ;;
            "Remediated")          grp_col="$GREEN"  ;;
        esac

        grp_lines=()
        while IFS=$'\t' read -r fp sev st cmt first last; do
            [[ "$st" == "$grp_status" ]] || continue
            grp_lines+=("${fp}|${sev}|${cmt}|${first}|${last}")
        done < "$RISK_REGISTER_FILE"

        [[ ${#grp_lines[@]} -eq 0 ]] && continue

        echo -e "\n  ${grp_col}▸ ${grp_status} (${#grp_lines[@]})${RESET}"
        echo -e "  ${grp_col}$(printf '─%.0s' {1..76})${RESET}"

        for gl in "${grp_lines[@]}"; do
            IFS='|' read -r fp sev cmt first last <<< "$gl"
            sev_col=$(color_for "$sev")
            # Resolve display message from this run if available; else mark stale
            disp_msg=""
            for entry in "${FINDINGS_THIS_RUN[@]}"; do
                e_sev="${entry%%|*}"; e_msg="${entry#*|}"
                e_fp=$(fingerprint "$e_sev" "$e_msg")
                if [[ "$e_fp" == "$fp" ]]; then disp_msg="$e_msg"; break; fi
            done
            [[ -z "$disp_msg" ]] && disp_msg="(not seen this run — may be resolved)"

            # Truncate for table column
            short="${disp_msg:0:65}"
            [[ ${#disp_msg} -gt 65 ]] && short+="…"

            printf "  ${sev_col}[%-8s]${RESET}  %s\n" "$sev" "$short"
            [[ -n "$cmt"   ]] && printf "             ${grp_col}↳ %s${RESET}\n"        "$cmt"
            [[ -n "$first" ]] && printf "             First: %-20s  Last: %s\n" "$first" "$last"
        done
    done
    echo -e "$DIV"
fi

section_end

# =============================================================================
# FINAL SUMMARY
# =============================================================================
echo -e "\n${GREEN}"
echo "============================================================"
echo " FINAL AUDIT SUMMARY — $(hostname) — $(date)"
echo "============================================================"
echo -e "${RESET}"
echo -e "  CRITICAL : ${RED}${COUNTS[CRITICAL]}${RESET}"
echo -e "  HIGH     : ${ORANGE}${COUNTS[HIGH]}${RESET}"
echo -e "  MEDIUM   : ${YELLOW}${COUNTS[MEDIUM]}${RESET}"
echo ""

if [[ ${COUNTS[CRITICAL]} -gt 0 ]]; then
    echo -e "${RED}  !! CRITICAL ISSUES FOUND — IMMEDIATE ACTION REQUIRED !!${RESET}"
elif [[ ${COUNTS[HIGH]} -gt 0 ]]; then
    echo -e "${ORANGE}  High-severity issues found — address promptly${RESET}"
elif [[ ${COUNTS[MEDIUM]} -gt 0 ]]; then
    echo -e "${YELLOW}  Medium-severity issues found — review and remediate${RESET}"
else
    echo -e "${GREEN}  ✓ All clear — no findings${RESET}"
fi

echo ""
echo -e "  • Risk register persists at: ${RISK_REGISTER_FILE}"
[[ -n "$LOG_FILE" ]] && echo -e "  • Full output saved to: $LOG_FILE"

exit 0
