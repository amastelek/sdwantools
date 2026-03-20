#!/bin/bash
# =============================================================================
# lan_monitor.sh — LAN Neighbor Monitor (CLI Dashboard)
# Compatible with openSUSE 15.6
# Crontab: 0 * * * * /path/to/lan_monitor.sh
# Usage:   ./lan_monitor.sh          → run scan + save to CSV
#          ./lan_monitor.sh --query  → display CLI dashboard
# =============================================================================

set -uo pipefail

# ── Config ────────────────────────────────────────────────────────────────────
DATA_DIR="${HOME}/lan_monitor_data"
CSV_FILE="${DATA_DIR}/arp_log.csv"
OUI_DB="${DATA_DIR}/oui.txt"
PING_COUNT=3
PING_TIMEOUT=2
MAX_AGE_HOURS=24

mkdir -p "${DATA_DIR}"

# ── Terminal colours ──────────────────────────────────────────────────────────
R=$'\033[0;31m'
G=$'\033[0;32m'
Y=$'\033[0;33m'
C=$'\033[0;36m'
BLD=$'\033[1m'
DIM=$'\033[2m'
RST=$'\033[0m'

GRN_BLK=$'\033[42m  \033[0m'    # solid green block   (online / pingable)
AMB_BLK=$'\033[43m  \033[0m'    # solid amber block   (in table, not pingable)
RED_BLK=$'\033[41m  \033[0m'    # solid red block     (not in neighbor table)
GRY_BLK=$'\033[100m  \033[0m'   # solid grey block    (no scan ran this hour)

# ── Dependency check ──────────────────────────────────────────────────────────
check_deps() {
    local missing=()
    for cmd in ip ping awk grep sed date curl; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "${R}ERROR${RST}: Missing dependencies: ${missing[*]}" >&2
        echo "Install with: sudo zypper install -y ${missing[*]}" >&2
        exit 1
    fi
}

# ── OUI vendor lookup ─────────────────────────────────────────────────────────
update_oui_db() {
    if [[ ! -f "${OUI_DB}" ]] || \
       [[ $(find "${OUI_DB}" -mtime +30 2>/dev/null | wc -l) -gt 0 ]]; then
        echo "[lan_monitor] Downloading IEEE OUI database..."
        curl -sL --max-time 30 \
            "https://standards-oui.ieee.org/oui/oui.txt" \
            -o "${OUI_DB}.tmp" && tr -d '\r' < "${OUI_DB}.tmp" > "${OUI_DB}" && rm "${OUI_DB}.tmp" || {
            echo "[lan_monitor] WARNING: Could not download OUI DB, vendor lookup limited." >&2
        }
    fi
}

lookup_vendor() {
    local mac="$1"
    [[ ! -f "${OUI_DB}" ]] && echo "Unknown" && return
    local prefix
    prefix=$(echo "$mac" | tr '[:lower:]' '[:upper:]' | \
             sed 's/://g' | cut -c1-6 | \
             sed 's/\(..\)\(..\)\(..\)/\1-\2-\3/')
    local vendor
    vendor=$(grep -i "^${prefix}" "${OUI_DB}" 2>/dev/null | \
             awk -F'\t' '{print $3}' | head -1 | \
             sed 's/^[[:space:]]*//; s/[[:space:]]*$//; s/\r//' | cut -c1-22)
    echo "${vendor:-Unknown}"
}

# ── Ping with avg latency ─────────────────────────────────────────────────────
ping_host() {
    local ip="$1"
    local result avg
    if result=$(ping -c "${PING_COUNT}" -W "${PING_TIMEOUT}" -q "${ip}" 2>/dev/null); then
        avg=$(echo "$result" | awk -F'/' '/rtt/{print $5}')
        echo "${avg:-0}ms"
    else
        echo "unreachable"
    fi
}

# ── CSV helpers ───────────────────────────────────────────────────────────────
init_csv() {
    if [[ ! -f "${CSV_FILE}" ]]; then
        echo "timestamp,ip,mac,vendor,pingable,latency" > "${CSV_FILE}"
    fi
}

prune_old_records() {
    local cutoff
    cutoff=$(date -d "${MAX_AGE_HOURS} hours ago" '+%Y-%m-%d %H:%M:%S')
    local tmp
    tmp=$(mktemp)
    head -1 "${CSV_FILE}" > "$tmp"
    awk -F',' -v cutoff="${cutoff}" 'NR>1 && $1 >= cutoff' "${CSV_FILE}" >> "$tmp"
    mv "$tmp" "${CSV_FILE}"
}

# ── Main scan ─────────────────────────────────────────────────────────────────
run_scan() {
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[lan_monitor] Scan started at ${timestamp}"

    update_oui_db
    init_csv
    prune_old_records

    # ip neighbor show line format:
    #   <ip> dev <iface> [lladdr <mac>] <STATE>
    # Valid states with a MAC: REACHABLE, STALE, DELAY, PROBE, PERMANENT
    # Skip: FAILED / INCOMPLETE (no lladdr), and IPv6 addresses (contain ':' in addr)
    local count=0
    while IFS= read -r line; do
        local ip mac vendor pingable latency

        # First field is the address
        ip=$(echo "$line" | awk '{print $1}')

        # Skip IPv6 — their address field always contains ':'
        [[ "$ip" == *:* ]] && continue

        # Skip lines with no lladdr (FAILED / INCOMPLETE)
        echo "$line" | grep -q 'lladdr' || continue

        # Extract MAC — field immediately after the keyword 'lladdr'
        mac=$(echo "$line" | awk '{for(i=1;i<=NF;i++) if($i=="lladdr") print $(i+1)}')
        [[ -z "$mac" ]] && continue

        vendor=$(lookup_vendor "$mac")
        latency=$(ping_host "$ip")

        if [[ "$latency" == "unreachable" ]]; then
            pingable="no"
            latency=""
        else
            pingable="yes"
        fi

        # Deduplicate: only write one record per ip+mac per hour-slot
        local hour_slot
        hour_slot=$(date '+%Y-%m-%d %H')
        if grep -q "^${hour_slot}.*,${ip},${mac}," "${CSV_FILE}" 2>/dev/null; then
            printf "[lan_monitor]  %-16s  %s  (already recorded this hour, skipped)\n" "$ip" "$mac"
            count=$(( count + 1 ))
            continue
        fi

        echo "${timestamp},${ip},${mac},\"${vendor}\",${pingable},${latency}" >> "${CSV_FILE}"
        printf "[lan_monitor]  %-16s  %s  %-22s  ping=%-3s  %s\n" \
            "$ip" "$mac" "$vendor" "$pingable" "${latency:-n/a}"
        count=$(( count + 1 ))

    done < <(ip neighbor show 2>/dev/null | tr -d '\r')

    echo "[lan_monitor] Scan complete — ${count} host(s) recorded."
}

# ── CLI Dashboard ─────────────────────────────────────────────────────────────
show_dashboard() {
    init_csv

    local now_epoch
    now_epoch=$(date '+%s')

    # ── Aggregate CSV into per-host data ──────────────────────────────────────
    # Associative arrays keyed by "ip|mac"
    declare -A h_vendor h_first h_last_ts h_last_ping h_last_lat
    declare -A h_seen_slots h_unseen_slots h_present_slots
    # Track every hour-slot in which a scan ran
    local scanned_slots=","

    local header=1
    while IFS= read -r csvline; do
        [[ $header -eq 1 ]] && { header=0; continue; }
        [[ -z "$csvline" ]] && continue

        # Parse CSV manually to handle quoted vendor field
        # Format: timestamp,ip,mac,"vendor",pingable,latency
        local ts ip mac vendor pingable latency
        ts=$(echo "$csvline"      | awk -F',' '{print $1}')
        ip=$(echo "$csvline"      | awk -F',' '{print $2}')
        mac=$(echo "$csvline"     | awk -F',' '{print $3}')
        vendor=$(echo "$csvline"  | awk -F'"' '{print $2}')
        pingable=$(echo "$csvline" | awk -F'"' '{print $3}' | awk -F',' '{print $2}')
        latency=$(echo "$csvline"  | awk -F'"' '{print $3}' | awk -F',' '{print $3}')

        [[ -z "$ip" || -z "$mac" ]] && continue

        # Map timestamp → hourly slot (0 = current hour, 23 = 23h ago)
        local ts_epoch
        ts_epoch=$(date -d "$ts" '+%s' 2>/dev/null) || continue
        local diff_h=$(( (now_epoch - ts_epoch) / 3600 ))
        [[ $diff_h -lt 0 || $diff_h -ge 24 ]] && continue

        # Record that a scan ran in this slot
        [[ "$scanned_slots" != *",${diff_h},"* ]] && scanned_slots+=",${diff_h},"

        local key="${ip}|${mac}"

        # Register host on first encounter
        if [[ -z "${h_vendor[$key]+x}" ]]; then
            h_vendor[$key]="$vendor"
            h_first[$key]="$ts"
            h_last_ts[$key]="$ts"
            h_last_ping[$key]="$pingable"
            h_last_lat[$key]="$latency"
            h_seen_slots[$key]=","
            h_unseen_slots[$key]=","
            h_present_slots[$key]=","
        fi

        # Track most recent record
        if [[ "$ts" > "${h_last_ts[$key]}" ]]; then
            h_last_ts[$key]="$ts"
            h_last_ping[$key]="$pingable"
            h_last_lat[$key]="$latency"
        fi

        # Record this host was present in the neighbor table this slot
        [[ "${h_present_slots[$key]}" != *",${diff_h},"* ]] && \
            h_present_slots[$key]+="${diff_h},"

        if [[ "$pingable" == "yes" ]]; then
            [[ "${h_seen_slots[$key]}" != *",${diff_h},"* ]] && \
                h_seen_slots[$key]+="${diff_h},"
        else
            [[ "${h_unseen_slots[$key]}" != *",${diff_h},"* ]] && \
                h_unseen_slots[$key]+="${diff_h},"
        fi

    done < "${CSV_FILE}"

    # ── Term width ────────────────────────────────────────────────────────────
    local tw
    tw=$(tput cols 2>/dev/null || echo 132)

    # ── Sort host keys by IP (numeric) ────────────────────────────────────────
    local -a sorted_keys=()
    while IFS= read -r k; do
        sorted_keys+=("$k")
    done < <(
        for key in "${!h_vendor[@]}"; do
            local ip="${key%%|*}"
            local padded
            padded=$(echo "$ip" | awk -F. '{printf "%03d.%03d.%03d.%03d",$1,$2,$3,$4}')
            printf "%s\t%s\n" "$padded" "$key"
        done | sort | awk -F'\t' '{print $2}'
    )

    # ── Stats ─────────────────────────────────────────────────────────────────
    local total=0 online=0 offline=0
    for key in "${!h_vendor[@]}"; do
        total=$(( total + 1 ))
        if [[ "${h_last_ping[$key]}" == "yes" ]]; then
            online=$(( online + 1 ))
        else
            offline=$(( offline + 1 ))
        fi
    done

    # ── Draw ──────────────────────────────────────────────────────────────────
    clear

    # Top border
    printf "${C}"; printf '═%.0s' $(seq 1 "$tw"); printf "${RST}\n"

    # Title bar
    local ts_now
    ts_now=$(date '+%Y-%m-%d %H:%M:%S')
    printf "${BLD}${C} LAN MONITOR  ${DIM}│${RST}${C}  ip neighbor  ·  openSUSE 15.6  ·  24h window${RST}"
    printf "%$((tw - 55))s\n" "${DIM}${ts_now}${RST}"

    # Stats line
    printf "${C}"; printf '─%.0s' $(seq 1 "$tw"); printf "${RST}\n"
    printf "  ${BLD}Hosts:${RST} ${C}${total}${RST}   ${BLD}Online:${RST} ${G}${online}${RST}   ${BLD}Offline:${RST} ${R}${offline}${RST}\n"
    printf "${C}"; printf '─%.0s' $(seq 1 "$tw"); printf "${RST}\n"

    # Column headers
    printf "  ${DIM}${BLD}%-16s  %-17s  %-22s  %-16s  %-10s  %-9s${RST}\n" \
        "IP ADDRESS" "MAC ADDRESS" "VENDOR" "FIRST SEEN" "LATENCY" "STATUS"

    printf "${C}"; printf '─%.0s' $(seq 1 "$tw"); printf "${RST}\n"

    # ── Host rows ─────────────────────────────────────────────────────────────
    for key in "${sorted_keys[@]}"; do
        local ip="${key%%|*}"
        local mac="${key##*|}"
        local vendor="${h_vendor[$key]}"
        local first="${h_first[$key]:0:16}"
        local lat="${h_last_lat[$key]:-}"
        local pingable="${h_last_ping[$key]}"

        # Latency — fixed 10-char visible field, colour applied around it
        local lat_plain lat_colour
        if [[ -z "$lat" ]]; then
            lat_plain="-"
            lat_colour="${DIM}"
        else
            lat_plain="${lat}"
            local lat_num="${lat%ms}"
            if awk "BEGIN{exit !($lat_num < 5)}"   2>/dev/null; then lat_colour="${G}"
            elif awk "BEGIN{exit !($lat_num < 50)}" 2>/dev/null; then lat_colour="${Y}"
            else lat_colour="${R}"
            fi
        fi

        # Status — fixed visible width
        local status_plain status_colour
        if [[ "$pingable" == "yes" ]]; then
            status_plain="● ONLINE "
            status_colour="${G}${BLD}"
        else
            status_plain="○ OFFLINE"
            status_colour="${R}"
        fi

        # Info line — all widths are plain-text widths, colour injected inline
        printf "  ${C}%-16s${RST}  ${DIM}%-17s${RST}  %-22s  ${DIM}%-16s${RST}  %s%-10s${RST}  %s%s${RST}\n" \
            "$ip" "$mac" "$vendor" "$first" \
            "$lat_colour" "$lat_plain" \
            "$status_colour" "$status_plain"

        # Presence bar — own line, indented, exactly 24 blocks (one per hour)
        # Green=pingable  Amber=in table/no ping  Red=absent when scan ran  Grey=no scan
        printf "  "
        for h in $(seq 23 -1 0); do
            local seen_list="${h_seen_slots[$key]:-,}"
            local unseen_list="${h_unseen_slots[$key]:-,}"
            local present_list="${h_present_slots[$key]:-,}"
            if [[ "$seen_list" == *",${h},"* ]]; then
                printf '%s' "${GRN_BLK}"
            elif [[ "$unseen_list" == *",${h},"* ]]; then
                printf '%s' "${AMB_BLK}"
            elif [[ "$scanned_slots" == *",${h},"* ]]; then
                # Scan ran but host wasn't in the neighbor table
                printf '%s' "${RED_BLK}"
            else
                printf '%s' "${GRY_BLK}"
            fi
        done
        printf "${RST}\n"
    done

    # ── Footer ────────────────────────────────────────────────────────────────
    printf "${C}"; printf '─%.0s' $(seq 1 "$tw"); printf "${RST}\n"
    printf "  Legend: ${GRN_BLK} Pingable  ${AMB_BLK} In table/no ping  ${RED_BLK} Not in table  ${GRY_BLK} No scan"
    printf "   ${DIM}CSV: ${CSV_FILE}${RST}\n"
    printf "${C}"; printf '═%.0s' $(seq 1 "$tw"); printf "${RST}\n"
}

# ── Entry point ───────────────────────────────────────────────────────────────
case "${1:-}" in
    query|--query|-q|dash|--dash|-d)
        show_dashboard
        ;;
    help|--help|-h)
        cat <<EOF
${BLD}lan_monitor.sh${RST} — LAN neighbor monitor

${BLD}Usage:${RST}
  lan_monitor.sh        Scan ip neighbor table, write to CSV  (run via cron)
  lan_monitor.sh query  Display 24h CLI dashboard
  lan_monitor.sh help   Show this help

${BLD}Crontab setup${RST} (run as root or a user with neighbour table access):
  crontab -e
  Add:  0 * * * * /path/to/lan_monitor.sh >> /var/log/lan_monitor.log 2>&1

${BLD}Data directory:${RST}  ${DATA_DIR}
${BLD}CSV log:${RST}         ${CSV_FILE}
EOF
        ;;
    "")
        check_deps
        run_scan
        ;;
    *)
        echo "Unknown option: $1  (try: lan_monitor.sh help)" >&2
        exit 1
        ;;
esac
