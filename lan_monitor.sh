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
# Subnets to exclude from scanning and display (CIDR, space-separated)
EXCLUDED_NETS="45.222.22.0/24"

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

# ── Subnet exclusion check ────────────────────────────────────────────────────
# Returns 0 (true) if the IP falls within any EXCLUDED_NETS entry
ip_is_excluded() {
    local ip="$1"
    local net
    for net in ${EXCLUDED_NETS}; do
        local net_addr="${net%/*}"
        local prefix="${net#*/}"
        if awk -F. -v ip="$ip" -v na="$net_addr" -v p="$prefix" '
            BEGIN {
                split(ip, a, ".")
                split(na, b, ".")
                ip_int  = a[1]*16777216 + a[2]*65536 + a[3]*256 + a[4]
                net_int = b[1]*16777216 + b[2]*65536 + b[3]*256 + b[4]
                mask    = (p==0) ? 0 : (2^32 - 2^(32-p))
                exit !( int(ip_int/2^(32-p)) == int(net_int/2^(32-p)) )
            }' /dev/null 2>/dev/null; then
            return 0
        fi
    done
    return 1
}


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

        # Skip excluded subnets
        ip_is_excluded "$ip" && continue

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

    # ── Parse CSV in a single awk pass ───────────────────────────────────────
    # awk does all field extraction, timestamp→epoch conversion, and slot math.
    # Output format per host (tab-separated, one line each field type):
    #   H <key> <vendor> <first_ts> <last_ts> <last_ping> <last_lat>
    #   S <key> <slot>   (seen/pingable)
    #   U <key> <slot>   (unseen/in-table-no-ping)
    #   P <key> <slot>   (present in table)
    #   T <slot>         (scan ran this slot)
    local awk_tmp
    awk_tmp=$(mktemp)

    awk -v now_epoch="$now_epoch" -v excluded="${EXCLUDED_NETS}" '
    function ip_excluded(ip,    n,parts,net,cidr,net_addr,prefix,ip_int,net_int,i,a,b) {
        n = split(excluded, parts, " ")
        for (i=1; i<=n; i++) {
            split(parts[i], cidr, "/")
            net_addr = cidr[1]; prefix = cidr[2]+0
            split(ip,      a, "."); ip_int  = a[1]*16777216+a[2]*65536+a[3]*256+a[4]
            split(net_addr,b, "."); net_int = b[1]*16777216+b[2]*65536+b[3]*256+b[4]
            if (prefix == 0) return 1
            shift = 32 - prefix
            if (int(ip_int / 2^shift) == int(net_int / 2^shift)) return 1
        }
        return 0
    }
    function ts_to_epoch(ts,    cmd,ep) {
        cmd = "date -d \""ts"\" +%s 2>/dev/null"
        cmd | getline ep
        close(cmd)
        return ep+0
    }
    NR==1 { next }   # skip header
    {
        # Parse quoted vendor: timestamp,ip,mac,"vendor",pingable,latency
        ts      = $0; sub(/,.*/, "", ts)
        rest    = $0; sub(/^[^,]*,/, "", rest)
        ip      = rest; sub(/,.*/, "", ip)
        rest2   = rest; sub(/^[^,]*,/, "", rest2)
        mac     = rest2; sub(/,.*/, "", mac)
        # vendor is between first pair of quotes
        vendor  = $0; sub(/^[^"]*"/, "", vendor); sub(/".*/, "", vendor)
        # after closing quote: ,pingable,latency
        tail    = $0; sub(/^[^"]*"[^"]*",/, "", tail)
        pingable = tail; sub(/,.*/, "", pingable)
        latency  = tail; sub(/^[^,]*,/, "", latency)

        if (ip == "" || mac == "") next
        if (ip ~ /:/) next                  # skip IPv6
        if (ip_excluded(ip)) next           # skip excluded subnets

        ts_epoch = ts_to_epoch(ts)
        if (ts_epoch == 0) next
        diff_h = int((now_epoch - ts_epoch) / 3600)
        if (diff_h < 0 || diff_h >= 24) next

        key = ip "|" mac

        # Track scan slot
        if (!scanned[diff_h]++) print "T\t" diff_h

        # Host record
        if (!(key in first_ts)) {
            first_ts[key] = ts
            last_ts[key]  = ts
            h_vendor[key] = vendor
            h_ping[key]   = pingable
            h_lat[key]    = latency
        }
        if (ts > last_ts[key]) {
            last_ts[key] = ts
            h_ping[key]  = pingable
            h_lat[key]   = latency
        }
        if (!seen_h[key,diff_h]++) {
            print "H\t" key "\t" vendor "\t" first_ts[key] "\t" ts "\t" pingable "\t" latency
            print "P\t" key "\t" diff_h
            if (pingable == "yes") print "S\t" key "\t" diff_h
            else                   print "U\t" key "\t" diff_h
        }
    }
    ' "${CSV_FILE}" > "$awk_tmp"

    # ── Load awk output into bash arrays ─────────────────────────────────────
    declare -A h_vendor h_first h_last_ts h_last_ping h_last_lat
    declare -A h_seen_slots h_unseen_slots h_present_slots
    local scanned_slots=","

    while IFS=$'\t' read -r rec_type f1 f2 f3 f4 f5 f6; do
        case "$rec_type" in
            T) [[ "$scanned_slots" != *",${f1},"* ]] && scanned_slots+=",${f1}," ;;
            H) local key="$f1"
               if [[ -z "${h_vendor[$key]+x}" ]]; then
                   h_vendor[$key]="$f2"
                   h_first[$key]="$f3"
                   h_last_ts[$key]="$f4"
                   h_last_ping[$key]="$f5"
                   h_last_lat[$key]="$f6"
                   h_seen_slots[$key]=","
                   h_unseen_slots[$key]=","
                   h_present_slots[$key]=","
               fi
               if [[ "$f4" > "${h_last_ts[$key]}" ]]; then
                   h_last_ts[$key]="$f4"
                   h_last_ping[$key]="$f5"
                   h_last_lat[$key]="$f6"
               fi ;;
            S) h_seen_slots[$f1]+="${f2}," ;;
            U) h_unseen_slots[$f1]+="${f2}," ;;
            P) h_present_slots[$f1]+="${f2}," ;;
        esac
    done < "$awk_tmp"
    rm -f "$awk_tmp"

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

    # ── Load dnsmasq leases (optional) ───────────────────────────────────────
    local LEASES_FILE="/var/run/dnsmasq/dnsmasq.leases"
    # Also check the bonding path mentioned by the user
    [[ ! -f "$LEASES_FILE" ]] && LEASES_FILE="/var/run/bonding/dnsmasq.leases"
    declare -A lease_name
    local has_leases=0
    if [[ -f "$LEASES_FILE" ]]; then
        has_leases=1
        while IFS= read -r lline; do
            [[ -z "$lline" ]] && continue
            local l_mac l_name
            l_mac=$(echo "$lline"  | awk '{print tolower($2)}')
            l_name=$(echo "$lline" | awk '{print $4}')
            # Skip wildcard entries
            [[ "$l_name" == "*" ]] && l_name=""
            [[ -n "$l_mac" && -n "$l_name" ]] && lease_name[$l_mac]="$l_name"
        done < "$LEASES_FILE"
    fi

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
    if [[ $has_leases -eq 1 ]]; then
        printf "  ${DIM}${BLD}%-16s  %-17s  %-22s  %-20s  %-16s  %-10s  %-9s${RST}\n" \
            "IP ADDRESS" "MAC ADDRESS" "VENDOR" "NAME" "FIRST SEEN" "LATENCY" "STATUS"
    else
        printf "  ${DIM}${BLD}%-16s  %-17s  %-22s  %-16s  %-10s  %-9s${RST}\n" \
            "IP ADDRESS" "MAC ADDRESS" "VENDOR" "FIRST SEEN" "LATENCY" "STATUS"
    fi

    printf "${C}"; printf '─%.0s' $(seq 1 "$tw"); printf "${RST}\n"

    # ── Host rows ─────────────────────────────────────────────────────────────
    for key in "${sorted_keys[@]}"; do
        local ip="${key%%|*}"
        local mac="${key##*|}"
        local vendor="${h_vendor[$key]}"
        local first="${h_first[$key]:0:16}"
        local lat="${h_last_lat[$key]:-}"
        local pingable="${h_last_ping[$key]}"

        # Latency — fixed 10-char visible field, colour via bash arithmetic (no awk fork)
        local lat_plain lat_colour
        if [[ -z "$lat" ]]; then
            lat_plain="-"
            lat_colour="${DIM}"
        else
            lat_plain="${lat}"
            # Strip 'ms', keep integer part for comparison
            local lat_int="${lat%.*}"
            lat_int="${lat_int%ms}"
            if   [[ "$lat_int" -lt 5  ]] 2>/dev/null; then lat_colour="${G}"
            elif [[ "$lat_int" -lt 50 ]] 2>/dev/null; then lat_colour="${Y}"
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

        # DHCP name lookup (normalise MAC to lowercase for key match)
        local mac_lower
        mac_lower=$(echo "$mac" | tr '[:upper:]' '[:lower:]')
        local hostname="${lease_name[$mac_lower]:-}"

        # Info line — all widths are plain-text widths, colour injected inline
        if [[ $has_leases -eq 1 ]]; then
            printf "  ${C}%-16s${RST}  ${DIM}%-17s${RST}  %-22s  ${Y}%-20s${RST}  ${DIM}%-16s${RST}  %s%-10s${RST}  %s%s${RST}\n" \
                "$ip" "$mac" "$vendor" "${hostname:--}" "$first" \
                "$lat_colour" "$lat_plain" \
                "$status_colour" "$status_plain"
        else
            printf "  ${C}%-16s${RST}  ${DIM}%-17s${RST}  %-22s  ${DIM}%-16s${RST}  %s%-10s${RST}  %s%s${RST}\n" \
                "$ip" "$mac" "$vendor" "$first" \
                "$lat_colour" "$lat_plain" \
                "$status_colour" "$status_plain"
        fi

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
