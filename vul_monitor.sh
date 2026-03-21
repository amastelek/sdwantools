#!/bin/bash
# =============================================================================
# vul_monitor.sh — LAN Vulnerability Monitor (CLI Dashboard)
# Compatible with openSUSE 15.6 / most systemd distros
#
# Usage:
#   vul_monitor.sh              → run scan (nmap + vulners), save snapshot
#   vul_monitor.sh --query      → display CLI dashboard of last run
#   vul_monitor.sh --help       → show help
#
# Scheduling:
#   Add to crontab:
#     @reboot /usr/local/sbin/daily_vul_monitor.sh >> /var/log/vul_monitor.log 2>&1
#   Or for a fixed daily trigger with random offset use daily_vul_monitor.sh
#   via:  0 2 * * * /usr/local/sbin/daily_vul_monitor.sh >> /var/log/vul_monitor.log 2>&1
#
# Dependencies: ip, ping, nmap (with vulners NSE script), curl, awk, sed, date
# Install nmap vulners (one-time):
#   git clone https://github.com/vulnersCom/nmap-vulners /usr/share/nmap/scripts/vulners
#   nmap --script-updatedb
# =============================================================================

set -uo pipefail

# ── Config ────────────────────────────────────────────────────────────────────
DATA_DIR="${HOME}/vul_monitor_data"
SNAPSHOT="${DATA_DIR}/last_scan.json"
VENDOR_CACHE="${DATA_DIR}/vendor_cache.tsv"   # mac_prefix<TAB>vendor
PING_COUNT=2
PING_TIMEOUT=2
TOP_PORTS=100         # nmap: how many top ports to probe per host
NMAP_TIMING="-T4"     # nmap timing template
MAX_CVE_DETAILS=3     # number of top CVEs to show descriptions for per host

mkdir -p "${DATA_DIR}"

# ── Terminal colours ──────────────────────────────────────────────────────────
R=$'\033[0;31m'
G=$'\033[0;32m'
Y=$'\033[0;33m'
C=$'\033[0;36m'
M=$'\033[0;35m'
BLD=$'\033[1m'
DIM=$'\033[2m'
RST=$'\033[0m'

# ── Dependency check ──────────────────────────────────────────────────────────
check_deps() {
    local missing=()
    for cmd in ip ping nmap awk grep sed date curl; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "${R}ERROR${RST}: Missing dependencies: ${missing[*]}" >&2
        echo "Install with: sudo zypper install -y ${missing[*]}" >&2
        exit 1
    fi
    # Check for vulners NSE script
    if ! nmap --script-help vulners &>/dev/null 2>&1; then
        echo "${Y}WARNING${RST}: nmap vulners NSE script not found." >&2
        echo "  git clone https://github.com/vulnersCom/nmap-vulners /usr/share/nmap/scripts/vulners" >&2
        echo "  nmap --script-updatedb" >&2
        echo "  Continuing without vulnerability data..." >&2
        VULNERS_AVAILABLE=0
    else
        VULNERS_AVAILABLE=1
    fi
}

# ── Vendor lookup via macvendorlookup.com (with local TSV cache) ──────────────
# Cache file format:  <lowercase-mac-no-colons-6chars> TAB <vendor>
# Entries never expire — MAC OUI assignments don't change.
lookup_vendor() {
    local mac="$1"
    local prefix
    prefix=$(echo "$mac" | tr '[:upper:]' '[:lower:]' | \
             sed 's/://g' | cut -c1-6)
    [[ -z "$prefix" ]] && echo "Unknown" && return

    # Check local cache first
    if [[ -f "${VENDOR_CACHE}" ]]; then
        local cached
        cached=$(grep -i "^${prefix}"$'\t' "${VENDOR_CACHE}" 2>/dev/null | \
                 cut -f2 | head -1)
        if [[ -n "$cached" ]]; then
            echo "$cached"
            return
        fi
    fi

    # Query macvendorlookup.com — free tier, no API key required
    # Returns plain JSON: [{"company":"...","mac_prefix":"..."}]
    local vendor
    vendor=$(curl -sf --max-time 8 \
        "https://www.macvendorlookup.com/api/v2/${mac}" 2>/dev/null | \
        grep -oP '"company"\s*:\s*"\K[^"]+' | head -1 | \
        sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | cut -c1-28)

    vendor="${vendor:-Unknown}"

    # Save to cache (create file with header if absent)
    if [[ ! -f "${VENDOR_CACHE}" ]]; then
        printf '# mac_prefix\tvendor\n' > "${VENDOR_CACHE}"
    fi
    printf '%s\t%s\n' "${prefix}" "${vendor}" >> "${VENDOR_CACHE}"

    echo "$vendor"
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

# ── Fetch CVE description from vulners.com API ────────────────────────────────
# Returns a short description string, or empty on failure.
fetch_cve_description() {
    local cve="$1"
    local desc
    desc=$(curl -sf --max-time 8 \
        "https://vulners.com/api/v3/search/id/?id=${cve}" 2>/dev/null | \
        grep -oP '"description"\s*:\s*"\K[^"]{10,200}' | head -1 | \
        sed 's/\\n/ /g; s/  */ /g')
    # Fallback: NIST NVD CVE API
    if [[ -z "$desc" ]]; then
        desc=$(curl -sf --max-time 8 \
            "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cve}" \
            2>/dev/null | \
            grep -oP '"value"\s*:\s*"\K[^"]{10,200}' | head -1 | \
            sed 's/\\n/ /g; s/  */ /g')
    fi
    # Truncate to 120 chars for display
    echo "${desc:0:120}"
}

# ── nmap scan: open ports + vulners ──────────────────────────────────────────
# Writes two tab-separated fields to out_file:
#   field 1: ports summary (single line)
#   field 2: CVE list (pipe-separated: ID|SCORE|DESC ...)
nmap_scan_host() {
    local ip="$1"
    local out_file="$2"

    local nmap_cmd="nmap ${NMAP_TIMING} --open -sV --top-ports ${TOP_PORTS}"
    if [[ "${VULNERS_AVAILABLE:-0}" -eq 1 ]]; then
        nmap_cmd+=" --script vulners"
    fi

    local nmap_out
    nmap_out=$(${nmap_cmd} "${ip}" 2>/dev/null) || true

    # ── Open ports summary ──────────────────────────────────────────────────
    local ports_summary
    ports_summary=$(echo "$nmap_out" | \
        awk '/^[0-9]+\/(tcp|udp)/{
            split($1,a,"/"); port=a[1]; proto=a[2]; service=$3
            printf "%s/%s(%s) ", port, proto, service
        }' | sed 's/[[:space:]]*$//')
    [[ -z "$ports_summary" ]] && ports_summary="no open ports detected"

    # ── Vulners CVE extraction — deduplicated, sorted by CVSS desc ──────────
    local cve_field="no CVEs found"
    if [[ "${VULNERS_AVAILABLE:-0}" -eq 1 ]]; then
        # Extract all CVE-YEAR-ID  SCORE pairs; deduplicate by CVE ID (keep
        # highest score for any duplicated ID), then sort highest-first.
        local deduped_cves
        deduped_cves=$(echo "$nmap_out" | \
            grep -oP 'CVE-\d{4}-\d{4,7}\s+[0-9]+\.[0-9]+' | \
            awk '{
                cve=$1; score=$2
                # keep highest score per CVE ID
                if (!(cve in best) || score+0 > best[cve]+0)
                    best[cve]=score
            }
            END {
                for (cve in best) printf "%s %s\n", cve, best[cve]
            }' | \
            sort -t' ' -k2 -rn)

        if [[ -n "$deduped_cves" ]]; then
            # Build a pipe-delimited list: CVE-XXXX-YYYY|SCORE|DESCRIPTION
            # Descriptions fetched only for the top MAX_CVE_DETAILS entries.
            local pipe_list=""
            local detail_count=0
            while IFS=' ' read -r cve score; do
                [[ -z "$cve" ]] && continue
                local desc=""
                if (( detail_count < MAX_CVE_DETAILS )); then
                    desc=$(fetch_cve_description "$cve")
                    detail_count=$(( detail_count + 1 ))
                fi
                # Sanitise desc — remove pipes and tabs (field separators)
                desc=$(echo "$desc" | tr '|\t' '  ')
                [[ -n "$pipe_list" ]] && pipe_list+="|"
                pipe_list+="${cve}~${score}~${desc}"
            done <<< "$deduped_cves"
            cve_field="${pipe_list}"
        fi
    else
        cve_field="vulners script unavailable"
    fi

    # Write tab-separated: ports <TAB> cve_field
    printf '%s\t%s' "${ports_summary}" "${cve_field}" > "${out_file}"
}

# ── JSON escaping ─────────────────────────────────────────────────────────────
json_esc() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    printf '%s' "$s"
}

# ── Main scan ─────────────────────────────────────────────────────────────────
run_scan() {
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[vul_monitor] Scan started at ${timestamp}"

    check_deps
    # (vendor lookups go direct to macvendorlookup.com with local cache — no DB download needed)

    # Collect neighbour entries (IPv4 only, with a MAC)
    local -a hosts=()
    while IFS= read -r line; do
        local ip mac
        ip=$(echo "$line" | awk '{print $1}')
        [[ "$ip" == *:* ]] && continue                  # skip IPv6
        echo "$line" | grep -q 'lladdr' || continue     # need a MAC
        mac=$(echo "$line" | awk '{for(i=1;i<=NF;i++) if($i=="lladdr") print $(i+1)}')
        [[ -z "$mac" ]] && continue
        hosts+=("${ip} ${mac}")
    done < <(ip neighbor show 2>/dev/null | tr -d '\r')

    local total=${#hosts[@]}
    echo "[vul_monitor] ${total} host(s) in neighbour table — running nmap scans..."

    local tmp_snap
    tmp_snap=$(mktemp)
    printf '{\n  "scan_time": "%s",\n  "hosts": [\n' \
        "$(json_esc "$timestamp")" > "${tmp_snap}"

    local idx=0
    for entry in "${hosts[@]}"; do
        local ip mac vendor latency pingable
        ip=$(echo "$entry"  | awk '{print $1}')
        mac=$(echo "$entry" | awk '{print $2}')
        vendor=$(lookup_vendor "$mac")
        latency=$(ping_host "$ip")

        if [[ "$latency" == "unreachable" ]]; then
            pingable="false"
            latency=""
        else
            pingable="true"
        fi

        printf "[vul_monitor] (%d/%d) nmap scanning %s ...\n" \
            $(( idx + 1 )) "${total}" "${ip}"

        local nmap_tmp
        nmap_tmp=$(mktemp)
        nmap_scan_host "${ip}" "${nmap_tmp}"
        local ports cves
        ports=$(cut -f1 "${nmap_tmp}")
        cves=$(cut  -f2 "${nmap_tmp}")
        rm -f "${nmap_tmp}"

        [[ $idx -gt 0 ]] && printf ',\n' >> "${tmp_snap}"

        cat >> "${tmp_snap}" <<JSONBLOCK
    {
      "ip":      "$(json_esc "$ip")",
      "mac":     "$(json_esc "$mac")",
      "vendor":  "$(json_esc "$vendor")",
      "pingable": ${pingable},
      "latency": "$(json_esc "$latency")",
      "ports":   "$(json_esc "$ports")",
      "cves":    "$(json_esc "$cves")"
    }
JSONBLOCK

        printf "[vul_monitor]  %-16s  ping=%-5s  ports: %s\n" \
            "$ip" "$pingable" "$ports"

        idx=$(( idx + 1 ))
    done

    printf '\n  ]\n}\n' >> "${tmp_snap}"
    mv "${tmp_snap}" "${SNAPSHOT}"
    echo "[vul_monitor] Snapshot saved to ${SNAPSHOT}"
    echo "[vul_monitor] Scan complete."
}

# ── CLI Dashboard ─────────────────────────────────────────────────────────────
show_dashboard() {
    if [[ ! -f "${SNAPSHOT}" ]]; then
        echo "${R}No snapshot found.${RST}  Run:  $(basename "$0")  to perform the first scan."
        exit 1
    fi

    # ── Parse JSON (no jq needed) ─────────────────────────────────────────────
    declare -a d_ip d_mac d_vendor d_ping d_lat d_ports d_cves
    local scan_time=""
    local idx=-1
    local in_hosts=0   # 1 once we've entered the "hosts": [ array

    while IFS= read -r line; do
        line=$(echo "$line" | sed 's/^[[:space:]]*//')

        [[ "$line" =~ \"scan_time\"[[:space:]]*:[[:space:]]*\"([^\"]+)\" ]] && \
            scan_time="${BASH_REMATCH[1]}"

        # Detect entry into the hosts array
        [[ "$line" =~ \"hosts\"[[:space:]]*:[[:space:]]*\[ ]] && in_hosts=1

        # Only count '{' as a new host record once inside the hosts array
        if [[ $in_hosts -eq 1 && "$line" == "{"  ]]; then
            idx=$(( idx + 1 ))
            continue
        fi

        if [[ "$line" =~ \"ip\"[[:space:]]*:[[:space:]]*\"([^\"]+)\" ]];
            then d_ip[$idx]="${BASH_REMATCH[1]}"; fi
        if [[ "$line" =~ \"mac\"[[:space:]]*:[[:space:]]*\"([^\"]+)\" ]];
            then d_mac[$idx]="${BASH_REMATCH[1]}"; fi
        if [[ "$line" =~ \"vendor\"[[:space:]]*:[[:space:]]*\"([^\"]+)\" ]];
            then d_vendor[$idx]="${BASH_REMATCH[1]}"; fi
        if [[ "$line" =~ \"pingable\"[[:space:]]*:[[:space:]]*(true|false) ]];
            then d_ping[$idx]="${BASH_REMATCH[1]}"; fi
        if [[ "$line" =~ \"latency\"[[:space:]]*:[[:space:]]*\"([^\"]*)\" ]];
            then d_lat[$idx]="${BASH_REMATCH[1]}"; fi
        if [[ "$line" =~ \"ports\"[[:space:]]*:[[:space:]]*\"([^\"]*)\" ]];
            then d_ports[$idx]="${BASH_REMATCH[1]}"; fi
        if [[ "$line" =~ \"cves\"[[:space:]]*:[[:space:]]*\"([^\"]*)\" ]];
            then d_cves[$idx]="${BASH_REMATCH[1]}"; fi
    done < "${SNAPSHOT}"

    local total=$(( idx + 1 ))
    local online=0 offline=0
    for (( i=0; i<total; i++ )); do
        [[ "${d_ping[$i]:-false}" == "true" ]] && \
            online=$(( online + 1 )) || offline=$(( offline + 1 ))
    done

    # ── Optional dnsmasq leases ───────────────────────────────────────────────
    local LEASES_FILE="/var/run/dnsmasq/dnsmasq.leases"
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
            [[ "$l_name" == "*" ]] && l_name=""
            [[ -n "$l_mac" && -n "$l_name" ]] && lease_name[$l_mac]="$l_name"
        done < "$LEASES_FILE"
    fi

    # ── Sort by IP (numeric) ──────────────────────────────────────────────────
    local -a sorted_idx=()
    while IFS= read -r i; do
        sorted_idx+=("$i")
    done < <(
        for (( i=0; i<total; i++ )); do
            local padded
            padded=$(echo "${d_ip[$i]}" | \
                awk -F. '{printf "%03d.%03d.%03d.%03d",$1,$2,$3,$4}')
            printf "%s\t%d\n" "$padded" "$i"
        done | sort | awk -F'\t' '{print $2}'
    )

    # ── Draw ──────────────────────────────────────────────────────────────────
    local tw
    tw=$(tput cols 2>/dev/null || echo 140)
    clear

    printf "${C}"; printf '═%.0s' $(seq 1 "$tw"); printf "${RST}\n"
    printf "${BLD}${C} LAN VULNERABILITY MONITOR${RST}${C}  ${DIM}│${RST}${C}  nmap --top-ports ${TOP_PORTS} + vulners  ·  last scan: ${scan_time}${RST}"
    printf "%$((tw - 75))s\n" "${DIM}$(date '+%Y-%m-%d %H:%M:%S')${RST}"
    printf "${C}"; printf '─%.0s' $(seq 1 "$tw"); printf "${RST}\n"
    printf "  ${BLD}Hosts scanned:${RST} ${C}${total}${RST}   ${BLD}Online:${RST} ${G}${online}${RST}   ${BLD}Offline:${RST} ${R}${offline}${RST}\n"
    printf "${C}"; printf '─%.0s' $(seq 1 "$tw"); printf "${RST}\n"

    for i in "${sorted_idx[@]}"; do
        local ip="${d_ip[$i]:-}"
        local mac="${d_mac[$i]:-}"

        # Skip any phantom entry that has no IP (shouldn't occur after parser fix)
        [[ -z "$ip" ]] && continue

        local vendor="${d_vendor[$i]:-Unknown}"
        local pingable="${d_ping[$i]:-false}"
        local lat="${d_lat[$i]:-}"
        local ports="${d_ports[$i]:-}"
        local cve_raw="${d_cves[$i]:-}"

        # Hostname from leases — guard against empty mac
        local mac_lower hostname=""
        mac_lower=$(echo "$mac" | tr '[:upper:]' '[:lower:]')
        [[ $has_leases -eq 1 && -n "$mac_lower" ]] && hostname="${lease_name[$mac_lower]:-N/A}"
        [[ $has_leases -eq 0 ]] && hostname="N/A"

        # Status
        local status_str status_col
        if [[ "$pingable" == "true" ]]; then
            status_str="● ONLINE "
            status_col="${G}${BLD}"
        else
            status_str="○ OFFLINE"
            status_col="${R}"
        fi

        # Latency colour
        local lat_col="${DIM}"
        if [[ -n "$lat" ]]; then
            local lat_num="${lat%ms}"
            if awk "BEGIN{exit !($lat_num < 5)}"   2>/dev/null; then lat_col="${G}"
            elif awk "BEGIN{exit !($lat_num < 50)}" 2>/dev/null; then lat_col="${Y}"
            else lat_col="${R}"
            fi
        fi

        printf "${C}"; printf '─%.0s' $(seq 1 "$tw"); printf "${RST}\n"

        # ── Row 1: identity + status ──────────────────────────────────────────
        printf "  ${BLD}${C}%-16s${RST}  ${DIM}%-17s${RST}  %-28s  ${Y}%-20s${RST}  ${lat_col}%-10s${RST}  %s%s${RST}\n" \
            "$ip" "$mac" "$vendor" "$hostname" "${lat:--}" \
            "$status_col" "$status_str"

        # ── Row 2: open ports ─────────────────────────────────────────────────
        printf "  ${DIM}Ports  :${RST}  ${M}%s${RST}\n" "$ports"

        # ── Rows 3+: CVE summary line + per-CVE description lines ─────────────
        # cve_raw is pipe-separated entries: CVE~SCORE~DESC|CVE~SCORE~DESC|...
        if [[ "$cve_raw" == "no CVEs found" || \
              "$cve_raw" == "vulners script unavailable" || \
              -z "$cve_raw" ]]; then
            local vuln_col="${G}"
            [[ "$cve_raw" == "vulners script unavailable" ]] && vuln_col="${Y}"
            printf "  ${DIM}Vulns  :${RST}  ${vuln_col}%s${RST}\n" "${cve_raw:-no CVEs found}"
        else
            # Build compact summary line: CVE-XXXX(SCORE) CVE-XXXX(SCORE) ...
            local summary_line=""
            local entry cve score
            local IFS_ORIG="$IFS"
            IFS='|' read -ra cve_entries <<< "$cve_raw"
            IFS="$IFS_ORIG"
            for entry in "${cve_entries[@]}"; do
                cve=$(echo "$entry"  | cut -d'~' -f1)
                score=$(echo "$entry" | cut -d'~' -f2)
                [[ -z "$cve" ]] && continue
                summary_line+="${cve}(${score}) "
            done
            summary_line=$(echo "$summary_line" | sed 's/[[:space:]]*$//')

            printf "  ${DIM}Vulns  :${RST}  ${R}${BLD}%s${RST}\n" "$summary_line"

            # Per-CVE detail lines (top MAX_CVE_DETAILS with descriptions)
            local detail_count=0
            for entry in "${cve_entries[@]}"; do
                [[ $detail_count -ge $MAX_CVE_DETAILS ]] && break
                cve=$(echo "$entry"  | cut -d'~' -f1)
                score=$(echo "$entry" | cut -d'~' -f2)
                local desc
                desc=$(echo "$entry" | cut -d'~' -f3-)
                [[ -z "$cve" ]] && continue

                local score_col="${G}"
                if awk "BEGIN{exit !(${score}+0 >= 9.0)}" 2>/dev/null; then
                    score_col="${R}${BLD}"
                elif awk "BEGIN{exit !(${score}+0 >= 7.0)}" 2>/dev/null; then
                    score_col="${R}"
                elif awk "BEGIN{exit !(${score}+0 >= 4.0)}" 2>/dev/null; then
                    score_col="${Y}"
                fi

                if [[ -n "$desc" ]]; then
                    printf "  ${DIM}  ↳${RST} ${score_col}%-20s CVSS %-4s${RST}  %s\n" \
                        "$cve" "$score" "$desc"
                else
                    printf "  ${DIM}  ↳${RST} ${score_col}%-20s CVSS %-4s${RST}  (no description available)\n" \
                        "$cve" "$score"
                fi
                detail_count=$(( detail_count + 1 ))
            done
        fi
    done

    printf "${C}"; printf '═%.0s' $(seq 1 "$tw"); printf "${RST}\n"
    printf "  ${DIM}Snapshot: ${SNAPSHOT}${RST}\n"
    printf "${C}"; printf '─%.0s' $(seq 1 "$tw"); printf "${RST}\n"
}

# ── Help ──────────────────────────────────────────────────────────────────────
show_help() {
    cat <<EOF
${BLD}vul_monitor.sh${RST} — LAN Vulnerability Monitor (nmap + vulners)

${BLD}Usage:${RST}
  vul_monitor.sh              Scan neighbours → nmap → vulners → save snapshot
  vul_monitor.sh --query      Show CLI dashboard of last run
  vul_monitor.sh --help       Show this help

${BLD}Dashboard rows per host:${RST}
  Line 1  IP · MAC · Vendor · Hostname (dnsmasq) · Latency · Status
  Ports   Top ${TOP_PORTS} open ports with service names
  Vulns   Deduplicated CVE list (highest CVSS first)
    ↳     Top ${MAX_CVE_DETAILS} CVEs expanded with CVSS score + description

${BLD}Cron scheduling (via daily_vul_monitor.sh):${RST}
  Place vul_monitor.sh at   /usr/local/sbin/vul_monitor.sh
  Place daily_vul_monitor.sh at  /usr/local/sbin/daily_vul_monitor.sh
  Add to root crontab:
    0 2 * * * /usr/local/sbin/daily_vul_monitor.sh >> /var/log/vul_monitor.log 2>&1

${BLD}Vendor lookup:${RST}
  Uses macvendorlookup.com API (free, no key needed).
  Results cached locally in ${VENDOR_CACHE}

${BLD}Setup vulners NSE script (one-time):${RST}
  git clone https://github.com/vulnersCom/nmap-vulners /usr/share/nmap/scripts/vulners
  nmap --script-updatedb

${BLD}Data directory:${RST}  ${DATA_DIR}
${BLD}Snapshot:${RST}        ${SNAPSHOT}
EOF
}

# ── Entry point ───────────────────────────────────────────────────────────────
case "${1:-}" in
    query|--query|-q|dash|--dash|-d)
        show_dashboard
        ;;
    help|--help|-h)
        show_help
        ;;
    "")
        run_scan
        ;;
    *)
        echo "Unknown option: $1  (try: $(basename "$0") --help)" >&2
        exit 1
        ;;
esac
