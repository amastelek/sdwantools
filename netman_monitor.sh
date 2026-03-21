#!/bin/bash
# =============================================================================
# netman_monitor.sh — LAN Network Manager Monitor (CLI Dashboard)
# Based on vul_monitor.sh by amastelek
# Compatible with: Debian 11/12, Ubuntu 20.04+, openSUSE Leap 15.x / Tumbleweed
#
# Usage:
#   netman_monitor.sh              → full scan (brute-force all communities)
#   netman_monitor.sh fastscan     → fast scan (public/private only)
#   netman_monitor.sh --query      → display CLI dashboard of last run
#   netman_monitor.sh --help       → show help
#
# Scheduling:
#   0 2 * * * /usr/local/sbin/netman_monitor.sh >> /var/log/netman_monitor.log 2>&1
#
# Dependencies: ip, ping, curl, awk, sed, date, nmap, snmpget, snmpwalk
#   Debian/Ubuntu : sudo apt-get install -y nmap snmp iproute2 curl
#   openSUSE      : sudo zypper install -y nmap net-snmp net-snmp-utils iproute2 curl
# =============================================================================

set -uo pipefail

# ── Config ────────────────────────────────────────────────────────────────────
DATA_DIR="${HOME}/netman_monitor_data"
SNAPSHOT="${DATA_DIR}/last_scan.json"
VENDOR_CACHE="${DATA_DIR}/vendor_cache.tsv"
COMMUNITY_STORE="${DATA_DIR}/known_communities.tsv"
PING_COUNT=2
PING_TIMEOUT=2
SNMP_TIMEOUT=2
SNMP_RETRIES=0          # 0 retries — rely on timeout only, keeps brute-force tight
SNMP_PORT=161

# Fast-scan wordlist (--fastscan flag)
SNMP_COMMUNITIES_FAST=( "public" "private" )

# Full community wordlist — v1 pass runs first, then v2c
SNMP_COMMUNITIES=(
    "public"
    "private"
    "community"
    "admin"
    "manager"
    "network"
    "monitor"
    "snmp"
    "snmpd"
    "switch"
    "router"
    "cisco"
    "default"
    "internal"
    "guest"
    "readonly"
    "readwrite"
    "read"
    "write"
    "test"
    "secret"
    "password"
    "pass"
    "1234"
    "12345"
)

# Populated at runtime by parse_args
FAST_SCAN=0

mkdir -p "${DATA_DIR}"

# ── Distro detection ──────────────────────────────────────────────────────────
DISTRO_FAMILY="unknown"
detect_distro() {
    if [[ -f /etc/os-release ]]; then
        local id_like id_val
        id_like=$(. /etc/os-release 2>/dev/null && printf '%s' "${ID_LIKE:-}")
        id_val=$(. /etc/os-release  2>/dev/null && printf '%s' "${ID:-}")
        local combined="${id_like} ${id_val}"
        case "${combined,,}" in
            *debian*|*ubuntu*)  DISTRO_FAMILY="debian" ;;
            *suse*|*opensuse*)  DISTRO_FAMILY="suse"   ;;
        esac
    fi
}

# ── Terminal colours ──────────────────────────────────────────────────────────
R=$'\033[0;31m'
G=$'\033[0;32m'
Y=$'\033[0;33m'
C=$'\033[0;36m'
M=$'\033[0;35m'
BLD=$'\033[1m'
DIM=$'\033[2m'
RST=$'\033[0m'

BLK_GRN=$'\033[0;32m█\033[0m'   # green block  ▀ for port up
BLK_RED=$'\033[0;31m█\033[0m'   # red block    ▀ for port down

# ── Portable line-drawing ─────────────────────────────────────────────────────
draw_line() {
    local char="$1" width="$2" i
    for (( i=0; i<width; i++ )); do printf '%s' "$char"; done
    printf '\n'
}

# ── Dependency check + auto-install ──────────────────────────────────────────
check_deps() {
    detect_distro
    declare -A PKG_MAP=(
        [nmap]="nmap:nmap"
        [snmpget]="snmp:net-snmp net-snmp-utils"
        [snmpwalk]="snmp:net-snmp net-snmp-utils"
        [ip]="iproute2:iproute2"
        [curl]="curl:curl"
        [ping]="iputils-ping:iputils"
        [awk]="gawk:gawk"
        [grep]="grep:grep"
        [sed]="sed:sed"
        [date]="coreutils:coreutils"
    )

    local missing=()
    for cmd in ip ping awk grep sed date curl nmap snmpget snmpwalk; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    [[ ${#missing[@]} -eq 0 ]] && return 0

    printf '%bMissing dependencies:%b %s\n' "${Y}" "${RST}" "${missing[*]}"

    if [[ "${DISTRO_FAMILY}" == "unknown" ]]; then
        printf '%bERROR%b: Cannot auto-install — unrecognised distro.\n' "${R}" "${RST}" >&2
        printf 'Please install manually: %s\n' "${missing[*]}" >&2
        exit 1
    fi

    declare -A pkgs_needed
    local cmd pkg_pair pkg p
    for cmd in "${missing[@]}"; do
        pkg_pair="${PKG_MAP[$cmd]:-}"
        if [[ -z "$pkg_pair" ]]; then pkgs_needed["$cmd"]=1; continue; fi
        case "${DISTRO_FAMILY}" in
            debian) IFS=':' read -r pkg _ <<< "$pkg_pair" ;;
            suse)   IFS=':' read -r _ pkg <<< "$pkg_pair" ;;
        esac
        for p in $pkg; do pkgs_needed["$p"]=1; done
    done

    local install_list=( "${!pkgs_needed[@]}" )
    printf '%bAuto-installing:%b %s\n' "${C}" "${RST}" "${install_list[*]}"

    if [[ $EUID -ne 0 ]] && ! command -v sudo &>/dev/null; then
        printf '%bERROR%b: Need root or sudo to install packages.\n' "${R}" "${RST}" >&2
        exit 1
    fi
    local SUDO=""
    [[ $EUID -ne 0 ]] && SUDO="sudo"

    local rc=0
    case "${DISTRO_FAMILY}" in
        debian)
            $SUDO apt-get update -qq 2>/dev/null || true
            $SUDO apt-get install -y -qq "${install_list[@]}" || rc=$?
            ;;
        suse)
            $SUDO zypper --non-interactive install --no-recommends \
                "${install_list[@]}" || rc=$?
            ;;
    esac

    if [[ $rc -ne 0 ]]; then
        printf '%bERROR%b: Package install failed (exit %d). Install manually: %s\n' \
            "${R}" "${RST}" "$rc" "${install_list[*]}" >&2
        exit 1
    fi

    local still_missing=()
    for cmd in ip ping awk grep sed date curl nmap snmpget snmpwalk; do
        command -v "$cmd" &>/dev/null || still_missing+=("$cmd")
    done
    if [[ ${#still_missing[@]} -gt 0 ]]; then
        printf '%bERROR%b: Still missing: %s\n' "${R}" "${RST}" "${still_missing[*]}" >&2
        exit 1
    fi
    printf '%bDependencies satisfied.%b\n' "${G}" "${RST}"
}

# ── Vendor lookup ─────────────────────────────────────────────────────────────
lookup_vendor() {
    local mac="$1"
    local prefix
    prefix=$(printf '%s' "$mac" | tr '[:upper:]' '[:lower:]' | sed 's/://g' | cut -c1-6)
    [[ -z "$prefix" ]] && printf 'Unknown' && return

    if [[ -f "${VENDOR_CACHE}" ]]; then
        local cached
        cached=$(grep -i "^${prefix}	" "${VENDOR_CACHE}" 2>/dev/null | cut -f2 | head -1)
        if [[ -n "$cached" ]]; then printf '%s' "$cached"; return; fi
    fi

    local raw vendor=""
    raw=$(curl -sf --max-time 8 \
        "https://www.macvendorlookup.com/api/v2/${mac}" 2>/dev/null || true)
    if [[ -n "$raw" ]]; then
        vendor=$(printf '%s' "$raw" | \
                 sed 's/.*"company"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' | \
                 head -1 | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | cut -c1-28)
        printf '%s' "$vendor" | grep -q '"' && vendor=""
    fi
    vendor="${vendor:-Unknown}"
    [[ ! -f "${VENDOR_CACHE}" ]] && printf '# mac_prefix\tvendor\n' > "${VENDOR_CACHE}"
    printf '%s\t%s\n' "${prefix}" "${vendor}" >> "${VENDOR_CACHE}"
    printf '%s' "$vendor"
}

# ── Ping ──────────────────────────────────────────────────────────────────────
ping_host() {
    local ip="$1"
    local result avg
    if result=$(ping -c "${PING_COUNT}" -W "${PING_TIMEOUT}" -q "${ip}" 2>/dev/null); then
        avg=$(printf '%s' "$result" | awk -F'/' '/rtt|round-trip/{print $5}')
        printf '%s' "${avg:-0}ms"
    else
        printf 'unreachable'
    fi
}

# ── nmap SNMP probe — port detection + version hint ───────────────────────────
# Sets global SNMP_NMAP_VERSION to "v1", "v2c", or "" (unknown).
# Returns 0 = port open/responding, 1 = closed/filtered.
SNMP_NMAP_VERSION=""

snmp_probe() {
    local ip="$1"
    SNMP_NMAP_VERSION=""

    local nmap_out
    nmap_out=$(nmap -sU -p "${SNMP_PORT}" -T4 \
                    --script snmp-info \
                    -oN - "${ip}" 2>/dev/null || true)

    if ! printf '%s' "$nmap_out" | grep -qi "${SNMP_PORT}/udp.*open"; then
        return 1
    fi

    local ver_line
    ver_line=$(printf '%s' "$nmap_out" | grep -i "snmp-info" | grep -i "snmp" | head -1)

    if printf '%s' "$ver_line" | grep -qi "v2c\|2c"; then
        SNMP_NMAP_VERSION="v2c"
    elif printf '%s' "$ver_line" | grep -qi "v1\b\|snmpv1"; then
        SNMP_NMAP_VERSION="v1"
    fi
    return 0
}

# ── SNMP brute-force (v1 first, then v2c) ────────────────────────────────────
# Prints a ! to stderr for each community attempt (progress indicator).
# Uses nmap version hint to skip the irrelevant version pass entirely.
# Fast-scan mode uses only public/private.
#
# Writes 5 tab-separated fields to out_file:
#   1: community   2: snmp_version   3: sysName   4: sysDescr   5: uptime
snmp_scan_host() {
    local ip="$1"
    local out_file="$2"

    local found_community="" found_version=""
    local sys_name="" sys_descr="" uptime_raw="" uptime_str=""

    # Select wordlist
    local -a wordlist
    if [[ "${FAST_SCAN}" -eq 1 ]]; then
        wordlist=( "${SNMP_COMMUNITIES_FAST[@]}" )
    else
        wordlist=( "${SNMP_COMMUNITIES[@]}" )
    fi

    # ── Helper: probe one community+version, print ! progress tick ──────────
    try_community() {
        local ver="$1" comm="$2"
        printf '!' >&2
        if snmpget "-${ver}" -c "${comm}" \
                   -t "${SNMP_TIMEOUT}" -r "${SNMP_RETRIES}" \
                   "${ip}:${SNMP_PORT}" \
                   SNMPv2-MIB::sysObjectID.0 \
                   >/dev/null 2>&1; then
            found_community="${comm}"
            found_version="${ver}"
            return 0
        fi
        return 1
    }

    # ── Step 1: try cached community first (fast path) ───────────────────────
    if [[ -f "${COMMUNITY_STORE}" ]]; then
        local cached_line cached_comm cached_ver
        cached_line=$(grep "^${ip}	" "${COMMUNITY_STORE}" 2>/dev/null | head -1)
        if [[ -n "$cached_line" ]]; then
            cached_comm=$(printf '%s' "$cached_line" | cut -f2)
            cached_ver=$(printf '%s'  "$cached_line" | cut -f3)
            [[ -z "$cached_ver" || "$cached_ver" == 20[0-9][0-9]* ]] && cached_ver="v1"
            if [[ -n "$cached_comm" ]]; then
                printf '\n[netman_monitor]    cached: "%s" (%s) ' "$cached_comm" "$cached_ver" >&2
                try_community "$cached_ver" "$cached_comm" && \
                    printf ' HIT\n' >&2
            fi
        fi
    fi

    # ── Steps 2/3: wordlist — v1 first, v2c second (or single pass if hinted) ─
    if [[ -z "$found_community" ]]; then
        local -a ver_passes=()
        case "${SNMP_NMAP_VERSION:-}" in
            v1)  ver_passes=("v1")        ;;   # v1-only — skip v2c entirely
            v2c) ver_passes=("v2c")       ;;   # v2c-only — skip v1 entirely
            *)   ver_passes=("v1" "v2c")  ;;   # unknown  — v1 first, then v2c
        esac

        local ver comm
        for ver in "${ver_passes[@]}"; do
            printf '\n[netman_monitor]    SNMP%s: ' "$ver" >&2
            for comm in "${wordlist[@]}"; do
                try_community "$ver" "$comm" && break 2
            done
        done
        printf '\n' >&2
    fi

    # ── Retrieve MIB values on success ───────────────────────────────────────
    if [[ -n "$found_community" ]]; then
        printf '[netman_monitor]    community="%s" %s — fetching MIB...\n' \
            "$found_community" "$found_version" >&2

        sys_name=$(snmpget "-${found_version}" -c "${found_community}" \
                           -t "${SNMP_TIMEOUT}" -r "${SNMP_RETRIES}" \
                           -Oqv "${ip}:${SNMP_PORT}" \
                           SNMPv2-MIB::sysName.0 2>/dev/null | \
                   tr -d '"' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
        sys_name="${sys_name:-N/A}"

        sys_descr=$(snmpget "-${found_version}" -c "${found_community}" \
                            -t "${SNMP_TIMEOUT}" -r "${SNMP_RETRIES}" \
                            -Oqv "${ip}:${SNMP_PORT}" \
                            SNMPv2-MIB::sysDescr.0 2>/dev/null | \
                    tr -d '"' | tr '\n' ' ' | \
                    sed 's/^[[:space:]]*//; s/[[:space:]]*$//; s/  */ /g' | \
                    cut -c1-80)
        sys_descr="${sys_descr:-N/A}"

        uptime_raw=$(snmpget "-${found_version}" -c "${found_community}" \
                             -t "${SNMP_TIMEOUT}" -r "${SNMP_RETRIES}" \
                             -Ov "${ip}:${SNMP_PORT}" \
                             SNMPv2-MIB::sysUpTime.0 2>/dev/null || true)
        uptime_str=$(printf '%s' "$uptime_raw" | \
                     sed 's/^Timeticks:[[:space:]]*([ 0-9]*)[[:space:]]*//' | \
                     sed 's/^[[:space:]]*//' | cut -c1-40)

        if [[ -z "$uptime_str" ]]; then
            uptime_str=$(snmpget "-${found_version}" -c "${found_community}" \
                                 -t "${SNMP_TIMEOUT}" -r "${SNMP_RETRIES}" \
                                 -Ov "${ip}:${SNMP_PORT}" \
                                 HOST-RESOURCES-MIB::hrSystemUptime.0 2>/dev/null | \
                         sed 's/^Timeticks:[[:space:]]*([ 0-9]*)[[:space:]]*//' | \
                         sed 's/^[[:space:]]*//' | cut -c1-40 || true)
        fi
        uptime_str="${uptime_str:-unknown}"

        # Persist community + version (upsert)
        [[ ! -f "${COMMUNITY_STORE}" ]] && \
            printf '# ip\tcommunity\tsnmp_version\ttimestamp\n' > "${COMMUNITY_STORE}"
        local ts
        ts=$(date '+%Y-%m-%d %H:%M:%S')
        if grep -q "^${ip}	" "${COMMUNITY_STORE}" 2>/dev/null; then
            local tmp_cs
            tmp_cs=$(mktemp)
            grep -v "^${ip}	" "${COMMUNITY_STORE}" > "${tmp_cs}"
            printf '%s\t%s\t%s\t%s\n' "${ip}" "${found_community}" "${found_version}" "${ts}" \
                >> "${tmp_cs}"
            mv "${tmp_cs}" "${COMMUNITY_STORE}"
        else
            printf '%s\t%s\t%s\t%s\n' "${ip}" "${found_community}" "${found_version}" "${ts}" \
                >> "${COMMUNITY_STORE}"
        fi
    fi

    # Sanitise tabs from field values
    sys_name=$(printf '%s'   "$sys_name"   | tr '\t' ' ')
    sys_descr=$(printf '%s'  "$sys_descr"  | tr '\t' ' ')
    uptime_str=$(printf '%s' "$uptime_str" | tr '\t' ' ')

    printf '%s\t%s\t%s\t%s\t%s' \
        "${found_community:-none}" \
        "${found_version:-none}" \
        "${sys_name:-N/A}" \
        "${sys_descr:-N/A}" \
        "${uptime_str:-N/A}" \
        > "${out_file}"
}

# ── Interface port status (IF-MIB) ────────────────────────────────────────────
# Uses raw numeric OIDs + -On output (OID = TYPE: VALUE) for unambiguous parsing.
# snmpwalk -On produces: .1.3.6.1.2.1.2.2.1.8.3 = INTEGER: down(2)
# The last dotted component of the OID is the ifIndex.
#
# Fetches all four error/discard counters per interface:
#   ifInErrors    .1.3.6.1.2.1.2.2.1.14  — receive errors
#   ifOutErrors   .1.3.6.1.2.1.2.2.1.20  — transmit errors
#   ifInDiscards  .1.3.6.1.2.1.2.2.1.13  — inbound packets discarded (e.g. buffer full)
#   ifOutDiscards .1.3.6.1.2.1.2.2.1.19  — outbound packets discarded
#
# Returns pipe-separated records:
#   ifIndex~ifDescr~operStatus~ifInErrors~ifOutErrors~ifInDiscards~ifOutDiscards
get_port_status() {
    local ip="$1" community="$2" ver="$3"

    local snmp_args="-${ver} -c ${community} -t ${SNMP_TIMEOUT} -r ${SNMP_RETRIES} -On"
    local descr_raw status_raw in_err_raw out_err_raw in_disc_raw out_disc_raw

    descr_raw=$(snmpwalk    ${snmp_args} "${ip}:${SNMP_PORT}" .1.3.6.1.2.1.2.2.1.2  2>/dev/null || true)
    status_raw=$(snmpwalk   ${snmp_args} "${ip}:${SNMP_PORT}" .1.3.6.1.2.1.2.2.1.8  2>/dev/null || true)
    in_err_raw=$(snmpwalk   ${snmp_args} "${ip}:${SNMP_PORT}" .1.3.6.1.2.1.2.2.1.14 2>/dev/null || true)
    out_err_raw=$(snmpwalk  ${snmp_args} "${ip}:${SNMP_PORT}" .1.3.6.1.2.1.2.2.1.20 2>/dev/null || true)
    in_disc_raw=$(snmpwalk  ${snmp_args} "${ip}:${SNMP_PORT}" .1.3.6.1.2.1.2.2.1.13 2>/dev/null || true)
    out_disc_raw=$(snmpwalk ${snmp_args} "${ip}:${SNMP_PORT}" .1.3.6.1.2.1.2.2.1.19 2>/dev/null || true)

    [[ -z "$status_raw" ]] && printf '' && return

    declare -A descr_map status_map in_err_map out_err_map in_disc_map out_disc_map

    local line oid idx val

    # descr: STRING value after "STRING: "
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        oid=$(printf '%s' "$line" | awk '{print $1}')
        idx=$(printf '%s' "$oid"  | awk -F'.' '{print $NF}')
        val=$(printf '%s' "$line" | sed 's/.*STRING: //' | tr -d '"\r')
        [[ "$idx" =~ ^[0-9]+$ ]] && descr_map["$idx"]="$val"
    done <<< "$descr_raw"

    # operStatus: "up(1)" or "down(2)" — extract digit from inside parens
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        oid=$(printf '%s' "$line" | awk '{print $1}')
        idx=$(printf '%s' "$oid"  | awk -F'.' '{print $NF}')
        val=$(printf '%s' "$line" | grep -o '([0-9]*)' | tr -d '()' | head -1)
        [[ -z "$val" ]] && val=$(printf '%s' "$line" | awk -F':' '{print $NF}' | tr -d ' \r')
        [[ "$idx" =~ ^[0-9]+$ ]] && status_map["$idx"]="$val"
    done <<< "$status_raw"

    # Counter parser (shared pattern for all four error/discard OIDs)
    parse_counter_walk() {
        local raw="$1"
        local -n _map="$2"
        local line oid idx val
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            oid=$(printf '%s' "$line" | awk '{print $1}')
            idx=$(printf '%s' "$oid"  | awk -F'.' '{print $NF}')
            val=$(printf '%s' "$line" | awk -F':' '{print $NF}' | tr -d ' \r')
            [[ "$idx" =~ ^[0-9]+$ ]] && _map["$idx"]="$val"
        done <<< "$raw"
    }

    parse_counter_walk "$in_err_raw"   in_err_map
    parse_counter_walk "$out_err_raw"  out_err_map
    parse_counter_walk "$in_disc_raw"  in_disc_map
    parse_counter_walk "$out_disc_raw" out_disc_map

    local result=""
    local sorted_keys
    sorted_keys=$(printf '%s\n' "${!status_map[@]}" | sort -n)

    while IFS= read -r idx; do
        [[ -z "$idx" ]] && continue
        local d="${descr_map[$idx]:-port${idx}}"
        local s="${status_map[$idx]:-2}"
        local ie="${in_err_map[$idx]:-0}"
        local oe="${out_err_map[$idx]:-0}"
        local id="${in_disc_map[$idx]:-0}"
        local od="${out_disc_map[$idx]:-0}"
        # Skip loopback interfaces
        printf '%s' "$d" | grep -qi 'lo\b\|loopback\|software' && continue
        [[ -n "$result" ]] && result+='|'
        result+="${idx}~${d}~${s}~${ie}~${oe}~${id}~${od}"
    done <<< "$sorted_keys"

    printf '%s' "$result"
}

# ── Printer detection + ink/cartridge/tray status ────────────────────────────
# Detects printer via prtGeneralPrinterStatus (raw OID 1.3.6.1.2.1.43.5.1.1.15.1)
# Uses direct numeric OIDs from Printer-MIB as per RFC 3805.
#
# Tray levels:  1.3.6.1.2.1.43.8.2.1.10.1.x  (prtInputCurrentLevel, x=1..N)
# Supply level: 1.3.6.1.2.1.43.11.1.1.9.1.x  (prtMarkerSuppliesLevel)
# Supply max:   1.3.6.1.2.1.43.11.1.1.8.1.x  (prtMarkerSuppliesMaxCapacity)
# Supply desc:  1.3.6.1.2.1.43.11.1.1.6.1.x  (prtMarkerSuppliesDescription)
# Supply type:  1.3.6.1.2.1.43.11.1.1.4.1.x  (prtMarkerSuppliesType)
# Tray desc:    1.3.6.1.2.1.43.8.2.1.13.1.x  (prtInputName)
#
# Returns empty string if device is not a printer.
# Result format:  printer_status|S:idx~desc~level~max~type|...|T:idx~name~level
get_printer_info() {
    local ip="$1" community="$2" ver="$3"

    local snmp_args="-${ver} -c ${community} -t ${SNMP_TIMEOUT} -r ${SNMP_RETRIES} -On"

    # ── Detect printer: probe prtGeneralPrinterStatus ─────────────────────────
    # OID: .1.3.6.1.2.1.43.5.1.1.15.1  (hrDeviceIndex=1, standard starting point)
    # Also try .1.3.6.1.2.1.43.5.1.1.15 walk to handle non-standard device indices
    local pstatus_raw
    pstatus_raw=$(snmpwalk ${snmp_args} "${ip}:${SNMP_PORT}" \
                           .1.3.6.1.2.1.43.5.1.1.15 2>/dev/null || true)
    [[ -z "$pstatus_raw" ]] && printf '' && return

    # Extract first status value — "INTEGER: idle(3)" → grab digit from parens
    local pstatus_val
    pstatus_val=$(printf '%s' "$pstatus_raw" | head -1 | \
                  grep -o '([0-9]*)' | tr -d '()' | head -1)
    [[ -z "$pstatus_val" ]] && \
        pstatus_val=$(printf '%s' "$pstatus_raw" | head -1 | \
                      awk -F':' '{print $NF}' | tr -d ' \r')

    local pstatus_str
    case "${pstatus_val}" in
        3) pstatus_str="idle"       ;;
        4) pstatus_str="processing" ;;
        5) pstatus_str="stopped"    ;;
        *) pstatus_str="unknown(${pstatus_val})" ;;
    esac

    # ── Supply ink/toner walks ────────────────────────────────────────────────
    local sdesc_raw slevel_raw smax_raw stype_raw
    sdesc_raw=$(snmpwalk  ${snmp_args} "${ip}:${SNMP_PORT}" .1.3.6.1.2.1.43.11.1.1.6  2>/dev/null || true)
    slevel_raw=$(snmpwalk ${snmp_args} "${ip}:${SNMP_PORT}" .1.3.6.1.2.1.43.11.1.1.9  2>/dev/null || true)
    smax_raw=$(snmpwalk   ${snmp_args} "${ip}:${SNMP_PORT}" .1.3.6.1.2.1.43.11.1.1.8  2>/dev/null || true)
    stype_raw=$(snmpwalk  ${snmp_args} "${ip}:${SNMP_PORT}" .1.3.6.1.2.1.43.11.1.1.4  2>/dev/null || true)

    # ── Tray walks ────────────────────────────────────────────────────────────
    local tname_raw tlevel_raw
    tname_raw=$(snmpwalk  ${snmp_args} "${ip}:${SNMP_PORT}" .1.3.6.1.2.1.43.8.2.1.13 2>/dev/null || true)
    tlevel_raw=$(snmpwalk ${snmp_args} "${ip}:${SNMP_PORT}" .1.3.6.1.2.1.43.8.2.1.10 2>/dev/null || true)

    # ── Parse supplies ────────────────────────────────────────────────────────
    # Lines: .1.3.6.1.2.1.43.11.1.1.6.1.1 = STRING: "Black Toner"
    #        .1.3.6.1.2.1.43.11.1.1.9.1.1 = INTEGER: 85
    # Index is the LAST component of the OID.
    declare -A sdesc_map slevel_map smax_map stype_map
    local line oid idx val

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        oid=$(printf '%s' "$line" | awk '{print $1}')
        idx=$(printf '%s' "$oid"  | awk -F'.' '{print $NF}')
        val=$(printf '%s' "$line" | sed 's/.*STRING: //' | tr -d '"\r')
        [[ "$idx" =~ ^[0-9]+$ ]] && sdesc_map["$idx"]="$val"
    done <<< "$sdesc_raw"

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        oid=$(printf '%s' "$line" | awk '{print $1}')
        idx=$(printf '%s' "$oid"  | awk -F'.' '{print $NF}')
        val=$(printf '%s' "$line" | awk -F':' '{print $NF}' | tr -d ' \r')
        [[ "$idx" =~ ^[0-9]+$ ]] && slevel_map["$idx"]="$val"
    done <<< "$slevel_raw"

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        oid=$(printf '%s' "$line" | awk '{print $1}')
        idx=$(printf '%s' "$oid"  | awk -F'.' '{print $NF}')
        val=$(printf '%s' "$line" | awk -F':' '{print $NF}' | tr -d ' \r')
        [[ "$idx" =~ ^[0-9]+$ ]] && smax_map["$idx"]="$val"
    done <<< "$smax_raw"

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        oid=$(printf '%s' "$line" | awk '{print $1}')
        idx=$(printf '%s' "$oid"  | awk -F'.' '{print $NF}')
        val=$(printf '%s' "$line" | awk -F':' '{print $NF}' | tr -d ' \r')
        # prtMarkerSuppliesType values come as "INTEGER: toner(3)" — grab digit from parens
        if [[ -z "$val" || ! "$val" =~ ^-?[0-9]+$ ]]; then
            val=$(printf '%s' "$line" | grep -o '([0-9]*)' | tr -d '()' | head -1)
        fi
        [[ "$idx" =~ ^[0-9]+$ ]] && stype_map["$idx"]="$val"
    done <<< "$stype_raw"

    # ── Parse trays ───────────────────────────────────────────────────────────
    declare -A tname_map tlevel_map
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        oid=$(printf '%s' "$line" | awk '{print $1}')
        idx=$(printf '%s' "$oid"  | awk -F'.' '{print $NF}')
        val=$(printf '%s' "$line" | sed 's/.*STRING: //' | tr -d '"\r')
        [[ "$idx" =~ ^[0-9]+$ ]] && tname_map["$idx"]="$val"
    done <<< "$tname_raw"

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        oid=$(printf '%s' "$line" | awk '{print $1}')
        idx=$(printf '%s' "$oid"  | awk -F'.' '{print $NF}')
        val=$(printf '%s' "$line" | awk -F':' '{print $NF}' | tr -d ' \r')
        [[ "$idx" =~ ^[0-9]+$ ]] && tlevel_map["$idx"]="$val"
    done <<< "$tlevel_raw"

    # ── Build result string ───────────────────────────────────────────────────
    local result="${pstatus_str}"

    # Supplies (S: prefix)
    local sorted_keys
    sorted_keys=$(printf '%s\n' "${!sdesc_map[@]}" | sort -n)
    while IFS= read -r idx; do
        [[ -z "$idx" ]] && continue
        local d="${sdesc_map[$idx]:-supply${idx}}"
        local lv="${slevel_map[$idx]:-0}"
        local mx="${smax_map[$idx]:-100}"
        local tp="${stype_map[$idx]:-0}"
        d=$(printf '%s' "$d" | tr '|~\t' '   ')
        result+="|S:${idx}~${d}~${lv}~${mx}~${tp}"
    done <<< "$sorted_keys"

    # Trays (T: prefix)
    sorted_keys=$(printf '%s\n' "${!tname_map[@]}" | sort -n)
    while IFS= read -r idx; do
        [[ -z "$idx" ]] && continue
        local n="${tname_map[$idx]:-Tray${idx}}"
        local lv="${tlevel_map[$idx]:-0}"
        n=$(printf '%s' "$n" | tr '|~\t' '   ')
        result+="|T:${idx}~${n}~${lv}"
    done <<< "$sorted_keys"

    printf '%s' "$result"
}

# ── Device type detection ────────────────────────────────────────────────────
# Returns "printer", "ap", or "" (unknown/generic).
# Printer: already detected via prtGeneralPrinterStatus; pass non-empty printer_info.
# AP: detected via sysObjectID OUI or sysDescr keywords (Cisco AP, Ubiquiti, etc.)
detect_device_type() {
    local ip="$1" community="$2" ver="$3" printer_info="$4" sys_descr="$5"

    # Already confirmed printer
    [[ -n "$printer_info" ]] && printf 'printer' && return

    # AP detection via sysDescr keywords
    local desc_lower
    desc_lower=$(printf '%s' "$sys_descr" | tr '[:upper:]' '[:lower:]')
    if printf '%s' "$desc_lower" | grep -qE         'access.?point|wireless|802\.11|wifi|wi-fi|ubiquiti|unifi|aironet|aruba|ruckus|meraki|eap|wlan'; then
        printf 'ap'
        return
    fi

    # AP detection via sysObjectID OUI walk — Ubiquiti=41112, Cisco-AIR=9
    local sysoid
    sysoid=$(snmpget "-${ver}" -c "${community}" -t 2 -r 0                      -Oqv "${ip}:${SNMP_PORT}"                      SNMPv2-MIB::sysObjectID.0 2>/dev/null | tr -d ' 
' || true)
    case "$sysoid" in
        *.1.3.6.1.4.1.41112.*|*.1.3.6.1.4.1.2011.*|*.1.3.6.1.4.1.14988.*)
            printf 'ap'; return ;;   # Ubiquiti, Huawei WLAN, MikroTik
    esac

    printf ''
}

# ── JSON escaping ─────────────────────────────────────────────────────────────
json_esc() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    printf '%s' "$s"
}

# ── Find dnsmasq leases ───────────────────────────────────────────────────────
find_leases() {
    local candidates=(
        "/var/lib/misc/dnsmasq.leases"
        "/var/lib/dnsmasq/dnsmasq.leases"
        "/var/run/dnsmasq/dnsmasq.leases"
        "/var/run/bonding/dnsmasq.leases"
        "/tmp/dnsmasq.leases"
    )
    local f
    for f in "${candidates[@]}"; do [[ -f "$f" ]] && printf '%s' "$f" && return; done
    printf ''
}

# ── Main scan ─────────────────────────────────────────────────────────────────
run_scan() {
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    printf '[netman_monitor] Scan started at %s' "$timestamp"
    [[ "${FAST_SCAN}" -eq 1 ]] && printf ' (FAST SCAN — public/private only)' 
    printf '\n'

    check_deps

    local -a hosts=()
    local line ip mac
    while IFS= read -r line; do
        ip=$(printf '%s' "$line" | awk '{print $1}')
        [[ "$ip" == *:* ]] && continue
        printf '%s' "$line" | grep -q 'lladdr' || continue
        mac=$(printf '%s' "$line" | awk '{for(i=1;i<=NF;i++) if($i=="lladdr") print $(i+1)}')
        [[ -z "$mac" ]] && continue
        hosts+=("${ip} ${mac}")
    done < <(ip neighbor show 2>/dev/null | tr -d '\r')

    local total=${#hosts[@]}
    printf '[netman_monitor] %d host(s) found\n' "$total"

    local tmp_snap
    tmp_snap=$(mktemp)
    printf '{\n  "scan_time": "%s",\n  "hosts": [\n' \
        "$(json_esc "$timestamp")" > "${tmp_snap}"

    local idx=0
    local entry vendor latency pingable
    for entry in "${hosts[@]}"; do
        ip=$(printf '%s'  "$entry" | awk '{print $1}')
        mac=$(printf '%s' "$entry" | awk '{print $2}')
        vendor=$(lookup_vendor "$mac")
        latency=$(ping_host "$ip")

        if [[ "$latency" == "unreachable" ]]; then
            pingable="false"; latency=""
        else
            pingable="true"
        fi

        # ── nmap SNMP probe ──────────────────────────────────────────────────
        local snmp_port_state community snmp_ver sys_name sys_descr uptime_str
        local port_status="" printer_info="" device_type="" snmp_tmp
        if snmp_probe "${ip}"; then
            snmp_port_state="open"
            local ver_hint="${SNMP_NMAP_VERSION:-unknown}"
            printf '[netman_monitor] (%d/%d) %s — UDP 161 open (hint: %s) brute-forcing: ' \
                $(( idx + 1 )) "${total}" "${ip}" "$ver_hint"

            snmp_tmp=$(mktemp)
            snmp_scan_host "${ip}" "${snmp_tmp}"

            community=$(cut  -f1 "${snmp_tmp}")
            snmp_ver=$(cut   -f2 "${snmp_tmp}")
            sys_name=$(cut   -f3 "${snmp_tmp}")
            sys_descr=$(cut  -f4 "${snmp_tmp}")
            uptime_str=$(cut -f5 "${snmp_tmp}")
            rm -f "${snmp_tmp}"

            # ── Extra data if we have a working community ────────────────────
            if [[ "$community" != "none" ]]; then
                printf '[netman_monitor]    Fetching port status...\n'
                port_status=$(get_port_status "${ip}" "${community}" "${snmp_ver}")
                printer_info=$(get_printer_info "${ip}" "${community}" "${snmp_ver}")
                device_type=$(detect_device_type "${ip}" "${community}" "${snmp_ver}" \
                                                 "${printer_info}" "${sys_descr}")
            fi
        else
            snmp_port_state="closed"
            community="none"; snmp_ver="none"
            sys_name="N/A"; sys_descr="N/A"; uptime_str="N/A"
            printf '[netman_monitor] (%d/%d) %s — UDP 161 closed, skipping\n' \
                $(( idx + 1 )) "${total}" "${ip}"
        fi

        [[ $idx -gt 0 ]] && printf ',\n' >> "${tmp_snap}"
        cat >> "${tmp_snap}" <<JSONBLOCK
    {
      "ip":           "$(json_esc "$ip")",
      "mac":          "$(json_esc "$mac")",
      "vendor":       "$(json_esc "$vendor")",
      "pingable":      ${pingable},
      "latency":      "$(json_esc "$latency")",
      "snmp_port":    "$(json_esc "$snmp_port_state")",
      "snmp_ver":     "$(json_esc "$snmp_ver")",
      "community":    "$(json_esc "$community")",
      "sys_name":     "$(json_esc "$sys_name")",
      "sys_descr":    "$(json_esc "$sys_descr")",
      "uptime":       "$(json_esc "$uptime_str")",
      "port_status":  "$(json_esc "$port_status")",
      "printer_info": "$(json_esc "$printer_info")",
      "device_type":  "$(json_esc "$device_type")"
    }
JSONBLOCK

        if [[ "$community" != "none" ]]; then
            printf '[netman_monitor]  %-16s FOUND community=%-12s ver=%-4s' \
                "$ip" "$community" "$snmp_ver"
            [[ -n "$device_type" ]] && printf '  [%s]' "$device_type"
            printf '\n'

            # Port up/down/error summary
            if [[ -n "$port_status" ]]; then
                local _up=0 _down=0 _err_ports=0
                local IFS_ORIG="$IFS"
                IFS='|' read -ra _ports <<< "$port_status"
                IFS="$IFS_ORIG"
                for _p in "${_ports[@]}"; do
                    [[ -z "$_p" ]] && continue
                    local _st _ie _oe _id _od
                    _st=$(printf '%s' "$_p" | cut -d'~' -f3)
                    _ie=$(printf '%s' "$_p" | cut -d'~' -f4); _ie=${_ie:-0}
                    _oe=$(printf '%s' "$_p" | cut -d'~' -f5); _oe=${_oe:-0}
                    _id=$(printf '%s' "$_p" | cut -d'~' -f6); _id=${_id:-0}
                    _od=$(printf '%s' "$_p" | cut -d'~' -f7); _od=${_od:-0}
                    [[ "$_st" == "1" ]] && _up=$(( _up + 1 )) || _down=$(( _down + 1 ))
                    local _tot=$(( _ie + _oe + _id + _od ))
                    [[ $_tot -gt 0 ]] && _err_ports=$(( _err_ports + 1 ))
                done
                printf '[netman_monitor]    Ports: %d up  %d down' "$_up" "$_down"
                if [[ $_err_ports -gt 0 ]]; then
                    printf '  |  %d port(s) with errors/discards\n' "$_err_ports"
                else
                    printf '  |  no errors or discards\n'
                fi
            fi
        elif [[ "$snmp_port_state" == "open" ]]; then
            printf '[netman_monitor]  %-16s SNMP open — no community matched\n' "$ip"
        fi

        idx=$(( idx + 1 ))
    done

    printf '\n  ]\n}\n' >> "${tmp_snap}"
    mv "${tmp_snap}" "${SNAPSHOT}"
    printf '[netman_monitor] Snapshot: %s\n' "${SNAPSHOT}"
    printf '[netman_monitor] Communities: %s\n' "${COMMUNITY_STORE}"
    printf '[netman_monitor] Scan complete.\n'
}

# ── Dashboard helpers ─────────────────────────────────────────────────────────

# Render port blocks: green █ = up, red █ = down, consecutive no spaces
render_port_blocks() {
    local port_status="$1"
    [[ -z "$port_status" ]] && printf '%b(no port data)%b' "${DIM}" "${RST}" && return

    local block_str=""
    local IFS_ORIG="$IFS"
    IFS='|' read -ra ports <<< "$port_status"
    IFS="$IFS_ORIG"

    for port in "${ports[@]}"; do
        [[ -z "$port" ]] && continue
        local st
        st=$(printf '%s' "$port" | cut -d'~' -f3)
        if [[ "$st" == "1" ]]; then
            block_str+="${BLK_GRN}"
        else
            block_str+="${BLK_RED}"
        fi
    done
    printf '%s' "$block_str"
}

# Render per-port error/discard counters.
# Checks all four counters: ifInErrors, ifOutErrors, ifInDiscards, ifOutDiscards.
# Prints a warning line for any port with non-zero counts.
# Prints a single green "no errors or discards" confirmation when all ports are clean.
render_port_errors() {
    local port_status="$1"
    [[ -z "$port_status" ]] && return

    local IFS_ORIG="$IFS"
    IFS='|' read -ra ports <<< "$port_status"
    IFS="$IFS_ORIG"

    local any_errors=0
    for port in "${ports[@]}"; do
        [[ -z "$port" ]] && continue
        local name st ie oe id od
        name=$(printf '%s' "$port" | cut -d'~' -f2)
        st=$(printf '%s'   "$port" | cut -d'~' -f3)
        ie=$(printf '%s'   "$port" | cut -d'~' -f4)
        oe=$(printf '%s'   "$port" | cut -d'~' -f5)
        id=$(printf '%s'   "$port" | cut -d'~' -f6)
        od=$(printf '%s'   "$port" | cut -d'~' -f7)
        # Default unset fields to 0
        ie=${ie:-0}; oe=${oe:-0}; id=${id:-0}; od=${od:-0}

        local total=$(( ie + oe + id + od ))
        if [[ $total -gt 0 ]]; then
            any_errors=1
            local st_label
            [[ "$st" == "1" ]] && st_label="${G}up${RST}" || st_label="${R}down${RST}"
            printf '    %b⚠%b %-14s %s' "${Y}" "${RST}" "$name" "$st_label"
            [[ $ie -gt 0 ]] && printf '  %bin-err:%b%d'      "${R}" "${RST}" "$ie"
            [[ $oe -gt 0 ]] && printf '  %bout-err:%b%d'     "${R}" "${RST}" "$oe"
            [[ $id -gt 0 ]] && printf '  %bin-disc:%b%d'     "${Y}" "${RST}" "$id"
            [[ $od -gt 0 ]] && printf '  %bout-disc:%b%d'    "${Y}" "${RST}" "$od"
            printf '\n'
        fi
    done

    if [[ $any_errors -eq 0 ]]; then
        printf '  %b  ✓ No errors or discards on any interface%b\n' "${G}" "${RST}"
    fi
}

# Render printer status, ink/toner supply bars, and paper tray levels.
# Handles S: (supply) and T: (tray) prefixed records from get_printer_info.
# Supply type integers per Printer-MIB: 3=toner 4=wasteToner 5=inkCartridge
#   6=inkRibbon 7=inkCartridgeKit 8=fusers 9=maintenanceKit 17=solidWax
# Level interpretation: positive=remaining  0=empty  -1=unknown  -2=OK/noRestrict
render_printer_supplies() {
    local printer_info="$1"
    [[ -z "$printer_info" ]] && return

    local IFS_ORIG="$IFS"
    IFS='|' read -ra parts <<< "$printer_info"
    IFS="$IFS_ORIG"

    local pstatus="${parts[0]:-unknown}"
    local pstatus_col="${G}"
    [[ "$pstatus" == "stopped"    ]] && pstatus_col="${R}"
    [[ "$pstatus" == "processing" ]] && pstatus_col="${Y}"
    [[ "$pstatus" == unknown*     ]] && pstatus_col="${DIM}"
    printf '  %bPrinter  :%b  status: %b%s%b\n' "${DIM}" "${RST}" "$pstatus_col" "$pstatus" "${RST}"

    # ── make_bar LEVEL MAX — produce a [████░░░░] PCT% string ────────────────
    make_bar() {
        local lv="$1" mx="$2"
        local bar_col="${G}" bar_str pct bar_len empty_len filled="" empty="" b

        # Negative values: -2 = no restriction (treat as full), -1 = unknown
        if [[ "$lv" -eq -2 ]] 2>/dev/null; then
            printf '%b[████████████████████] OK%b' "${G}" "${RST}"; return
        fi
        if [[ "$lv" -lt 0 || "$mx" -le 0 ]] 2>/dev/null; then
            printf '%b[  level unknown    ]%b' "${DIM}" "${RST}"; return
        fi
        pct=$(( lv * 100 / mx ))
        [[ $pct -lt 0   ]] && pct=0
        [[ $pct -gt 100 ]] && pct=100
        bar_len=$(( pct * 20 / 100 ))
        empty_len=$(( 20 - bar_len ))
        for (( b=0; b<bar_len;   b++ )); do filled+='█'; done
        for (( b=0; b<empty_len; b++ )); do empty+='░'; done
        [[ $pct -lt 20 ]] && bar_col="${R}"
        [[ $pct -lt 40 && $pct -ge 20 ]] && bar_col="${Y}"
        printf '%b[%s%s] %3d%%%b' "$bar_col" "$filled" "$empty" "$pct" "${RST}"
    }

    local i
    for (( i=1; i<${#parts[@]}; i++ )); do
        local part="${parts[$i]}"
        [[ -z "$part" ]] && continue
        local prefix="${part:0:2}"

        if [[ "$prefix" == "S:" ]]; then
            # Supply record: S:idx~desc~level~max~type
            local rec="${part:2}"
            local sname slevel smax stype
            sname=$(printf '%s'  "$rec" | cut -d'~' -f2)
            slevel=$(printf '%s' "$rec" | cut -d'~' -f3)
            smax=$(printf '%s'   "$rec" | cut -d'~' -f4)
            stype=$(printf '%s'  "$rec" | cut -d'~' -f5)

            local type_label
            case "$stype" in
                3)  type_label="toner"    ;;
                4)  type_label="waste"    ;;
                5)  type_label="ink"      ;;
                6)  type_label="ribbon"   ;;
                7)  type_label="cart-kit" ;;
                8)  type_label="fuser"    ;;
                9)  type_label="maint"    ;;
                17) type_label="wax"      ;;
                *)  type_label="supply"   ;;
            esac

            # Truncate supply name to 30 chars for consistent column alignment
            local sname_trunc
            sname_trunc=$(printf '%.30s' "$sname")
            printf '  %b  %-8s %-30s %b' "${DIM}" "$type_label" "$sname_trunc" "${RST}"
            make_bar "$slevel" "$smax"
            printf '\n'

        elif [[ "$prefix" == "T:" ]]; then
            # Tray record: T:idx~name~level
            local rec="${part:2}"
            local tname tlevel
            tname=$(printf '%s'  "$rec" | cut -d'~' -f2)
            tlevel=$(printf '%s' "$rec" | cut -d'~' -f3)

            # Tray level: 0=empty  positive=sheets  -2=unknown/full  -3=empty(some models)
            local tray_col="${G}" tray_str
            if [[ "$tlevel" -eq 0 || "$tlevel" -eq -3 ]] 2>/dev/null; then
                tray_col="${R}"; tray_str="EMPTY"
            elif [[ "$tlevel" -lt 0 ]] 2>/dev/null; then
                tray_col="${DIM}"; tray_str="unknown"
            else
                tray_str="${tlevel} sheets"
            fi
            # Truncate tray name to 30 chars — same column width as supplies
            local tname_trunc
            tname_trunc=$(printf '%.30s' "$tname")
            printf '  %b  %-8s %-30s %b%s%b\n' \
                "${DIM}" "tray" "$tname_trunc" "$tray_col" "$tray_str" "${RST}"
        fi
    done
}

# ── CLI Dashboard ─────────────────────────────────────────────────────────────
show_dashboard() {
    if [[ ! -f "${SNAPSHOT}" ]]; then
        printf '%bNo snapshot found.%b  Run: %s\n' "${R}" "${RST}" "$(basename "$0")"
        exit 1
    fi

    # ── Parse snapshot ────────────────────────────────────────────────────────
    declare -a d_ip d_mac d_vendor d_ping d_lat d_snmpport d_snmpver \
               d_community d_sysname d_descr d_uptime d_portstatus d_printerinfo d_devicetype
    local scan_time="" idx=-1 in_hosts=0 line

    while IFS= read -r line; do
        line=$(printf '%s' "$line" | sed 's/^[[:space:]]*//')

        if [[ "$line" =~ \"scan_time\"[[:space:]]*:[[:space:]]*\"([^\"]+)\" ]];
            then scan_time="${BASH_REMATCH[1]}"; fi
        if [[ "$line" =~ \"hosts\"[[:space:]]*:[[:space:]]*\[ ]]; then in_hosts=1; fi
        if [[ $in_hosts -eq 1 && "$line" == "{" ]]; then idx=$(( idx + 1 )); continue; fi

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
        if [[ "$line" =~ \"snmp_port\"[[:space:]]*:[[:space:]]*\"([^\"]*)\" ]];
            then d_snmpport[$idx]="${BASH_REMATCH[1]}"; fi
        if [[ "$line" =~ \"snmp_ver\"[[:space:]]*:[[:space:]]*\"([^\"]*)\" ]];
            then d_snmpver[$idx]="${BASH_REMATCH[1]}"; fi
        if [[ "$line" =~ \"community\"[[:space:]]*:[[:space:]]*\"([^\"]*)\" ]];
            then d_community[$idx]="${BASH_REMATCH[1]}"; fi
        if [[ "$line" =~ \"sys_name\"[[:space:]]*:[[:space:]]*\"([^\"]*)\" ]];
            then d_sysname[$idx]="${BASH_REMATCH[1]}"; fi
        if [[ "$line" =~ \"sys_descr\"[[:space:]]*:[[:space:]]*\"([^\"]*)\" ]];
            then d_descr[$idx]="${BASH_REMATCH[1]}"; fi
        if [[ "$line" =~ \"uptime\"[[:space:]]*:[[:space:]]*\"([^\"]*)\" ]];
            then d_uptime[$idx]="${BASH_REMATCH[1]}"; fi
        if [[ "$line" =~ \"port_status\"[[:space:]]*:[[:space:]]*\"([^\"]*)\" ]];
            then d_portstatus[$idx]="${BASH_REMATCH[1]}"; fi
        if [[ "$line" =~ \"printer_info\"[[:space:]]*:[[:space:]]*\"([^\"]*)\" ]];
            then d_printerinfo[$idx]="${BASH_REMATCH[1]}"; fi
        if [[ "$line" =~ \"device_type\"[[:space:]]*:[[:space:]]*\"([^\"]*)\" ]];
            then d_devicetype[$idx]="${BASH_REMATCH[1]}"; fi
    done < "${SNAPSHOT}"

    local total=$(( idx + 1 ))

    # ── Migrate stale port_status records from old buggy parser ───────────────
    # Old code stored "up(1)"/"down(2)" as the status field instead of "1"/"2".
    # Fix any such records in-memory before rendering so a re-scan isn't required.
    local i
    for (( i=0; i<total; i++ )); do
        local ps="${d_portstatus[$i]:-}"
        [[ -z "$ps" ]] && continue
        if printf '%s' "$ps" | grep -qE 'up\([0-9]+\)|down\([0-9]+\)'; then
            d_portstatus[$i]=$(printf '%s' "$ps" | \
                sed 's/~up([0-9][0-9]*)~/~1~/g;  s/~up([0-9][0-9]*)$/~1/g;
                     s/~down([0-9][0-9]*)~/~2~/g; s/~down([0-9][0-9]*)$/~2/g')
        fi
    done

    local online=0 offline=0 snmp_ok=0 snmp_open_no_comm=0
    for (( i=0; i<total; i++ )); do
        [[ "${d_ping[$i]:-false}" == "true" ]] && \
            online=$(( online + 1 )) || offline=$(( offline + 1 ))
        if [[ "${d_community[$i]:-none}" != "none" ]]; then
            snmp_ok=$(( snmp_ok + 1 ))
        elif [[ "${d_snmpport[$i]:-closed}" == "open" ]]; then
            snmp_open_no_comm=$(( snmp_open_no_comm + 1 ))
        fi
    done

    # dnsmasq leases
    local LEASES_FILE
    LEASES_FILE=$(find_leases)
    declare -A lease_name
    local has_leases=0
    if [[ -n "$LEASES_FILE" ]]; then
        has_leases=1
        local lline l_mac l_name
        while IFS= read -r lline; do
            [[ -z "$lline" ]] && continue
            l_mac=$(printf '%s'  "$lline" | awk '{print tolower($2)}')
            l_name=$(printf '%s' "$lline" | awk '{print $4}')
            [[ "$l_name" == "*" ]] && l_name=""
            [[ -n "$l_mac" && -n "$l_name" ]] && lease_name["$l_mac"]="$l_name"
        done < "$LEASES_FILE"
    fi

    # Sort by IP
    local -a sorted_idx=()
    local si
    while IFS= read -r si; do sorted_idx+=("$si"); done < <(
        for (( i=0; i<total; i++ )); do
            local padded
            padded=$(printf '%s' "${d_ip[$i]}" | \
                awk -F. '{printf "%03d.%03d.%03d.%03d",$1,$2,$3,$4}')
            printf '%s\t%d\n' "$padded" "$i"
        done | sort | awk -F'\t' '{print $2}'
    )

    local tw
    tw=$(tput cols 2>/dev/null || printf '140')

    # ── Header ────────────────────────────────────────────────────────────────
    clear
    printf '%b' "${C}"; draw_line '═' "$tw" | tr -d '\n'; printf '%b\n' "${RST}"
    printf '%b NETMAN NETWORK MONITOR%b  %b│%b  SNMP v1/v2c  ·  last scan: %s%b' \
        "${BLD}${C}" "${RST}${C}" "${DIM}" "${RST}${C}" "$scan_time" "${RST}"
    printf '%*s\n' $(( tw - 65 )) \
        "$(printf '%b%s%b' "${DIM}" "$(date '+%Y-%m-%d %H:%M:%S')" "${RST}")"
    printf '%b' "${C}"; draw_line '─' "$tw" | tr -d '\n'; printf '%b\n' "${RST}"
    printf '  %bScanned:%b %b%d%b  %bOnline:%b %b%d%b  %bOffline:%b %b%d%b  %bSNMP OK:%b %b%d%b  %bSNMP open/no-comm:%b %b%d%b\n' \
        "${BLD}" "${RST}" "${C}"  "$total"            "${RST}" \
        "${BLD}" "${RST}" "${G}"  "$online"           "${RST}" \
        "${BLD}" "${RST}" "${R}"  "$offline"          "${RST}" \
        "${BLD}" "${RST}" "${M}"  "$snmp_ok"          "${RST}" \
        "${BLD}" "${RST}" "${Y}"  "$snmp_open_no_comm" "${RST}"
    printf '%b' "${C}"; draw_line '─' "$tw" | tr -d '\n'; printf '%b\n' "${RST}"

    # ── Section A: SNMP-responsive devices (community found) ─────────────────
    local has_snmp=0
    for i in "${sorted_idx[@]}"; do
        [[ "${d_community[$i]:-none}" != "none" ]] && { has_snmp=1; break; }
    done

    if [[ $has_snmp -eq 1 ]]; then
        printf '%b SNMP DEVICES%b\n' "${BLD}${M}" "${RST}"
        printf '%b' "${C}"; draw_line '─' "$tw" | tr -d '\n'; printf '%b\n' "${RST}"

        for i in "${sorted_idx[@]}"; do
            local community="${d_community[$i]:-none}"
            [[ "$community" == "none" ]] && continue

            local ip="${d_ip[$i]:-}"        mac="${d_mac[$i]:-}"
            local vendor="${d_vendor[$i]:-Unknown}"
            local pingable="${d_ping[$i]:-false}"
            local lat="${d_lat[$i]:-}"
            local sys_name="${d_sysname[$i]:-N/A}"
            local sys_descr="${d_descr[$i]:-N/A}"
            local uptime="${d_uptime[$i]:-unknown}"
            local snmp_ver="${d_snmpver[$i]:-}"
            local port_status="${d_portstatus[$i]:-}"
            local printer_info="${d_printerinfo[$i]:-}"
            local device_type="${d_devicetype[$i]:-}"

            local mac_lower hostname=""
            mac_lower=$(printf '%s' "$mac" | tr '[:upper:]' '[:lower:]')
            [[ $has_leases -eq 1 && -n "$mac_lower" ]] && \
                hostname="${lease_name[$mac_lower]:-}"
            [[ -z "$hostname" ]] && hostname="${sys_name}"

            local status_str status_col
            [[ "$pingable" == "true" ]] && \
                { status_str="● ONLINE "; status_col="${G}${BLD}"; } || \
                { status_str="○ OFFLINE"; status_col="${R}"; }

            local lat_col="${DIM}"
            if [[ -n "$lat" ]]; then
                local lat_num="${lat%ms}"
                if   awk "BEGIN{exit !($lat_num+0 <  5)}" 2>/dev/null; then lat_col="${G}"
                elif awk "BEGIN{exit !($lat_num+0 < 50)}" 2>/dev/null; then lat_col="${Y}"
                else lat_col="${R}"; fi
            fi

            local ver_label=""
            [[ -n "$snmp_ver" && "$snmp_ver" != "none" ]] && ver_label="(${snmp_ver})"

            # Device type badge
            local type_badge=""
            case "${device_type}" in
                printer) type_badge=" ${BLD}${M}[PRINTER]${RST}" ;;
                ap)      type_badge=" ${BLD}${C}[AP]${RST}"      ;;
            esac

            printf '%b' "${C}"; draw_line '─' "$tw" | tr -d '\n'; printf '%b\n' "${RST}"

            # Row 1: IP · MAC · vendor · hostname · latency · status · [type badge]
            printf '  %b%-16s%b  %b%-17s%b  %-28s  %b%-20s%b  %b%-10s%b  %b%s%b%b\n' \
                "${BLD}${C}" "$ip" "${RST}" \
                "${DIM}" "$mac" "${RST}" \
                "$vendor" \
                "${Y}" "$hostname" "${RST}" \
                "$lat_col" "${lat:--}" "${RST}" \
                "$status_col" "$status_str" "${RST}" \
                "$type_badge"

            # Row 2: community + version + sysName
            printf '  %bCommunity:%b %b%-14s%b%b%-6s%b  %bsysName:%b %b%s%b\n' \
                "${DIM}" "${RST}" "${M}${BLD}" "$community" "${RST}" \
                "${DIM}" "$ver_label" "${RST}" \
                "${DIM}" "${RST}" "${Y}" "$sys_name" "${RST}"

            # Row 3: sysDescr
            printf '  %bsysDescr :%b %s\n' "${DIM}" "${RST}" "$sys_descr"

            # Row 4: Uptime
            printf '  %bUptime   :%b %b%s%b\n' \
                "${DIM}" "${RST}" "${G}${BLD}" "$uptime" "${RST}"

            # Row 5: Interface port status blocks
            if [[ -n "$port_status" ]]; then
                printf '  %bPorts    :%b ' "${DIM}" "${RST}"
                render_port_blocks "$port_status"
                printf '\n'
                render_port_errors "$port_status"
            fi

            # Printer section (only if this device is a printer)
            if [[ -n "$printer_info" ]]; then
                render_printer_supplies "$printer_info"
            fi
        done
    fi

    # ── Section B: SNMP port open but no community found ─────────────────────
    local has_unknown=0
    for i in "${sorted_idx[@]}"; do
        [[ "${d_community[$i]:-none}" == "none" && \
           "${d_snmpport[$i]:-closed}" == "open" ]] && { has_unknown=1; break; }
    done

    if [[ $has_unknown -eq 1 ]]; then
        printf '%b' "${C}"; draw_line '─' "$tw" | tr -d '\n'; printf '%b\n' "${RST}"
        printf '%b SNMP PORT OPEN — COMMUNITY UNKNOWN%b\n' "${BLD}${Y}" "${RST}"
        printf '%b' "${C}"; draw_line '─' "$tw" | tr -d '\n'; printf '%b\n' "${RST}"

        for i in "${sorted_idx[@]}"; do
            [[ "${d_community[$i]:-none}" != "none" ]] && continue
            [[ "${d_snmpport[$i]:-closed}" != "open" ]] && continue

            local ip="${d_ip[$i]:-}"    mac="${d_mac[$i]:-}"
            local vendor="${d_vendor[$i]:-Unknown}"
            local pingable="${d_ping[$i]:-false}"
            local lat="${d_lat[$i]:-}"
            local snmp_ver="${d_snmpver[$i]:-unknown}"

            local mac_lower hostname=""
            mac_lower=$(printf '%s' "$mac" | tr '[:upper:]' '[:lower:]')
            [[ $has_leases -eq 1 && -n "$mac_lower" ]] && \
                hostname="${lease_name[$mac_lower]:-N/A}"
            [[ -z "$hostname" ]] && hostname="N/A"

            local status_str status_col
            [[ "$pingable" == "true" ]] && \
                { status_str="● ONLINE "; status_col="${G}${BLD}"; } || \
                { status_str="○ OFFLINE"; status_col="${R}"; }

            local lat_col="${DIM}"
            if [[ -n "$lat" ]]; then
                local lat_num="${lat%ms}"
                if   awk "BEGIN{exit !($lat_num+0 <  5)}" 2>/dev/null; then lat_col="${G}"
                elif awk "BEGIN{exit !($lat_num+0 < 50)}" 2>/dev/null; then lat_col="${Y}"
                else lat_col="${R}"; fi
            fi

            printf '  %b%-16s%b  %b%-17s%b  %-28s  %b%-20s%b  %b%-10s%b  %b%s%b  %bnmap hint: %s%b\n' \
                "${C}" "$ip" "${RST}" \
                "${DIM}" "$mac" "${RST}" \
                "$vendor" \
                "${DIM}" "$hostname" "${RST}" \
                "$lat_col" "${lat:--}" "${RST}" \
                "$status_col" "$status_str" "${RST}" \
                "${Y}" "$snmp_ver" "${RST}"
        done
    fi

    # ── Section C: Known Community Store ─────────────────────────────────────
    printf '%b' "${C}"; draw_line '═' "$tw" | tr -d '\n'; printf '%b\n' "${RST}"
    printf '%b KNOWN SNMP COMMUNITIES%b  %b(%s)%b\n' \
        "${BLD}${M}" "${RST}" "${DIM}" "${COMMUNITY_STORE}" "${RST}"
    printf '%b' "${C}"; draw_line '─' "$tw" | tr -d '\n'; printf '%b\n' "${RST}"

    if [[ -f "${COMMUNITY_STORE}" ]]; then
        printf '  %b%-18s  %-16s  %-6s  %s%b\n' \
            "${BLD}" "IP" "COMMUNITY" "VER" "LAST SEEN" "${RST}"
        printf '  %b%-18s  %-16s  %-6s  %s%b\n' "${DIM}" \
            "──────────────────" "────────────────" "──────" "───────────────────" "${RST}"
        local cs_ip cs_community cs_ver cs_ts
        while IFS='	' read -r cs_ip cs_community cs_ver cs_ts; do
            [[ "$cs_ip" == \#* || -z "$cs_ip" ]] && continue
            if [[ -z "$cs_ts" ]]; then cs_ts="$cs_ver"; cs_ver="v1"; fi
            printf '  %-18s  %b%-16s%b  %b%-6s%b  %b%s%b\n' \
                "$cs_ip" "${M}" "$cs_community" "${RST}" \
                "${C}" "$cs_ver" "${RST}" \
                "${DIM}" "$cs_ts" "${RST}"
        done < "${COMMUNITY_STORE}"
    else
        printf '  %bNo communities stored yet.%b\n' "${DIM}" "${RST}"
    fi

    # ── Footer ────────────────────────────────────────────────────────────────
    printf '%b' "${C}"; draw_line '═' "$tw" | tr -d '\n'; printf '%b\n' "${RST}"
    printf '  %bSnapshot : %s%b\n' "${DIM}" "${SNAPSHOT}" "${RST}"
    printf '  %bComms    : %s%b\n' "${DIM}" "${COMMUNITY_STORE}" "${RST}"
    printf '%b' "${C}"; draw_line '─' "$tw" | tr -d '\n'; printf '%b\n' "${RST}"
}

# ── Help ──────────────────────────────────────────────────────────────────────
show_help() {
    detect_distro
    cat <<EOF
${BLD}netman_monitor.sh${RST} — LAN Network Manager Monitor (SNMP v1/v2c)
Compatible with: Debian 11/12, Ubuntu 20.04+, openSUSE Leap 15.x / Tumbleweed

${BLD}Usage:${RST}
  netman_monitor.sh              Full scan — all ${#SNMP_COMMUNITIES[@]} communities, v1 then v2c
  netman_monitor.sh fastscan     Fast scan — public/private only
  netman_monitor.sh --query      Show CLI dashboard of last run
  netman_monitor.sh --help       Show this help

${BLD}SNMP Detection:${RST}
  1. nmap -sU probes UDP 161 — skips brute-force on closed ports
  2. nmap snmp-info NSE detects version (v1/v2c) to skip wrong-version pass
  3. Cached community+version tried first on repeat scans
  4. Brute-force order: v1 first, v2c second (or single pass if version known)
  5. Each attempt prints ! for progress visibility
  6. Detects interface port up/down status + error counts via IF-MIB
  7. Detects printers via Printer-MIB — shows status + ink/toner levels

${BLD}Dashboard sections:${RST}
  SNMP Devices              — full detail with port status blocks and printer info
  SNMP port open/no-comm    — devices with SNMP open but unknown community
  Known SNMP Communities    — accumulated store with version + timestamp

${BLD}Dependencies:${RST}
  Missing packages installed automatically on first run.
  Debian/Ubuntu : apt-get install -y nmap snmp iproute2 curl
  openSUSE      : zypper install -y nmap net-snmp net-snmp-utils iproute2 curl

${BLD}Cron:${RST}
  0 2 * * * /usr/local/sbin/netman_monitor.sh >> /var/log/netman_monitor.log 2>&1

${BLD}Data:${RST}  ${DATA_DIR}
EOF
}

# ── Argument parsing ──────────────────────────────────────────────────────────
parse_args() {
    case "${1:-}" in
        fastscan|--fastscan)
            FAST_SCAN=1
            run_scan
            ;;
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
            printf 'Unknown option: %s  (try: %s --help)\n' "$1" "$(basename "$0")" >&2
            exit 1
            ;;
    esac
}

parse_args "${1:-}"
