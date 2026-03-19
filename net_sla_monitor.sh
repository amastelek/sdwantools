#!/usr/bin/env bash
# =============================================================================
# net_sla_monitor.sh — Interface Reachability Monitor & SLA Dashboard
# =============================================================================
# Probes every eligible interface IP by pinging PRIMARY_TARGET via -I <ip>.
# If both primary pings fail, falls back to SECONDARY_TARGET.
# Interface is marked UP if any ping to either target succeeded.
#
# Usage:
#   ./net_sla_monitor.sh           — run probes and append results to CSV
#   ./net_sla_monitor.sh query     — print SLA dashboard (no probing)
#
# Crontab (every 20 minutes):
#   */20 * * * * /path/to/net_sla_monitor.sh >> /var/log/net_sla_monitor.log 2>&1
#
# CSV columns:
#   timestamp, interface, local_ip, target_used, ping1_ok, ping2_ok, status
# =============================================================================

set -euo pipefail

# ── Probe targets (edit these) ─────────────────────────────────────────────────
PRIMARY_TARGET="102.219.109.8"
SECONDARY_TARGET="102.219.109.3"

# ── General configuration ──────────────────────────────────────────────────────
CSV_FILE="${HOME}/net_sla_results.csv"
CSV_HEADER="timestamp,interface,local_ip,target_used,ping1_ok,ping2_ok,status"
PING_COUNT=1      # ICMP packets per attempt
PING_TIMEOUT=3    # seconds to wait per attempt
LOG_TAG="net_sla"

# ── Interface inclusion/exclusion rules ────────────────────────────────────────
#
# SKIP_IFACE_PATTERNS: glob patterns matched against the interface name.
# Any interface whose name matches one of these is skipped entirely,
# regardless of what IP it has.
#
# Current exclusions:
#   lo         — loopback
#   tun*       — kernel/OpenVPN/WireGuard tunnel interfaces
#   mtun*      — custom managed-tunnel interfaces
#   gre*       — GRE tunnel interfaces (gre0, gretap0, …)
#   erspan*    — ERSPAN mirror interfaces
#   ifb*       — Intermediate Functional Block (traffic shaping helpers)
#   veth*      — virtual ethernet pairs (container/bridge plumbing)
#   docker*    — Docker bridge/host interfaces
#   virbr*     — libvirt bridge interfaces
#
# To add more, append space-separated glob patterns, e.g. "dummy* bond*"
#
SKIP_IFACE_PATTERNS="lo tun* mtun* gre* gretap* erspan* ifb* veth* docker* virbr*"

# ── IP address exclusion ranges ────────────────────────────────────────────────
#
# SKIP_IP_PREFIXES: any inet address whose dotted-decimal representation
# starts with one of these strings is skipped.  This lets you exclude
# specific management subnets or RFC-1918 ranges you do not want tested.
#
# Current exclusions:
#   127.          — loopback range
#   169.254.      — IPv4 link-local (auto-assigned, not routable)
#   10.207.35.    — management subnet on eth0 (10.207.35.0/29)
#
# Example: to also skip all of 10.0.0.0/8 add "10." to the list.
#
SKIP_IP_PREFIXES="127. 169.254. 10.207.35."

# ── Helpers ────────────────────────────────────────────────────────────────────
ts()  { date '+%Y-%m-%d %H:%M:%S'; }
log() { echo "[$(ts)] [$LOG_TAG] $*"; }

# Return 0 (true) if interface name $1 matches any pattern in SKIP_IFACE_PATTERNS
is_iface_skipped() {
    local name="$1" pat
    for pat in $SKIP_IFACE_PATTERNS; do
        # shellcheck disable=SC2254
        case "$name" in $pat) return 0 ;; esac
    done
    return 1
}

# Return 0 (true) if IP address $1 starts with any prefix in SKIP_IP_PREFIXES
is_ip_skipped() {
    local ip="$1" prefix
    for prefix in $SKIP_IP_PREFIXES; do
        [[ "$ip" == "$prefix"* ]] && return 0
    done
    return 1
}

# Ensure CSV exists with header row
init_csv() {
    if [[ ! -f "$CSV_FILE" ]]; then
        echo "$CSV_HEADER" > "$CSV_FILE"
        log "Created CSV at $CSV_FILE"
    fi
}

# ── Probe mode ─────────────────────────────────────────────────────────────────
do_probe() {
    log "Starting probe  primary=$PRIMARY_TARGET  secondary=$SECONDARY_TARGET"

    local probe_count=0
    local cur_iface=""

    # Parse `ip -4 addr show` line by line.
    #
    # Interface header lines look like:
    #   2: eth0: <FLAGS> mtu ...
    #   87: ppp3768: <FLAGS> mtu ...
    #   11: tun1792: <POINTOPOINT,...> mtu ...        <- will be skipped by name
    #
    # Address lines look like:
    #   inet 45.222.22.83/24 scope global eth3
    #   inet 172.30.4.38 peer 172.30.4.39/32 scope link tun1792
    #
    # We track the current interface name from header lines, then act on
    # each inet line that belongs to a non-skipped interface.

    while IFS= read -r line; do

        # ── Interface header line ──────────────────────────────────────────────
        # Format:  <index>: <name>[@parent]: <flags>
        if [[ "$line" =~ ^[0-9]+:[[:space:]]+([^:@[:space:]]+) ]]; then
            cur_iface="${BASH_REMATCH[1]}"
            continue
        fi

        # ── inet (IPv4) address line ───────────────────────────────────────────
        if [[ "$line" =~ ^[[:space:]]+inet[[:space:]]+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
            local ip="${BASH_REMATCH[1]}"

            # Skip if we haven't seen an interface header yet
            [[ -z "$cur_iface" ]] && continue

            # Skip by interface name
            is_iface_skipped "$cur_iface" && continue

            # Skip by IP prefix
            is_ip_skipped "$ip" && {
                log "Skipping $cur_iface $ip (excluded prefix)"
                continue
            }

            probe_interface "$cur_iface" "$ip"
            (( probe_count++ )) || true
        fi

    done < <(ip -4 addr show 2>/dev/null)

    if (( probe_count == 0 )); then
        log "No eligible interfaces found. Nothing to probe."
    else
        log "Probe complete -- $probe_count interface(s) checked."
    fi
}

# Ping primary target twice via local_ip; fall back to secondary if both fail.
# Log result to CSV.
probe_interface() {
    local iface="$1"
    local local_ip="$2"
    local now
    now=$(ts)

    local target="$PRIMARY_TARGET"
    local ok1=0 ok2=0

    log "Probing $iface ($local_ip) -> $target (primary)"

    ping -c "$PING_COUNT" -W "$PING_TIMEOUT" -I "$local_ip" "$target" \
        > /dev/null 2>&1 && ok1=1 || true

    sleep 1

    ping -c "$PING_COUNT" -W "$PING_TIMEOUT" -I "$local_ip" "$target" \
        > /dev/null 2>&1 && ok2=1 || true

    # Both primary attempts failed — try secondary
    if (( ok1 == 0 && ok2 == 0 )); then
        target="$SECONDARY_TARGET"
        log "  primary failed, trying $target (secondary)"

        ping -c "$PING_COUNT" -W "$PING_TIMEOUT" -I "$local_ip" "$target" \
            > /dev/null 2>&1 && ok1=1 || true

        sleep 1

        ping -c "$PING_COUNT" -W "$PING_TIMEOUT" -I "$local_ip" "$target" \
            > /dev/null 2>&1 && ok2=1 || true
    fi

    # UP = at least one ping to either target replied
    local status="DOWN"
    (( ok1 == 1 || ok2 == 1 )) && status="UP"

    echo "${now},${iface},${local_ip},${target},${ok1},${ok2},${status}" \
        >> "$CSV_FILE"

    log "  target=$target  ping1=$ok1  ping2=$ok2  -> $status"
}

# ── Query / dashboard mode ─────────────────────────────────────────────────────
do_query() {
    if [[ ! -f "$CSV_FILE" ]]; then
        echo "No data at $CSV_FILE -- run probes first."
        exit 0
    fi

    local now_epoch
    now_epoch=$(date +%s)

    awk \
        -v hour_ago="$(( now_epoch - 3600 ))"     \
        -v day_ago="$(( now_epoch  - 86400 ))"    \
        -v month_ago="$(( now_epoch - 2592000 ))" \
        -v now_epoch="$now_epoch"                 \
        -v csv_path="$CSV_FILE"                   \
        -v pri="$PRIMARY_TARGET"                  \
        -v sec="$SECONDARY_TARGET"                \
        '
    BEGIN { FS = "," }
    NR == 1 { next }

    {
        ts_str   = $1
        iface    = $2
        local_ip = $3
        target   = $4
        status   = $7

        cmd = "date -d \"" ts_str "\" +%s 2>/dev/null"
        cmd | getline ts_epoch
        close(cmd)
        ts_epoch += 0

        ip_map[iface]      = local_ip
        target_map[iface]  = target
        last_status[iface] = status
        last_ts[iface]     = ts_str

        if (target == sec) sec_hits[iface]++
        total_rows[iface]++

        if (ts_epoch >= hour_ago)  { h_total[iface]++; if (status=="UP") h_up[iface]++ }
        if (ts_epoch >= day_ago)   { d_total[iface]++; if (status=="UP") d_up[iface]++ }
        if (ts_epoch >= month_ago) { m_total[iface]++; if (status=="UP") m_up[iface]++ }
    }

    function rep(ch, n,   s, i) { s=""; for(i=0;i<n;i++) s=s ch; return s }

    function sla_str(up, tot) {
        if (tot+0 == 0) return "     N/A"
        return sprintf("%7.3f%%", up/tot*100)
    }

    END {
        # W = inner width between the two outer | borders.
        # Row format: | %-12s | %-16s | %-8s | %-9s | %-9s | %-10s | %15s | %11s | %10s |
        # Total row length = 128 chars  =>  W = 128 - 2 = 126
        W = 126
        ts_now = strftime("%Y-%m-%d %H:%M:%S", now_epoch)

        printf "\n"
        printf "+%s+\n", rep("-", W)
        printf "|  %-*s  |\n", W-4, "NETWORK INTERFACE SLA DASHBOARD"
        printf "|  %-*s  |\n", W-4, ("Generated  : " ts_now)
        printf "|  %-*s  |\n", W-4, ("Source     : " csv_path)
        printf "|  %-*s  |\n", W-4, ("Primary    : " pri)
        printf "|  %-*s  |\n", W-4, ("Secondary  : " sec)
        printf "+%s+\n", rep("-", W)

        printf "| %-12s | %-16s | %-8s | %-9s | %-9s | %-10s | %-15s | %-11s | %-10s |\n",
            "INTERFACE", "LOCAL IP", "STATUS", "LAST TGT", "SEC HITS",
            "PROBES 24H", "SLA LAST HOUR", "SLA 24H", "SLA 30D"
        printf "+%s+\n", rep("-", W)

        n = asorti(ip_map, sorted)

        for (i = 1; i <= n; i++) {
            ifc = sorted[i]

            h_str = sla_str(h_up[ifc]+0,  h_total[ifc]+0)
            d_str = sla_str(d_up[ifc]+0,  d_total[ifc]+0)
            m_str = sla_str(m_up[ifc]+0,  m_total[ifc]+0)

            st_lbl   = (last_status[ifc] == "UP") ? "UP  [OK]" : "DOWN[!!]"
            tgt_lbl  = (target_map[ifc] == pri)   ? "primary"  : "secondary"

            sh  = sec_hits[ifc]+0
            tot = total_rows[ifc]+0
            sh_str = (tot > 0) ? sprintf("%d (%.0f%%)", sh, sh/tot*100) : "0"

            printf "| %-12s | %-16s | %-8s | %-9s | %-9s | %-10s | %15s | %11s | %10s |\n",
                ifc, ip_map[ifc], st_lbl, tgt_lbl, sh_str, d_total[ifc]+0, h_str, d_str, m_str
        }

        printf "+%s+\n", rep("-", W)
        printf "\n  Legend:\n"
        printf "    SLA      = (successful probes / total probes) x 100%%\n"
        printf "    N/A      = no probe data in that time window\n"
        printf "    UP       = at least one ping succeeded (primary or secondary target)\n"
        printf "    DOWN     = all pings failed on both targets\n"
        printf "    LAST TGT = target used in the most recent probe cycle\n"
        printf "    SEC HITS = probes that fell back to secondary (primary was unreachable)\n"
        printf "    PROBES 24H = total number of probe cycles run in the past 24 hours\n"
        printf "    Interval = every 20 minutes via cron\n\n"
    }
    ' "$CSV_FILE"
}

# ── Entry point ────────────────────────────────────────────────────────────────
main() {
    local mode="${1:-probe}"
    init_csv

    case "$mode" in
        query|--query|-q) do_query   ;;
        probe|--probe|-p|*) do_probe ;;
    esac
}

main "$@"
