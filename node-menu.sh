#!/usr/bin/env bash
# ================================================
# Node Tools Menu - node-menu.sh (auto-install on openSUSE Leap 15.6 / Debian Buster)
# ================================================

BASTION_CONF="/usr/local/sbin/bastion.conf"

# ------------------------------------------------
# Detect OS
# ------------------------------------------------
is_opensuse_156=false
is_debian_buster=false
if [[ -f /etc/os-release ]]; then
  . /etc/os-release 2>/dev/null
  [[ "$ID" == "opensuse-leap" && "$VERSION_ID" == "15.6" ]] && is_opensuse_156=true
  [[ "$ID" == "debian" && "$VERSION_CODENAME" == "buster" ]] && is_debian_buster=true
fi

# ------------------------------------------------
# Dependency check + auto-install (openSUSE 15.6 / Debian Buster)
# ------------------------------------------------
missing=()
for cmd in whiptail btop speedtest trip tuptime vnstat nmap; do
  command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
done
[[ ! -x /usr/local/sbin/ping_sla.sh ]] && missing+=("ping_sla.sh")
[[ ! -x /usr/local/sbin/ping_speedtest.sh ]] && missing+=("ping_speedtest.sh")
[[ ! -x /usr/local/sbin/listneighbours.sh ]] && missing+=("listneighbours.sh")
[[ ! -x /usr/local/sbin/asn ]] && missing+=("asn")
[[ ! -x /usr/local/sbin/net_sla_monitor.sh ]] && missing+=("net_sla_monitor.sh")
[[ ! -x /usr/local/sbin/lan_monitor.sh ]] && missing+=("lan_monitor.sh")
[[ ! -x /usr/local/sbin/prettyping ]] && missing+=("prettyping")

if [[ ${#missing[@]} -gt 0 && "$is_opensuse_156" == true ]]; then
  echo "=== openSUSE Leap 15.6 detected ==="
  echo "Auto-installing missing dependencies..."

  for dep in "${missing[@]}"; do
    case "$dep" in
      whiptail)
        echo "→ Installing whiptail (newt)"
        sudo zypper install -y newt
        ;;
      btop)
        echo "→ Installing btop"
        sudo zypper install -y btop
        ;;
      trip)
        echo "→ Adding network:utilities repo and installing trippy"
        sudo zypper addrepo -f https://download.opensuse.org/repositories/network:utilities/openSUSE_Leap_15.6/network:utilities.repo
        sudo zypper refresh
        sudo zypper install -y trippy
        ;;
      speedtest)
        echo "→ Installing official Ookla speedtest CLI"
        curl -s https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.rpm.sh | sudo bash
        sudo zypper install -y speedtest
        ;;
      prettyping)
        echo "→ Downloading prettyping to /usr/local/sbin"
        sudo curl -L -o /usr/local/sbin/prettyping https://raw.githubusercontent.com/denilsonsa/prettyping/master/prettyping
        sudo chmod +x /usr/local/sbin/prettyping
        ;;
      ping_sla.sh)
        echo "→ Downloading ping_sla.sh to /usr/local/sbin"
        sudo curl -L -o /usr/local/sbin/ping_sla.sh https://raw.githubusercontent.com/amastelek/sdwantools/refs/heads/main/ping_sla.sh
        sudo chmod +x /usr/local/sbin/ping_sla.sh
        ;;
      tuptime)
        echo "→ Installing tuptime via upstream install script"
        bash < <(curl -Ls https://git.io/tuptime-install.sh)
        ;;
      vnstat)
        echo "→ Installing vnstat"
        sudo zypper install -y vnstat
        echo "→ Enabling and starting vnstatd service"
        sudo systemctl enable vnstatd
        sudo systemctl start vnstatd
        ;;
      ping_speedtest.sh)
        echo "→ Downloading ping_speedtest.sh to /usr/local/sbin"
        sudo curl -L -o /usr/local/sbin/ping_speedtest.sh https://raw.githubusercontent.com/amastelek/sdwantools/refs/heads/main/ping_speedtest.sh
        sudo chmod +x /usr/local/sbin/ping_speedtest.sh
        ;;
      nmap)
        echo "→ Installing nmap"
        sudo zypper install -y nmap
        ;;
      listneighbours.sh)
        echo "→ Downloading listneighbours.sh to /usr/local/sbin"
        sudo curl -L -o /usr/local/sbin/listneighbours.sh https://raw.githubusercontent.com/amastelek/sdwantools/refs/heads/main/listneighbours.sh
        sudo chmod +x /usr/local/sbin/listneighbours.sh
        ;;
      asn)
        echo "→ Installing asn prerequisites"
        sudo zypper in -y curl whois bind-utils mtr jq nmap ncat ipcalc aha grepcidr
        echo "→ Downloading asn to /usr/local/sbin"
        sudo curl -o /usr/local/sbin/asn https://raw.githubusercontent.com/nitefood/asn/master/asn
        sudo chmod 755 /usr/local/sbin/asn
        ;;
      net_sla_monitor.sh)
        echo "→ Downloading net_sla_monitor.sh to /usr/local/sbin"
        sudo curl -L -o /usr/local/sbin/net_sla_monitor.sh https://raw.githubusercontent.com/amastelek/sdwantools/refs/heads/main/net_sla_monitor.sh
        sudo chmod +x /usr/local/sbin/net_sla_monitor.sh
        ;;
      lan_monitor.sh)
        echo "→ Downloading lan_monitor.sh to /usr/local/sbin"
        sudo curl -L -o /usr/local/sbin/lan_monitor.sh https://raw.githubusercontent.com/amastelek/sdwantools/refs/heads/main/lan_monitor.sh
        sudo chmod +x /usr/local/sbin/lan_monitor.sh
        ;;
    esac
  done

  # Re-check after installation
  missing=()
  for cmd in whiptail btop speedtest trip tuptime vnstat nmap; do
    command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
  done
  [[ ! -x /usr/local/sbin/ping_sla.sh ]] && missing+=("ping_sla.sh")
  [[ ! -x /usr/local/sbin/ping_speedtest.sh ]] && missing+=("ping_speedtest.sh")
  [[ ! -x /usr/local/sbin/listneighbours.sh ]] && missing+=("listneighbours.sh")
  [[ ! -x /usr/local/sbin/asn ]] && missing+=("asn")
  [[ ! -x /usr/local/sbin/net_sla_monitor.sh ]] && missing+=("net_sla_monitor.sh")
  [[ ! -x /usr/local/sbin/lan_monitor.sh ]] && missing+=("lan_monitor.sh")
  [[ ! -x /usr/local/sbin/prettyping ]] && missing+=("prettyping")
fi

if [[ ${#missing[@]} -gt 0 && "$is_debian_buster" == true ]]; then
  echo "=== Debian Buster detected ==="
  echo "Auto-installing missing dependencies..."

  for dep in "${missing[@]}"; do
    case "$dep" in
      whiptail)
        echo "→ Installing whiptail"
        sudo apt install -y whiptail
        ;;
      trip)
        echo "→ Installing trippy 0.13.0 musl (.deb)"
        cd /tmp
        wget -q https://github.com/fujiapple852/trippy/releases/download/0.13.0/trippy_x86_64-unknown-linux-musl_0.13.0_amd64.deb
        sudo dpkg -i trippy_x86_64-unknown-linux-musl_0.13.0_amd64.deb
        rm -f /tmp/trippy_x86_64-unknown-linux-musl_0.13.0_amd64.deb
        ;;
      ping_sla.sh)
        echo "→ Downloading ping_sla.sh to /usr/local/sbin"
        sudo curl -L -o /usr/local/sbin/ping_sla.sh https://raw.githubusercontent.com/amastelek/sdwantools/refs/heads/main/ping_sla.sh
        sudo chmod +x /usr/local/sbin/ping_sla.sh
        ;;
      prettyping)
        echo "→ Downloading prettyping to /usr/local/sbin"
        sudo curl -L -o /usr/local/sbin/prettyping https://raw.githubusercontent.com/denilsonsa/prettyping/master/prettyping
        sudo chmod +x /usr/local/sbin/prettyping
        ;;
      ping_speedtest.sh)
        echo "→ Downloading ping_speedtest.sh to /usr/local/sbin"
        sudo curl -L -o /usr/local/sbin/ping_speedtest.sh https://raw.githubusercontent.com/amastelek/sdwantools/refs/heads/main/ping_speedtest.sh
        sudo chmod +x /usr/local/sbin/ping_speedtest.sh
        ;;
      listneighbours.sh)
        echo "→ Downloading listneighbours.sh to /usr/local/sbin"
        sudo curl -L -o /usr/local/sbin/listneighbours.sh https://raw.githubusercontent.com/amastelek/sdwantools/refs/heads/main/listneighbours.sh
        sudo chmod +x /usr/local/sbin/listneighbours.sh
        ;;
      asn)
        echo "→ Downloading asn to /usr/local/bin"
        sudo curl -o /usr/local/bin/asn https://raw.githubusercontent.com/nitefood/asn/master/asn
        sudo chmod +x /usr/local/bin/asn
        ;;
      net_sla_monitor.sh)
        echo "→ Downloading net_sla_monitor.sh to /usr/local/sbin"
        sudo curl -L -o /usr/local/sbin/net_sla_monitor.sh https://raw.githubusercontent.com/amastelek/sdwantools/refs/heads/main/net_sla_monitor.sh
        sudo chmod +x /usr/local/sbin/net_sla_monitor.sh
        ;;
      lan_monitor.sh)
        echo "→ Downloading lan_monitor.sh to /usr/local/sbin"
        sudo curl -L -o /usr/local/sbin/lan_monitor.sh https://raw.githubusercontent.com/amastelek/sdwantools/refs/heads/main/lan_monitor.sh
        sudo chmod +x /usr/local/sbin/lan_monitor.sh
        ;;
    esac
  done

  # Re-check after installation
  missing=()
  for cmd in whiptail btop speedtest trip tuptime vnstat nmap; do
    command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
  done
  [[ ! -x /usr/local/sbin/ping_sla.sh ]] && missing+=("ping_sla.sh")
  [[ ! -x /usr/local/sbin/ping_speedtest.sh ]] && missing+=("ping_speedtest.sh")
  [[ ! -x /usr/local/sbin/listneighbours.sh ]] && missing+=("listneighbours.sh")
  [[ ! -x /usr/local/sbin/asn ]] && missing+=("asn")
  [[ ! -x /usr/local/sbin/net_sla_monitor.sh ]] && missing+=("net_sla_monitor.sh")
  [[ ! -x /usr/local/sbin/lan_monitor.sh ]] && missing+=("lan_monitor.sh")
  [[ ! -x /usr/local/sbin/prettyping ]] && missing+=("prettyping")
fi

# Final check
if [[ ${#missing[@]} -gt 0 ]]; then
  if command -v whiptail >/dev/null 2>&1; then
    whiptail --title "Missing Dependencies" --msgbox \
      "The following tools are still missing:\n\n${missing[*]}\n\nPlease install them manually." \
      14 70
  else
    echo "ERROR: Missing dependencies: ${missing[*]}"
  fi
  exit 1
fi

# ------------------------------------------------
# Crontab check — ensure SLA and speedtest jobs exist
# ------------------------------------------------
CRON_SLA='*/10 * * * *    /usr/local/sbin/ping_sla.sh'
CRON_SPEEDTEST='@daily          /usr/local/sbin/ping_speedtest.sh'
CRON_NETMON='*/20 * * * *    /usr/local/sbin/net_sla_monitor.sh'

_crontab_has() {
  crontab -l 2>/dev/null | grep -qF "$1"
}

_add_cron_entry() {
  local entry="$1"
  local label="$2"
  echo "→ Adding cron entry: $label"
  ( crontab -l 2>/dev/null; echo "$entry" ) | crontab -
}

if ! _crontab_has '/usr/local/sbin/ping_sla.sh'; then
  _add_cron_entry "$CRON_SLA" "ping_sla.sh every 10 minutes"
fi

if ! _crontab_has '/usr/local/sbin/ping_speedtest.sh'; then
  _add_cron_entry "$CRON_SPEEDTEST" "ping_speedtest.sh daily"
fi

if ! _crontab_has '/usr/local/sbin/net_sla_monitor.sh'; then
  _add_cron_entry "$CRON_NETMON" "net_sla_monitor.sh every 20 minutes"
fi

# ------------------------------------------------
# /etc/profile.d/extra.sh — ensure login hook exists
# ------------------------------------------------
EXTRA_SH="/etc/profile.d/extra.sh"
if [[ ! -f "$EXTRA_SH" ]]; then
  echo "→ Creating $EXTRA_SH"
  sudo tee "$EXTRA_SH" > /dev/null <<'PROFILE_EOF'
#!/bin/bash
# Check if current user is root (UID 0)
if [ "$(id -u)" -eq 0 ]; then
    /usr/local/sbin/node-menu.sh
else
    neofetch --ascii "$(figlet -f slant NN)" --cpu_display mode barinfo --memory_display barinfo --disk_display barinfo --cpu_temp C
fi
PROFILE_EOF
  sudo chmod +x "$EXTRA_SH"
fi

# ------------------------------------------------
# Helpers (unchanged)
# ------------------------------------------------
choose_source_ip() {
  local menu=()
  while IFS= read -r line; do
    local iface ip
    iface="${line%% *}"
    ip="${line#* }"
    [[ -z "$ip" || "$ip" == 127.* || "$ip" == ::* ]] && continue
    menu+=("$ip" "$iface → $ip")
  done < <(ip -4 -o addr show up | awk '{gsub("/.*", "", $4); print $2 " " $4}' | grep -v '^lo ')

  if [[ ${#menu[@]} -eq 0 ]]; then
    whiptail --title "Error" --msgbox "No IPv4 addresses found!" 10 60
    return
  fi

  local choice
  choice=$(whiptail --title "Speedtest Source IP" \
    --menu "Select interface & IP:" \
    18 75 10 "${menu[@]}" 3>&1 1>&2 2>&3)
  echo "$choice"
}

choose_interface() {
  local title="${1:-Select Interface}"
  local menu=()
  # Only list interfaces that are up AND have an IPv4 address assigned
  while IFS= read -r line; do
    local iface ip
    iface="${line%% *}"
    ip="${line#* }"
    [[ -z "$iface" || -z "$ip" ]] && continue
    menu+=("$iface" "$iface ($ip)")
  done < <(ip -4 -o addr show up | awk '{gsub("/.*", "", $4); print $2 " " $4}' | grep -v '^lo ')

  if [[ ${#menu[@]} -eq 0 ]]; then
    whiptail --title "Error" --msgbox "No interfaces with an IPv4 address found!" 10 60
    return
  fi

  local choice
  choice=$(whiptail --title "$title" \
    --menu "Choose interface:" \
    15 60 8 "${menu[@]}" 3>&1 1>&2 2>&3)
  echo "$choice"
}

# ------------------------------------------------
# New: SLA / System Reports Submenu
# ------------------------------------------------
do_reports_submenu() {
  while true; do
    local choice
    choice=$(whiptail --title "System & SLA Reports" \
      --menu "Select report to view:" \
      20 80 10 \
      "neofetch"       "System information overview" \
      "df"             "Disk usage (human readable)" \
      "tuptime"        "Detailed uptime history" \
      "vnstat"         "Network traffic statistics" \
      "sla"            "SLA ping report (query=sla)" \
      "speedtest_hist" "Speedtest history (query=speedtest)" \
      "net_sla"        "Network SLA monitor report" \
      "lan_mon"        "LAN monitor report" \
      "Back"           "Return to main menu" \
      3>&1 1>&2 2>&3)

    case "$choice" in
      neofetch)
        clear
        echo "=== System Information (neofetch) ==="
        echo "====================================="
        neofetch
        echo
        echo "Press Enter to return..."
        read -r
        ;;
      df)
        clear
        echo "=== Disk Usage (df -h) ==="
        echo "========================="
        df -h
        echo
        echo "Press Enter to return..."
        read -r
        ;;
      tuptime)
        clear
        echo "=== Uptime History (tuptime) ==="
        echo "================================"
        tuptime
        echo
        echo "Press Enter to return..."
        read -r
        ;;
      vnstat)
        clear
        echo "=== Network Traffic (vnstat) ==="
        echo "================================"
        vnstat
        echo
        echo "Press Enter to return..."
        read -r
        ;;
      sla)
        clear
        echo "=== SLA Ping Report ==="
        echo "======================"
        /usr/local/sbin/ping_sla.sh query=sla
        echo
        echo "Press Enter to return..."
        read -r
        ;;
      speedtest_hist)
        clear
        echo "=== Speedtest History ==="
        echo "========================="
        /usr/local/sbin/ping_sla.sh query=speedtest
        echo
        echo "Press Enter to return..."
        read -r
        ;;
      nft)
        clear
        echo "=== Firewall Ruleset (nft list ruleset) ==="
        echo "=========================================="
        sudo nft list ruleset
        echo
        echo "Press Enter to return..."
        read -r
        ;;
      nft)
        clear
        echo "=== nftables Ruleset (nft list ruleset) ==="
        echo "=========================================="
        nft list ruleset
        echo
        echo "Press Enter to return..."
        read -r
        ;;
      nft)
        clear
        echo "=== nftables Ruleset (nft list ruleset) ==="
        echo "=========================================="
        nft list ruleset
        echo
        echo "Press Enter to return..."
        read -r
        ;;
      nft)
        clear
        echo "=== Firewall Ruleset (nft list ruleset) ==="
        echo "=========================================="
        sudo nft list ruleset
        echo
        echo "Press Enter to return..."
        read -r
        ;;
      nft)
        clear
        echo "=== nftables Ruleset (nft list ruleset) ==="
        echo "=========================================="
        sudo nft list ruleset
        echo
        echo "Press Enter to return..."
        read -r
        ;;
      nft)
        clear
        echo "=== nftables Ruleset (nft list ruleset) ==="
        echo "=========================================="
        nft list ruleset
        echo
        echo "Press Enter to return..."
        read -r
        ;;
      nft)
        clear
        echo "=== nftables Ruleset (nft list ruleset) ==="
        echo "=========================================="
        nft list ruleset
        echo
        echo "Press Enter to return..."
        read -r
        ;;
      nft)
        clear
        echo "=== Firewall Ruleset (nft list ruleset) ==="
        echo "=========================================="
        sudo nft list ruleset
        echo
        echo "Press Enter to return..."
        read -r
        ;;
      nft)
        clear
        echo "=== nftables Ruleset (nft list ruleset) ==="
        echo "=========================================="
        sudo nft list ruleset
        echo
        echo "Press Enter to return..."
        read -r
        ;;
      nft)
        clear
        echo "=== nftables Ruleset (nft list ruleset) ==="
        echo "=========================================="
        sudo nft list ruleset
        echo
        echo "Press Enter to return..."
        read -r
        ;;
      vulners)
        local vtarget
        vtarget=$(whiptail --title "Nmap Vulners Scan" \
          --inputbox "Enter target hostname or IP to scan:" \
          10 60 "" 3>&1 1>&2 2>&3)
        [[ -z "$vtarget" ]] && continue
        clear
        echo "=== Nmap Vulners Scan: $vtarget ==="
        echo "===================================="
        echo "Running: nmap -sV --script vulners $vtarget"
        echo "(this may take a moment)"
        echo
        sudo nmap -sV --script vulners "$vtarget"
        echo
        echo "Press Enter to return..."
        read -r
        ;;
      asn)
        local atarget
        atarget=$(whiptail --title "ASN Lookup / Trace" \
          --inputbox "Enter target hostname or IP:" \
          10 60 "" 3>&1 1>&2 2>&3)
        [[ -z "$atarget" ]] && continue
        clear
        echo "=== ASN Lookup: $atarget ==="
        echo "============================"
        /usr/local/sbin/asn "$atarget"
        echo
        echo "Press Enter to return..."
        read -r
        ;;

      net_sla)
        clear
        echo "=== Network SLA Monitor Report ==="
        echo "================================="
        /usr/local/sbin/net_sla_monitor.sh query
        echo
        echo "Press Enter to return..."
        read -r
        ;;
      lan_mon)
        clear
        echo "=== LAN Monitor Report ==="
        echo "========================="
        /usr/local/sbin/lan_monitor.sh query
        echo
        echo "Press Enter to return..."
        read -r
        ;;
      Back|"")
        return
        ;;
      *)
        whiptail --title "Error" --msgbox "Invalid selection" 8 40
        ;;
    esac
  done
}

# ------------------------------------------------
# Menu actions
# ------------------------------------------------
do_btop() { clear; btop; }

do_speedtest() {
  local ip
  ip=$(choose_source_ip)
  [[ -z "$ip" ]] && return
  clear
  echo "Running Ookla Speedtest bound to IP: $ip"
  echo "=============================================="
  speedtest --ip "$ip"
  echo
  echo "Press Enter to return..."
  read -r
}

# ------------------------------------------------
# Traces — prompt for target, show forward + backward loss
# ------------------------------------------------
do_traces() {
  # Step 1: choose interface
  local int
  int=$(choose_interface "Trace Interface")
  [[ -z "$int" ]] && return

  # Step 2: prompt for target with default
  local target
  target=$(whiptail --title "Trippy Trace Target" \
    --inputbox "Enter target hostname or IP:" \
    10 60 "1.1.1.1" 3>&1 1>&2 2>&3)
  [[ -z "$target" ]] && return

  clear
  echo "Launching Trippy trace to $target on $int"
  echo "  Columns: default + Fwd loss (F), Bwd loss (B), Fwd loss% (D)"
  echo "=============================================="
  echo "Exit with 'q'"
  # --tui-custom-columns appends F (forward loss count),
  # B (backward loss count), and D (forward loss %) to the
  # standard column set — these are the native bidir-loss
  # heuristics introduced in Trippy 0.12 / present in 0.13.
  trip --interface "$int" \
       --tui-custom-columns holsravbwdtFBD \
       --first-ttl 2 \
       --tcp \
       "$target"
}

# ------------------------------------------------
# Bastion — prompt for user and port before SSH
# ------------------------------------------------
do_bastion() {
  if [[ ! -f "$BASTION_CONF" ]]; then
    whiptail --title "Error" --msgbox "Bastion config not found!\nExpected: $BASTION_CONF" 12 70
    return
  fi

  local menu=()
  while IFS='|' read -r host desc || [[ -n "$host" ]]; do
    [[ "$host" =~ ^[[:space:]]*# ]] && continue
    [[ -z "${host//[[:space:]]/}" ]] && continue
    menu+=("$host" "${desc:-$host}")
  done < "$BASTION_CONF"

  [[ ${#menu[@]} -eq 0 ]] && { whiptail --title "Error" --msgbox "No hosts in bastion.conf" 10 60; return; }

  # Prepend an Edit option to the host list
  local all_menu=("__edit__" "── Edit bastion.conf in nano ──" "${menu[@]}")

  # Step 1: choose host or edit config
  local choice
  choice=$(whiptail --title "Bastion Hosts" \
    --menu "Select host to SSH or edit config:" 20 80 12 "${all_menu[@]}" 3>&1 1>&2 2>&3)
  [[ -z "$choice" ]] && return

  # Handle edit selection
  if [[ "$choice" == "__edit__" ]]; then
    clear
    echo "Opening $BASTION_CONF in nano..."
    echo "=============================================="
    nano "$BASTION_CONF"
    return
  fi

  # Step 2: prompt for username (default: root)
  local ssh_user
  ssh_user=$(whiptail --title "SSH Username" \
    --inputbox "Enter SSH username for $choice:" \
    10 60 "root" 3>&1 1>&2 2>&3)
  [[ -z "$ssh_user" ]] && return

  # Step 3: prompt for port (default: 22)
  local ssh_port
  ssh_port=$(whiptail --title "SSH Port" \
    --inputbox "Enter SSH port for $choice:" \
    10 60 "22" 3>&1 1>&2 2>&3)
  [[ -z "$ssh_port" ]] && return

  clear
  echo "Connecting: ssh -p $ssh_port ${ssh_user}@${choice}"
  echo "=============================================="
  ssh -p "$ssh_port" "${ssh_user}@${choice}"
}

do_extended_ping() {
  local host
  host=$(whiptail --title "Extended Ping" \
    --inputbox "Enter hostname or IP:" 10 60 "" 3>&1 1>&2 2>&3)
  [[ -z "$host" ]] && return

  clear
  echo "Probing $host with 10 pings to auto-calculate RTT thresholds..."
  local ping_output avg rttmin=0 rttmax=0
  ping_output=$(ping -c 10 -q -W 2 "$host" 2>&1)
  if echo "$ping_output" | grep -q "rtt min/avg"; then
    avg=$(echo "$ping_output" | awk -F'/' '/rtt/ {print $5}')
    rttmin=$(awk "BEGIN {printf \"%.0f\", $avg * 0.8}")
    rttmax=$(awk "BEGIN {printf \"%.0f\", $avg * 1.2}")
    # Ensure rttmax is never below 10ms (e.g. sub-ms LAN results)
    [[ $rttmax -lt 10 ]] && rttmax=10
  fi

  clear
  if [[ $rttmin -gt 0 && $rttmax -gt 0 ]]; then
    echo "Pretty-pinging $host (auto thresholds: min=${rttmin}ms, max=${rttmax}ms)"
    echo "=============================================="
    /usr/local/sbin/prettyping --rttmin "$rttmin" --rttmax "$rttmax" "$host"
  else
    echo "Pretty-pinging $host (could not calibrate thresholds)"
    echo "=============================================="
    /usr/local/sbin/prettyping "$host"
  fi
  echo
  echo "Press Enter to return to menu (or Ctrl+C to stop prettyping)..."
  read -r
}

# ------------------------------------------------
# Node Diagnostics Submenu
# ------------------------------------------------
do_node_diagnostics() {
  while true; do
    local choice
    choice=$(whiptail --title "Node Diagnostics" \
      --menu "Select diagnostic to run:" \
      22 80 10 \
      "bondlog"    "Bond log - last 100 entries" \
      "juggler"    "Juggler service log - last 100 entries (current boot)" \
      "dmesg"      "Kernel ring buffer (dmesg)" \
      "neighbours" "List network neighbours (ARP/NDP)" \
      "nft"        "Firewall ruleset (nft list ruleset)" \
      "vulners"    "Nmap vulners scan (input host)" \
      "asn"        "ASN lookup / trace (input host)" \
      "ethtool"    "Interface statistics (ethtool -S)" \
      "Back"       "Return to main menu" \
      3>&1 1>&2 2>&3)

    case "$choice" in
      bondlog)
        clear
        echo "=== Bond Log (last 100 entries) ==="
        echo "==================================="
        bondlog -n 100
        echo
        echo "Press Enter to return..."
        read -r
        ;;
      juggler)
        clear
        echo "=== Juggler Service Log (last 100, current boot) ==="
        echo "===================================================="
        journalctl -u juggler -n 100 -b --no-pager
        echo
        echo "Press Enter to return..."
        read -r
        ;;
      dmesg)
        clear
        echo "=== Kernel Ring Buffer (dmesg) ==="
        echo "=================================="
        dmesg
        echo
        echo "Press Enter to return..."
        read -r
        ;;
      neighbours)
        clear
        echo "=== Network Neighbours (listneighbours) ==="
        echo "=========================================="
        /usr/local/sbin/listneighbours.sh
        echo
        echo "Press Enter to return..."
        read -r
        ;;
      nft)
        clear
        echo "=== Firewall Ruleset (nft list ruleset) ==="
        echo "=========================================="
        sudo nft list ruleset
        echo
        echo "Press Enter to return..."
        read -r
        ;;
      vulners)
        local vtarget
        vtarget=$(whiptail --title "Nmap Vulners Scan" \
          --inputbox "Enter target hostname or IP to scan:" \
          10 60 "" 3>&1 1>&2 2>&3)
        [[ -z "$vtarget" ]] && continue
        clear
        echo "=== Nmap Vulners Scan: $vtarget ==="
        echo "===================================="
        echo "Running: sudo nmap -sV --script vulners $vtarget"
        echo "(this may take a moment)"
        echo
        sudo nmap -sV --script vulners "$vtarget"
        echo
        echo "Press Enter to return..."
        read -r
        ;;
      asn)
        local atarget
        atarget=$(whiptail --title "ASN Lookup / Trace" \
          --inputbox "Enter target hostname or IP:" \
          10 60 "" 3>&1 1>&2 2>&3)
        [[ -z "$atarget" ]] && continue
        clear
        echo "=== ASN Lookup: $atarget ==="
        echo "============================"
        /usr/local/sbin/asn "$atarget"
        echo
        echo "Press Enter to return..."
        read -r
        ;;
      ethtool)
        local eth_menu=()
        # Physical Ethernet only — exclude virtual types: gretap, erspan, br*, ifb*
        while IFS= read -r iface; do
          eth_menu+=("$iface" "$iface")
        done < <(ip -o link show \
                   | awk '/link\/ether/ {gsub(/:$/, "", $2); print $2}' \
                   | grep -Ev '^(gretap|erspan|br|ifb)')

        if [[ ${#eth_menu[@]} -eq 0 ]]; then
          whiptail --title "Error" --msgbox "No Ethernet interfaces found!" 10 60
          continue
        fi

        local eif
        eif=$(whiptail --title "ethtool Statistics" \
          --menu "Select Ethernet interface to inspect:" \
          18 60 8 "${eth_menu[@]}" 3>&1 1>&2 2>&3)
        [[ -z "$eif" ]] && continue
        clear
        echo "=== ethtool -S $eif ==="
        echo "========================"
        sudo ethtool -S "$eif"
        echo
        echo "Press Enter to return..."
        read -r
        ;;
      Back|"")
        return
        ;;
      *)
        whiptail --title "Error" --msgbox "Invalid selection" 8 40
        ;;
    esac
  done
}

# ------------------------------------------------
# Main menu
# ------------------------------------------------
while true; do
  choice=$(whiptail --title "Node Tools Menu" \
    --menu "Select an option:" \
    20 75 9 \
    "btop"           "Launch btop system monitor" \
    "Speedtests"     "Ookla speedtest (choose IP)" \
    "Traces"         "Trippy trace (choose target + interface)" \
    "Bastion"        "SSH jump to configured hosts" \
    "Reports"        "System & SLA reports submenu" \
    "Extended ping"  "Pretty ping with auto RTT thresholds" \
    "Diagnostics"    "Node diagnostics (bondlog, juggler, dmesg)" \
    "Exit"           "Exit the menu" \
    3>&1 1>&2 2>&3)

  case "$choice" in
    btop)           do_btop ;;
    Speedtests)     do_speedtest ;;
    Traces)         do_traces ;;
    Bastion)        do_bastion ;;
    Reports)        do_reports_submenu ;;
    "Extended ping") do_extended_ping ;;
    Diagnostics)        do_node_diagnostics ;;
    Exit|"")
      clear
      echo "Goodbye!"
      exit 0
      ;;
    *) whiptail --title "Oops" --msgbox "Invalid selection" 8 40 ;;
  esac
done
