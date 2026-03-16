#!/bin/bash

# Check if curl is installed
if ! command -v curl &> /dev/null; then
    echo "Error: curl is not installed. Please install it using 'sudo apt install curl' or equivalent."
    exit 1
fi
# Check if ip command is available
if ! command -v ip &> /dev/null; then
    echo "Error: ip command is not installed. Please install iproute2 using 'sudo apt install iproute2' or equivalent."
    exit 1
fi
# Check if nmap is installed
if ! command -v nmap &> /dev/null; then
    echo "Error: nmap is not installed. Please install it using 'sudo apt install nmap' or equivalent."
    exit 1
fi
# Check if lldpcli is installed
if ! command -v lldpcli &> /dev/null; then
    echo "Error: lldpcli is not installed. Please install it using 'sudo apt install lldpd' or equivalent."
    exit 1
fi
# Check if script is run as root (required for nmap and lldpcli)
if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root for nmap and lldpcli to function."
    exit 1
fi

# Function to query MAC vendor with fallback
get_vendor() {
    local mac=$1
    local vendor

    # Primary: Query macvendors.com API
    vendor=$(curl -s --connect-timeout 5 "https://api.macvendors.com/$mac")

    # If primary fails (empty or error), fallback to macvendorlookup.com
    if [[ -z "$vendor" || "$vendor" == *"error"* || "$vendor" == *"Not Found"* ]]; then
        # Fallback API returns JSON array; extract 'company' from first object
        vendor=$(curl -s --connect-timeout 5 "https://www.macvendorlookup.com/api/v2/$mac" | \
                 grep -o '"company":"[^"]*' | head -1 | sed 's/"company":"//')

        # If fallback also empty (not found or error), set to Unknown
        if [[ -z "$vendor" ]]; then
            echo "Unknown"
            return
        fi
    fi

    # Crop vendor name to 30 characters
    echo "${vendor:0:30}"
}

# Function to get open ports using nmap
get_open_ports() {
    local ip=$1
    # Perform a quick TCP SYN scan on common ports (-F for fast scan)
    ports=$(nmap -F --open -T4 "$ip" | grep ^[0-9] | awk '{print $1}' | tr '\n' ',' | sed 's/,$//')
    if [[ -z "$ports" ]]; then
        echo "None"
    else
        echo "$ports"
    fi
}

# Print IP neighbors table header
echo "IP Neighbors Table:"
printf "%-15s %-17s %-30s %s\n" "IP Address" "MAC Address" "Vendor" "Open Ports"
printf "%-15s %-17s %-30s %s\n" "---------------" "-----------------" "------------------------------" "--------------------"

# Get IP neighbors, filter out IPv6 (lines containing ::), and process each entry
ip neigh show | grep -v "::" | while read -r line; do
    # Extract IP and MAC address using awk
    ip=$(echo "$line" | awk '{print $1}')
    mac=$(echo "$line" | awk '{print $5}')
    # Only process lines with valid IP and MAC addresses
    if [[ -n "$ip" && -n "$mac" ]]; then
        # Get vendor for the MAC address
        vendor=$(get_vendor "$mac")
        # Get open ports for the IP
        ports=$(get_open_ports "$ip")
        # Print formatted output
        printf "%-15s %-17s %-30s %s\n" "$ip" "$mac" "$vendor" "$ports"
    fi
done

# Print LLDP neighbors table
echo -e "\nLLDP Neighbors Summary Table:"
# Check if lldpcli command returns any neighbors
lldp_output=$(lldpcli show neighbors summary 2>/dev/null)
if [[ -z "$lldp_output" || $(echo "$lldp_output" | grep -c "Interface:") -eq 0 ]]; then
    echo "No LLDP neighbors found."
else
    # Print LLDP table header
    printf "%-15s %-17s %-30s %s\n" "Interface" "Chassis ID" "System Name" "Port Description"
    printf "%-15s %-17s %-30s %s\n" "---------------" "-----------------" "------------------------------" "--------------------"
    # Process lldpcli output
    echo "$lldp_output" | awk '
    BEGIN { interface=""; chassis=""; sysname="Unknown"; portdesc="Unknown"; }
    /Interface:/ {
        if (interface != "") {
            printf "%-15s %-17s %-30s %s\n", interface, chassis, sysname, portdesc;
        }
        interface=$2; sub(/,$/, "", interface);
        chassis=""; sysname="Unknown"; portdesc="Unknown";
    }
    /ChassisID:/ { if ($3 == "mac") { chassis=$4 } else { chassis=$3 } }
    /SysName:/ { sysname=$2 }
    /PortDescr:/ { portdesc=$2 }
    END { if (interface != "") {
            printf "%-15s %-17s %-30s %s\n", interface, chassis, sysname, portdesc;
        }
    }'
fi

exit 0
