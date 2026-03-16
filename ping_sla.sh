#!/bin/bash

# Ping & Speedtest SLA Monitor Script (NOC Dashboard Edition)

PING_DATA_FILE="$HOME/ping_sla.csv"
SPEED_DATA_FILE="$HOME/speedtest.csv"

########################################
# TERMINAL COLOURS
########################################

RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
CYAN=$(tput setaf 6)
WHITE=$(tput setaf 7)
BOLD=$(tput bold)
RESET=$(tput sgr0)

########################################
# QUERY MODE PARSER
########################################

query_mode="all"
if [[ "$1" == query=* ]]; then
    query_mode="${1#query=}"
    set -- query
fi

########################################
# UTILITY FUNCTIONS
########################################

ping_ip() {
    local ip="$1"
    local received=$(ping -c 10 -W 2 "$ip" 2>/dev/null | awk '/received/ {print $4}')
    echo "${received:-0}"
}

truncate_ping_to_year() {
    local year=$(date +%Y)
    awk -F, -v yr="$year" 'NR==1 || substr($1,1,4)==yr {print}' "$PING_DATA_FILE" > "$PING_DATA_FILE.tmp"
    mv "$PING_DATA_FILE.tmp" "$PING_DATA_FILE"
}

truncate_speed_to_30days() {

    local start_epoch=$(date -d '30 days ago' '+%s')

    awk -v s="$start_epoch" -F, '
    function ts_from_str(ts){
        sp=index(ts," ")
        datep=substr(ts,1,sp-1)
        timep=substr(ts,sp+1)
        split(datep,d,"-")
        split(timep,t,":")
        return mktime(d[1]" "d[2]" "d[3]" "t[1]" "t[2]" "t[3])
    }
    NR==1 {print; next}
    { if(ts_from_str($1)>=s) print }
    ' "$SPEED_DATA_FILE" > "$SPEED_DATA_FILE.tmp"

    mv "$SPEED_DATA_FILE.tmp" "$SPEED_DATA_FILE"
}

compute_avg() {

    local start_epoch="$1"
    local end_epoch="${2:-$(date -d '2100-01-01' +%s)}"

    awk -v s1="$start_epoch" -v s2="$end_epoch" -F, '
    function ts_from_str(ts){
        sp=index(ts," ")
        datep=substr(ts,1,sp-1)
        timep=substr(ts,sp+1)
        split(datep,d,"-")
        split(timep,t,":")
        return mktime(d[1]" "d[2]" "d[3]" "t[1]" "t[2]" "t[3])
    }
    NR>1{
        ts=ts_from_str($1)
        if(ts>=s1 && ts<s2){
            sum+=$3
            n++
        }
    }
    END{
        if(n>0){
            printf "%.2f%% (%d samples)",sum/n,n
        } else {
            print "No data"
        }
    }
    ' "$PING_DATA_FILE"
}

########################################
# SLA GAUGE
########################################

draw_bar(){
percent=$(printf "%.0f" "$1")
width=40
filled=$((percent*width/100))
empty=$((width-filled))

bar=$(printf "%${filled}s"|tr ' ' '█')
space=$(printf "%${empty}s")

if ((percent>=99)); then
color=$GREEN
elif ((percent>=97)); then
color=$YELLOW
else
color=$RED
fi

printf "%s[%s%s]%s %s%3s%%%s\n" "$WHITE" "$color$bar" "$space" "$RESET" "$color" "$percent" "$RESET"
}

get_percent(){
echo "$1" | awk -F'%' '{print $1}'
}

########################################
# SLA DOWNTIME CALCULATOR
########################################

calc_downtime(){

start_month=$(date -d "$(date '+%Y-%m-01')" +%s)

awk -v s="$start_month" -F, '
function ts_from_str(ts){
sp=index(ts," ")
datep=substr(ts,1,sp-1)
timep=substr(ts,sp+1)
split(datep,d,"-")
split(timep,t,":")
return mktime(d[1]" "d[2]" "d[3]" "t[1]" "t[2]" "t[3])
}
NR>1{
ts=ts_from_str($1)
if(ts>=s){
fail=(100-$3)/100
downtime+=fail*600
}
}
END{
allowed=2592000*0.001
printf "Downtime this month: %.0f sec\n",downtime
printf "Allowed (99.9 SLA): %.0f sec\n",allowed
printf "Remaining budget: %.0f sec\n",allowed-downtime
}
' "$PING_DATA_FILE"
}

########################################
# PING MONITOR MODE
########################################

if [ $# -eq 0 ]; then

if [ ! -f "$PING_DATA_FILE" ]; then
echo "timestamp,success_count,percent" > "$PING_DATA_FILE"
else
truncate_ping_to_year
fi

s1=$(ping_ip 1.1.1.1)
s2=$(ping_ip 8.8.8.8)
s3=$(ping_ip 9.9.9.9)

total=$((s1+s2+s3))
percent=$(echo "scale=2;$total/30*100"|bc)

ts=$(date '+%Y-%m-%d %H:%M:%S')
echo "$ts,$total,$percent" >> "$PING_DATA_FILE"

echo "Logged: $total/30 ($percent%)"

########################################
# SPEEDTEST MODE
########################################

elif [ "$1" = "speedtest" ]; then

if [ ! -f "$SPEED_DATA_FILE" ]; then
echo "timestamp,server,isp,latency,jitter,download_mbps,upload_mbps,packet_loss,result_url" > "$SPEED_DATA_FILE"
else
truncate_speed_to_30days
fi

json=$(speedtest --progress=no --format=json --accept-license --accept-gdpr)

download=$(python3 -c "import sys,json;d=json.load(sys.stdin);print(round(d['download']['bandwidth']*8/1000000,2))" <<< "$json")
upload=$(python3 -c "import sys,json;d=json.load(sys.stdin);print(round(d['upload']['bandwidth']*8/1000000,2))" <<< "$json")
latency=$(python3 -c "import sys,json;d=json.load(sys.stdin);print(d['ping']['latency'])" <<< "$json")
packet_loss=$(python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('packetLoss',0))" <<< "$json")

ts=$(date '+%Y-%m-%d %H:%M:%S')

echo "$ts,x,x,$latency,x,$download,$upload,$packet_loss,x" >> "$SPEED_DATA_FILE"

echo "Logged: $download Mbps down"

########################################
# QUERY DASHBOARD
########################################

elif [ "$1" = "query" ]; then

########################################
# SYSTEM PANEL
########################################

if [ "$query_mode" = "all" ]; then

neofetch --ascii "$(figlet -f slant NN)"

echo
echo "${BOLD}${CYAN}DISK USAGE${RESET}"
echo "================================================"
df -h

echo
tuptime

fi

########################################
# SLA DASHBOARD
########################################

if [[ "$query_mode" = "all" || "$query_mode" = "sla" ]]; then

echo
echo "${BOLD}${CYAN}NETWORK SLA DASHBOARD${RESET}"
echo "================================================"

start_hour=$(date -d "$(date '+%Y-%m-%d %H'):00:00" +%s)
start_day=$(date -d "$(date '+%Y-%m-%d 00:00:00')" +%s)
start_month=$(date -d "$(date '+%Y-%m-01 00:00:00')" +%s)
start_year=$(date -d "$(date '+%Y-01-01 00:00:00')" +%s)

cur_month_first=$(date '+%Y-%m-01')
prev_month_first=$(date -d "$cur_month_first -1 month" '+%Y-%m-%d')

start_last=$(date -d "$prev_month_first 00:00:00" +%s)
end_last=$(date -d "$cur_month_first 00:00:00" +%s)

hour=$(compute_avg "$start_hour")
day=$(compute_avg "$start_day")
month=$(compute_avg "$start_month")
year=$(compute_avg "$start_year")
last_month=$(compute_avg "$start_last" "$end_last")

hour_p=$(get_percent "$hour")
day_p=$(get_percent "$day")
month_p=$(get_percent "$month")
year_p=$(get_percent "$year")
last_month_p=$(get_percent "$last_month")

printf "\n%-18s" "Current Hour"; draw_bar "$hour_p"
printf "%-18s" "Today"; draw_bar "$day_p"
printf "%-18s" "This Month"; draw_bar "$month_p"
printf "%-18s" "This Year"; draw_bar "$year_p"
printf "%-18s" "Last Month"; draw_bar "$last_month_p"

echo
printf "%-18s %s\n" "Hour Avg:" "$hour"
printf "%-18s %s\n" "Day Avg:" "$day"
printf "%-18s %s\n" "Month Avg:" "$month"
printf "%-18s %s\n" "Year Avg:" "$year"
printf "%-18s %s\n" "Last Month Avg:" "$last_month"

echo
echo "${BOLD}${CYAN}SLA BUDGET${RESET}"
echo "================================================"
calc_downtime

fi

########################################
# SPEEDTEST DASHBOARD
########################################

if [[ "$query_mode" = "all" || "$query_mode" = "speedtest" ]]; then

echo
echo "${BOLD}${CYAN}WAN PERFORMANCE (30 DAY HISTORY)${RESET}"
echo "================================================"

python3 <<EOF
import csv

rows=[]
with open("$SPEED_DATA_FILE") as f:
    r=csv.DictReader(f)
    rows=list(r)

print(f"{'Date':10} {'Down':>8} {'Up':>8} {'Latency':>8} {'Loss':>6}")
print("-"*48)

for r in rows[-30:]:
    d=r['timestamp'][:10]
    down=r['download_mbps']
    up=r['upload_mbps']
    lat=r['latency']
    loss=r['packet_loss']
    print(f"{d:10} {down:>8} {up:>8} {lat:>8} {loss:>6}")
EOF

fi

########################################
# VNSTAT
########################################

if [[ "$query_mode" = "all" ]]; then
echo
echo "${BOLD}${CYAN}TRAFFIC STATISTICS${RESET}"
echo "================================================"
vnstat
fi

fi
