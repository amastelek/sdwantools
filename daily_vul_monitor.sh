#!/bin/bash
# =============================================================================
# daily_vul_monitor.sh — Random-delay wrapper for vul_monitor.sh
#
# Place at:  /usr/local/sbin/daily_vul_monitor.sh
# Add to root crontab:
#   @daily      * * * /usr/local/sbin/daily_vul_monitor.sh >> /var/log/vul_monitor.log 2>&1
#
# The script sleeps a random duration of up to 24 hours before running the
# scan, so the actual execution time is unpredictable and spread across the day.
# =============================================================================

MAX_DELAY=86400

# Generate a random delay within the specified range (0 – 86399 seconds)
RANDOM_DELAY=$(( RANDOM % MAX_DELAY ))

echo "[daily_vul_monitor] $(date '+%Y-%m-%d %H:%M:%S') — sleeping ${RANDOM_DELAY}s before scan"

# Sleep for the random duration
sleep "$RANDOM_DELAY"

# Execute the vulnerability monitor
/usr/local/sbin/vul_monitor.sh
