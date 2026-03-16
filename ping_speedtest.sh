#!/bin/bash
MAX_DELAY=28800
# Generate a random delay within the specified range
RANDOM_DELAY=$(( RANDOM % MAX_DELAY ))
# Sleep for the random duration
sleep $RANDOM_DELAY
# Execute your desired command
/usr/local/sbin/ping_sla.sh speedtest
