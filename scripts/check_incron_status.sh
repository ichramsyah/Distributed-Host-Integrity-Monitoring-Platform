#!/bin/bash

# =================================================================
# Script Name    : incron_monitor.sh
# Description    : Monitors the incron daemon status and updates a 
#                  status file for external reporting/dashboards.
# Author         : Ichramsyah
# =================================================================

STATUS_FILE="/home/ichram/fim/incron_status.txt"

if ps aux | grep -q "[/]usr/sbin/incrond"; then
    echo "running" > "$STATUS_FILE"
else
    echo "stopped" > "$STATUS_FILE"
fi
