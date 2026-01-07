#!/bin/bash

# =================================================================
# Script Name    : auditd_healer.sh
# Description    : Ensures auditd service is healthy and optimizes 
#                  the backlog limit for security logging.
# Author         : Ichramsyah
# =================================================================

if ! systemctl is-active --quiet auditd; then
    sudo systemctl restart auditd
    sleep 3
fi

if ! timeout 5s sudo auditctl -s > /dev/null 2>&1; then
    sudo killall -9 auditd
    sudo systemctl restart auditd
    sleep 3
fi

CURRENT_LIMIT=$(sudo auditctl -s | grep "backlog_limit" | awk '{print $2}')
TARGET_LIMIT=8192

if [[ -z "$CURRENT_LIMIT" ]] || [[ "$CURRENT_LIMIT" -lt "$TARGET_LIMIT" ]]; then
    sudo auditctl -b $TARGET_LIMIT
fi