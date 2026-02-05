#!/bin/bash

# ------------------------------------------------------------------
# 🛡️ AUDITD HEALER (WATCHDOG)
# ------------------------------------------------------------------
# DISCLAIMER:
# This script is provided for demonstration and portfolio purposes only. Actual production configurations, 
# credentials, and infrastructure details are managed securely and are not included in this repository.
#
# It showcases a self-healing concept for auditd monitoring in a
# File Integrity Monitoring (FIM) system.
#
# The commands below may force-restart system services and adjust
# audit subsystem parameters. DO NOT use this script directly in
# production environments without proper validation and hardening.
#
# Description:
#   Ensures the Audit Daemon is always running and healthy.
#   It force-restarts the service if it hangs and adjusts buffer limits.
#
# Usage:
#   Intended to be triggered via cron in a controlled environment.
# ------------------------------------------------------------------

if ! systemctl is-active --quiet auditd; then
    echo "[$(date)] WARN: Auditd is dead. Restarting..."
    sudo systemctl restart auditd
    sleep 3
fi

if ! timeout 5s sudo auditctl -s > /dev/null 2>&1; then
    echo "[$(date)] CRITICAL: Auditd is hung. Force killing..."
    sudo killall -9 auditd
    sudo systemctl restart auditd
    sleep 3
fi

CURRENT_LIMIT=$(sudo auditctl -s | grep "backlog_limit" | awk '{print $2}')
TARGET_LIMIT=8192

if [[ -z "$CURRENT_LIMIT" ]] || [[ "$CURRENT_LIMIT" -lt "$TARGET_LIMIT" ]]; then
    echo "[$(date)] INFO: Increasing buffer limit to $TARGET_LIMIT"
    sudo auditctl -b $TARGET_LIMIT
fi