#!/bin/bash

# ------------------------------------------------------------------
# INCRON STATUS CHECKER
# ------------------------------------------------------------------
# NOTE:
#   This script is provided for demonstration purposes as part of a
#   File Integrity Monitoring (FIM) showcase project.
# ------------------------------------------------------------------
# Description:
#   Checks if the Incron daemon is running and writes the status to a file.
#   This file is read by the Python Agent/API to report system health.
# ------------------------------------------------------------------

STATUS_FILE="${1:-/tmp/incron_status.txt}"

if ps aux | grep -q "[/]usr/sbin/incrond"; then
    echo "running" > "$STATUS_FILE"
else
    echo "stopped" > "$STATUS_FILE"
fi