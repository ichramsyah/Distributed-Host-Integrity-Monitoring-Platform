#!/bin/bash

# ------------------------------------------------------------------
# AUDITD MONTHLY MAINTENANCE & HEALTH CHECK
# ------------------------------------------------------------------
# NOTE:
#   This script is provided for demonstration purposes as part of a
#   File Integrity Monitoring (FIM) showcase project.
# ------------------------------------------------------------------
# Description:
#   1. Flushes existing Auditd rules to prevent buffer stagnation.
#   2. Restarts the Auditd service.
#   3. Re-applies the critical directory monitoring rules.
#   4. Performs a physical Write/Delete test to verify event capture.
# ------------------------------------------------------------------

# --- CONFIGURATION (ADJUST FOR YOUR ENVIRONMENT) ---
LOG_FILE="/var/log/fim_maintenance.log"
TARGET_DIR="/path/to/monitored/directory" # e.g., /var/www/html
TEST_FILE="$TARGET_DIR/audit_test_ping.tmp"
AUDIT_KEY="fim_critical_watch"

# Function to write logs with timestamp
log_msg() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# Ensure script is run as root
if [ "$EUID" -ne 0 ]; then 
  echo "Please run as root"
  exit 1
fi

log_msg "--- STARTING MONTHLY AUDITD MAINTENANCE ---"

# 1. STOP SERVICE & FLUSH RULES
log_msg "Stopping service and flushing old rules..."
service auditd stop
auditctl -D > /dev/null 2>&1

# 2. RESTART SERVICE
log_msg "Restarting auditd daemon..."
service auditd start
sleep 3 

# 3. RE-APPLY RULES
log_msg "Re-applying monitoring rules for: $TARGET_DIR"
# Watch for Write (w) and Attribute Change (a) events
auditctl -w "$TARGET_DIR" -p wa -k "$AUDIT_KEY"

if auditctl -l | grep -q "$AUDIT_KEY"; then
    log_msg "OK: Rules successfully applied."
else
    log_msg "ERROR: Failed to apply rules!"
fi

# 4. FUNCTIONAL TEST (PHYSICAL I/O)
log_msg "Performing dummy write/delete test..."
touch "$TEST_FILE"
rm "$TEST_FILE"

sleep 5

# 5. VERIFY LOG CAPTURE
# Check if the test file activity appears in the audit log
if tail -n 50 /var/log/audit/audit.log | grep -q "audit_test_ping.tmp"; then
    log_msg "SUCCESS: Auditd is functioning normally (Event captured)."
else
    log_msg "FAILED: Auditd did not record the test event."
fi

log_msg "--- MAINTENANCE COMPLETED ---"
echo "------------------------------------------------" >> "$LOG_FILE"