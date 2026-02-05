# 🛡️ DHIMP - Host Agent (The Watcher)

The **Host Agent** is the specialized "eyes and ears" of the platform. Written in Python, it sits on the user-space boundary and reacts instantly to kernel-level file system events triggered by `incron`.

## 📖 How It Works

1.  **Trigger**: `incron` detects a file change (Create/Modify/Delete) and spawns the Agent process.
2.  **Forensics**: The Agent immediately queries the Linux Audit System (`auditd`) to identify **WHO** (User ID) and **WHAT** (Process Name) caused the event.
3.  **Analysis**: The file is scanned against embedded **YARA rules** to detect malware signatures (Webshells, Crypto-miners, etc.).
4.  **Reporting**: The enriched alert is sent to the local `backend` API for storage.

## 📂 Directory Structure

```bash
agent/
├── config/
│   ├── crontab.example        # Cron jobs for health checks & maintenance
│   └── incrontab.example      # Incron rules for file watching
├── rules/
│   └── yara-rules.yar         # Custom YARA signatures (PHP Shells, Obfuscation)
├── scripts/
│   ├── auditd_healer.sh       # Watchdog: Restarts auditd if hung/crashed
│   ├── check_incron.sh        # Health Check: Verifies incron process status
│   └── maintain_auditd.sh     # Monthly: Rotary log flushing & I/O testing
└── src/
    └── agent.py               # Core Logic
```

## 🧠 Smart Logic & Detection Rules

### 1. Malware Detection (YARA)

The agent uses `yara-python` with custom rules located in `rules/yara-rules.yar`.

- **PHP Dangerous Functions**: Detects `shell_exec`, `passthru`, `system`, etc.
- **Webshell Payloads**: Flags `eval()` or `assert()` combined with `$_GET/$_POST`.
- **Obfuscation**: Identifies Base64/Gzip encoded payloads often used to hide backdoors.
- **System Recon**: Detects scripts attempting to read `/etc/passwd` or use `curl/wget`.

### 2. Self-Healing & Maintenance (Scripts)

To ensure 99.9% uptime, the agent includes shell scripts for autonomous recovery:

- **Auditd Healer** (`auditd_healer.sh`): Runs every 5 mins. If `auditd` hangs or dies, it force-kills and restarts the daemon, and automatically increases buffer limits (`auditctl -b 8192`) to prevent event loss.
- **Monthly Maintenance** (`maintain_auditd.sh`): A "Deep Clean" routine that flushes rules, rotates logs, and performs a physical write/delete test to verify the kernel is still sending events.

### 3. Core Agent Logic (`agent.py`)

- **Deduplication**: Implements a **1.5-second cache** to prevent alert spam from rapid file operations.
- **Context-Aware**:
  - **Office Hours Strategy**: Events outside 06:00 - 18:00 are flagged as `[SUSPICIOUS ACTIVITY]`.
  - **Critical Files**: Modifications to `.htaccess` or sensitive configurations are always flagged as `[DANGER]`.
  - **Extension Blacklist**: `.php`, `.sh`, `.exe`, `.pl` files trigger immediate scrutiny.

## 🛠️ Tech Stack

- **Language**: Python 3.10+
- **Core Libs**: `requests`, `yara-python`
- **System Tools**:
  - `incron` (Inotify Cron System)
  - `auditd` (Linux Audit Daemon)
  - `ausearch` (Audit Log Query)

## 🚀 Installation & Setup

### 1. System Dependencies

```bash
sudo apt update
sudo apt install incron auditd python3-pip
```

### 2. Python Setup

```bash
cd agent
pip install -r requirements.txt
```

### 3. Configuration

Set the Environment Variables (or hardcode in `src/agent.py` for testing):

```bash
export API_URL="http://127.0.0.1:8000/api"
export YARA_PATH="/path/to/agent/rules/yara-rules.yar"
```

### 4. Incron Rule Setup

To start watching a directory (e.g., `/var/www/html`):

```bash
# Add user to incron allow list
echo "root" | sudo tee -a /etc/incron.allow

# Edit incrontab
sudo incrontab -e
```

**Add the following rule:**

```text
/var/www/html IN_MODIFY,IN_CREATE,IN_DELETE,IN_MOVED_TO,IN_MOVED_FROM /usr/bin/python3 /path/to/agent/src/agent.py $@/$# $%
```

_Explanation_:

- `$@`: Watched Directory
- `$#`: Filename
- `$%`: Event Name

### 5. Cron Automation Setup (Self-Healing)

To ensure the agent remains active and healthy, configure `cron` to run the helper scripts:

```bash
# Edit root crontab
sudo crontab -e
```

**Add the following lines:**

```bash
# 1. Health Check (Every 2 mins): Updates status for Dashboard
*/2 * * * * /path/to/agent/scripts/check_incron.sh /tmp/incron_status.txt

# 2. Watchdog (Every 5 mins): Restarts Auditd if crashed
*/5 * * * * /path/to/agent/scripts/auditd_healer.sh >> /var/log/fim_healer.log 2>&1

# 3. Deep Maintenance (Monthly): Log rotation & IO test
0 3 1 * * /path/to/agent/scripts/maintain_auditd.sh
```

## 🔍 Troubleshooting

- **Logs**: Check `/var/log/fim_agent.log` for execution errors.
- **Permissions**: Ensure the script has usage rights for `sudo ausearch` (configure `/etc/sudoers.d/`).
