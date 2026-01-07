# 🛡️ FIM (File Integrity Monitoring) & Threat Detection System

A robust, real-time File Integrity Monitoring system designed to secure web servers (specifically Open Journal Systems - OJS). This system combines kernel-level monitoring with content-based threat detection to identify unauthorized changes, webshells, and malware injections instantly.

> **Project Context:** Internship Project at Directorate of TSI, Universitas Paramadina.  
> **Author:** Ichramsyah

---

## 🚀 Key Features

### 1. Real-Time Event Detection

- Utilizes **Incron** (Inotify) to capture file system events at the kernel level.
- **Forensic-Grade Accuracy:**
  - `IN_CREATE` → DITAMBAHKAN (Added)
  - `IN_CLOSE_WRITE` → DIUBAH (Modified)
  - `IN_DELETE` → DIHAPUS (Deleted)

### 2. Intelligent Threat Detection

- **YARA Integration:** Scans file content immediately upon modification.
- **Custom Ruleset:** Detects:
  - Dangerous PHP functions (`shell_exec`, `passthru`, `system`).
  - Webshell payloads (obfuscated `eval`, base64 decoding).
  - Hidden malware signatures.

### 3. Smart Deduplication Engine

- Implements a custom **Debouncing Algorithm** using MD5 hashing (Path + Event).
- Prevents log flooding caused by rapid file save operations in Linux, ensuring clean and readable audit logs.

### 4. User Attribution (Auditd)

- Integrates with Linux **Auditd** (`ausearch`) to identify _who_ (user/UID) and _what process_ (PID/Comm) triggered the file change.

### 5. Critical File Protection

- **Whitelist Bypass Logic:** Even if a folder is whitelisted (e.g., Uploads), files with critical extensions (`.php`, `.phtml`, `.htaccess`) are **always** scanned and reported.
- **Anti-Forensic Detection:** Bypasses deduplication for `DELETE` events to ensure attempts to remove evidence are always logged.

---

## 🛠️ Technology Stack

- **Core Agent:** Python 3, Incron, YARA-Python.
- **System Tools:** Linux Auditd, Inotify-tools.
- **Backend API:** Django REST Framework.
- **Database:** SQLite.
- **Infrastructure:** AWS EC2 (Ubuntu).

---

## 📂 Project Structure

```text
fim-project/
├── backend/                # Django Backend (API & Admin)
│   ├── api/                # API Endpoints
│   ├── manage.py
│   └── ...
├── scripts/                # FIM Agent Scripts
│   ├── agent.py            # Main Logic (Event Processor)
│   ├── agent_debug.txt     # Local Debug Logs
│   └── incron_status.txt   # Service Health Check
├── yara-rules.yar          # Custom YARA Detection Rules
├── requirements.txt        # Python Dependencies
└── README.md               # Documentation
```

## ⚙️ Installation & Setup

### 1. Prerequisites

Ensure the server has the necessary system tools installed:

```bash
sudo apt update
sudo apt install incron auditd yara
sudo systemctl enable incron auditd
sudo systemctl start incron auditd
```

### 2. Python Environment

```bash
# Clone the repository
git clone [https://github.com/your-username/fim-project.git](https://github.com/your-username/fim-project.git)
cd fim-project

# Install Python dependencies
pip3 install -r requirements.txt
# (Ensure yara-python, requests, etc. are installed)
```

### 3. Configure YARA Rules

Make sure `yara-rules.yar` contains the definitions for PHP malware detection. _(See `yara-rules.yar` file for details)_.

```bash
sudo apt update
sudo apt install incron auditd yara
sudo systemctl enable incron auditd
sudo systemctl start incron auditd
```

### 4. Configure Incron

Set up the kernel watcher to trigger the agent.

```bash
incrontab -e
```

Add the following line (Adjust paths accordingly):

```bash
/var/www/OJS/ IN_CLOSE_WRITE,IN_CREATE,IN_DELETE,IN_MOVED_TO,IN_MOVED_FROM /usr/bin/python3 /home/ubuntu/fim/scripts/agent.py $@/$# $%
```

### 5. Run the Backend

```bash
cd backend
python3 manage.py migrate
python3 manage.py runserver 0.0.0.0:8000
```

## 🔍 How It Works

1. **Trigger**: A file is modified in the monitored directory.

2. **Capture**: `Incron` detects the signal and executes `agent.py`.

3. **Process**:

   - `agent.py` checks the Deduplication Cache.
   - If valid, it scans the file content using `YARA`.
   - It queries `Auditd` to find the user responsible.

4. **Report**: The agent sends a JSON payload to the Django API.
   - Status: `[NORMAL]`,`[KEGIATAN MENCURIGAKAN]`, `[BAHAYA]`, or `[MALWARE]`.

## 🛡️ Security Logic

| Condition                      | Severity Tag              | Action                     |
| ------------------------------ | ------------------------- | -------------------------- |
| YARA Match Found               | `[MALWARE]`               | Alert Admin Immediately    |
| Critical Ext (.php, .htaccess) | `[BAHAYA]`                | Log as Warning             |
| Changes Outside Office Hours   | `[KEGIATAN MENCURIGAKAN]` | Log as Suspicious Activity |
| Standard File Changes          | Normal                    | Log for Audit Trail        |

## 🚀 Project Status

This system is currently **deployed in production** at the **Directorate of Technology Systems & Information (TSI), Universitas Paramadina**. It actively monitors and secures the university's Open Journal Systems (OJS) infrastructure against unauthorized changes and malware threats.
