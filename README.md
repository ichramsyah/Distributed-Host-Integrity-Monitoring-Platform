# 🛡️ Distributed Host Integrity Monitoring Platform (DHIMP)

[![Python](https://img.shields.io/badge/Python_3-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![YARA](https://img.shields.io/badge/YARA-2EA44F?style=for-the-badge&logo=virustotal&logoColor=white)](https://virustotal.github.io/yara/)
[![Auditd](https://img.shields.io/badge/Linux_Auditd-FCC624?style=for-the-badge&logo=linux&logoColor=black)](https://manpages.ubuntu.com/manpages/trusty/man8/auditd.8.html)
[![Bash](https://img.shields.io/badge/Bash_Scripting-4EAA25?style=for-the-badge&logo=gnu-bash&logoColor=white)](https://www.gnu.org/software/bash/)
[![SQLite](https://img.shields.io/badge/SQLite-003B57?style=for-the-badge&logo=sqlite&logoColor=white)](https://www.sqlite.org/)
[![Django REST Framework](https://img.shields.io/badge/Django_RF-092E20?style=for-the-badge&logo=django&logoColor=white)](https://www.django-rest-framework.org/)
[![Next.js](https://img.shields.io/badge/Next.js-000000?style=for-the-badge&logo=nextdotjs&logoColor=white)](https://nextjs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?style=for-the-badge&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-06B6D4?style=for-the-badge&logo=tailwind-css&logoColor=white)](https://tailwindcss.com/)
[![JWT](https://img.shields.io/badge/JWT_Auth-d63aff?style=for-the-badge&logo=json-web-tokens&logoColor=white)](https://jwt.io/)
[![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)
[![Prometheus](https://img.shields.io/badge/Prometheus-E6522C?style=for-the-badge&logo=prometheus&logoColor=white)](https://prometheus.io/)
[![Grafana](https://img.shields.io/badge/Grafana-F46800?style=for-the-badge&logo=grafana&logoColor=white)](https://grafana.com/)
[![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-2088FF?style=for-the-badge&logo=github-actions&logoColor=white)](https://github.com/features/actions)
[![Ansible](https://img.shields.io/badge/Ansible-EE0000?style=for-the-badge&logo=ansible&logoColor=white)](https://www.ansible.com/)
[![Trivy](https://img.shields.io/badge/Trivy_Scan-47BAE8?style=for-the-badge&logo=aquasecurity&logoColor=white)](https://trivy.dev/)
[![AWS EC2](https://img.shields.io/badge/AWS_EC2-FF9900?style=for-the-badge&logo=amazonec2&logoColor=white)](https://aws.amazon.com/ec2/)

> **Disclaimer**: This project is for portfolio and showcase purposes only. It demonstrates the design and logic of a Distributed Host Integrity Monitoring Platform but requires additional hardening for production use.

## 📖 Overview

The **Distributed Host Integrity Monitoring Platform (DHIMP)** is a scalable security solution designed to monitor the integrity of files across multiple distributed servers from a single viewpoint.

The system uses a decentralized architecture where each monitored server functions as an independent unit containing its own **Agent** and **Backend Aggregator**. A **Centralized Dashboard** then connects to these distributed units, allowing administrators to monitor security events across the entire infrastructure through a single "Single Pane of Glass" interface.

## 🏗️ Architecture

Each monitored server operates as a self-contained unit (Agent + Backend + Infra). The Centralized Dashboard aggregates data from all these sources.

```mermaid
graph TD
    subgraph "Server Unit (Repeated for each Monitored Server)"
        direction TB

        subgraph "Host System"
            FS["File System (Create/Modify/Delete)"]
            Auditd["Auditd Service (Syscall Logs)"]
            Incrond["Incrond Daemon (File Watcher)"]
        end

        subgraph "Agent Layer"
            Agent["Python Agent Script"]
            YARA["YARA Engine (Malware Scan)"]
        end

        subgraph "Backend Layer (Dockerized)"
            API["Django REST API (Gunicorn)"]
            DB[("SQLite Database")]
            Cron["Docker Cron Job (Auto-Purging)"]
            Archive[("CSV Archive (Monthly Reports)")]
        end

        %% Internal Data Flow
        FS -- "Trigger Event" --> Incrond
        Incrond -- "Spawn With Args" --> Agent
        Agent -- "1. Query User (ausearch)" --> Auditd
        Agent -- "2. Scan File" --> YARA
        Agent -- "3. Send Alert (JSON)" --> API
        API -- "Store Data" --> DB
        Cron -- "Monthly Archive" --> DB
        DB -- "Export Logs" --> Archive
    end

    subgraph "SaaS Central View"
        Dashboard["Next.js Central Dashboard"]
    end

    %% External Data Flow
    Dashboard -- "Fetch Aggregated Logs (REST)" --> API
    Dashboard -- "Check Service Health" --> API
    API -- "Status Check" --> Incrond
```

## 📂 Project Structure

```bash
.
├── agent/                         # [PER-SERVER] Host IDS Agent
│   ├── config/                    # Configuration templates
│   │   ├── crontab.example        # Example Cron jobs
│   │   └── incrontab.example      # Example Incron rules
│   ├── rules/                     # Detection Rules
│   │   └── yara-rules.yar         # YARA definitions for malware scanning
│   ├── src/
│   │   └── agent.py               # Main Logic: Watcher -> Audit -> YARA -> API
│   ├── requirements.txt           # Python dependencies (requests, yara-python)
│   └── README.md
│
├── backend/                       # [PER-SERVER] Local Data Aggregator
│   ├── api/                       # API Application
│   │   ├── views.py               # Endpoints (Ingest, Analytics)
│   │   ├── models.py              # DB Schema (FimLog)
│   │   ├── serializers.py         # Data Validation
│   │   └── urls.py                # Router
│   ├── backend/                   # Project Settings
│   │   └── settings.py            # Django Config (SQLite, JWT)
│   ├── docker-compose.yml         # Services: Backend, Prometheus, Grafana, Node-Exporter
│   ├── Dockerfile                 # Gunicorn Production Build
│   └── manage.py
│
├── frontend/                      # [CENTRALIZED] Analytical Dashboard
│   ├── src/
│   │   ├── app/                   # Next.js App Router (Dashboard, Login)
│   │   ├── components/            # UI Components (Visx Charts, Lucide Icons)
│   │   └── lib/                   # Utils
│   ├── public/                    # Static Assets
│   ├── Dockerfile                 # Production Docker Build
│   ├── next.config.ts             # Next.js Config
│   ├── tailwind.config.js         # Styling Config
│   └── package.json
│
├── infra/                         # Deployment Automation
│   ├── deploy-backend.yml         # Ansible Playbook for Backend
│   └── inventory.ini              # Server Inventory
│
└── montly-reports/                # Reporting Assets
```

## ✨ Key Features

#### 🔍 Advanced Detection & Forensics

- **Host-Based Real-time Agent**: Built on Python & Linux Auditd to capture granular forensic details (User ID, Process Name, Working Directory). Implements **Context-Aware Filtering** to distinguish anomalies based on operational hours.
- **Hybrid Threat Detection**: Combines **Behavioral Analysis** with **YARA Content Inspection** to detect complex attack patterns like RCE, PHP Webshells, and Obfuscated Code.
- **Offline Data Resilience**: Integrated **SQLite local buffering** to prevent log loss during network instability, with automated re-sync mechanisms.

#### ⚡ Distributed Architecture & Security

- **Independently Operable Backends**: Distributed Django architecture where each node operates independently, secured by **Shared-Secret JWT Authentication**.
- **Hardened Monitoring Stack**: Containerized Prometheus & Grafana with **Localhost Binding (127.0.0.1)**, enforcing access exclusively via secure SSH Tunnels.
- **Autonomous Watchdog & Health**: Real-time Incron monitoring and Cron-based self-healing routines to ensure 99.9% service uptime on edge nodes.

#### 📊 Centralized Control & Visualization

- **Unified Dashboard (Single Pane of Glass)**: Next.js interface featuring **Multi-Server API Aggregation** for real-time monitoring of global nodes in a single session.
- **Automated Data Lifecycle**: Docker-based Cron jobs for **Monthly Archival & Auto-Purging**, maintaining peak database performance by offloading historical data to CSV.

#### 🏗️ DevOps & Automation

- **Deep-Clean CI/CD Pipeline**: GitHub Actions & Ansible strategy featuring autonomous dependency handling and **Docker Residue Cleanup** for stable deployments.
- **Shift-Left Security**: Integrated **Trivy Vulnerability Scanner** with a **Zero-Tolerance Policy** for Critical/High vulnerabilities during the build phase.

## 🛠️ Tech Stack

#### 1. Core Agent & Forensics

- **Python 3**: The core runtime for the agent logic.
- **YARA**: Embedded malware analysis engine for signature-based detection.
- **Cron**: Manages automated system tasks and maintenance to ensure high availability and data integrity.
  - **Watchdog Mechanism**: Periodic health-checks and self-healing for Incron and Auditd services.
  - **Automated Maintenance**: Monthly service rotation and physical monitoring integrity tests.
  - **Data Retention Policy**: Monthly automated log archival to CSV and database cleanup via Django management commands.
- **Incron**: Uses `inotify` triggers for real-time file system monitoring.
- **Linux Auditd**: Captures deep forensic data (User ID, Process Name) via syscalls.
- **Bash Scripting**: Used for self-healing and service recovery mechanisms.
- **SQLite**: Provides local buffering to ensure no logs are lost during network outages.

#### 2. Full-Stack Development

- **Django REST Framework**: High-performance edge backend for data aggregation.
- **Next.js**: The framework for the Centralized Dashboard (Single Pane of Glass).
- **TypeScript**: Ensures type safety and code quality across the frontend.
- **Tailwind CSS**: Utility-first CSS framework for rapid and responsive UI design.
- **JWT (Shared-Secret)**: Secure cross-server authentication mechanism.

#### 3. DevOps & Infrastructure

- **Docker**: Containerization for consistent deployment across all environments.
- **Prometheus & Grafana**: Complete infrastructure monitoring stack.
- **GitHub Actions**: Automated CI/CD pipelines for testing and deployment.
- **Ansible**: Configuration management for mass-deployment of agents.
- **Trivy**: Vulnerability scanning to ensure secure container images.
- **AWS EC2**: The production environment hosting the distributed nodes.

---

## 🚀 Getting Started

#### 1. Deploying a Server Unit (Agent + Backend)

Run this on **each** server you want to monitor.

```bash
# 1. Clone & Configure Infra
cd infra
ansible-playbook -i inventory.ini deploy-backend.yml

# 2. Manual Start (if not using Ansible)
cd backend
docker-compose up -d --build
```

_This starts the Local Backend Aggregator (Gunicorn/Django) and Monitoring Stack (Prometheus/Grafana)._

#### 2. Configure the Agent

On the same server, set up the agent to talk to the Local Backend.

```bash
cd agent
pip install -r requirements.txt
# Ensure agent.py points to http://localhost:8000/api
```

#### 3. Deploy Centralized Dashboard

Run this once on your admin machine or central server.

```bash
cd frontend
cp .env.local.example .env.local
```

Edit `.env.local` to list all your monitored servers:

```env
NEXT_PUBLIC_API_MAIN=https://server1.com/api
NEXT_PUBLIC_API_SERVER2=https://server2.com/api
NEXT_PUBLIC_API_SERVER3=https://server3.com/api
```

Start the dashboard:

```bash
npm install
npm run dev
# OR with Docker
docker build -t fim-dashboard . && docker run -p 3000:3000 fim-dashboard
```

## ⚠️ Notes

- Ensure the **Centralized Dashboard** has network access to the **Backend Aggregator** ports (default: 8000) on all monitored servers.
- Use HTTPS in production to secure the data in transit between Server Units and the Dashboard.
