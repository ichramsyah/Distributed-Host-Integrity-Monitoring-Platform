# 🛡️ DHIMP - Backend Aggregator (Agent Node)

This is the **Backend Aggregator** component of the Distributed Host Integrity Monitoring Platform. It acts as a localized "Edge API" for each monitored server, responsible for ingesting logs from the Agent, buffering them in a local SQLite database, and serving them to the Central Dashboard.

## 📖 Overview

Designed for resilience, each backend operates independently. If the network goes down, the backend continues to accept logs from the local agent and stores them safely in SQLite. Once connectivity is restored, the Central Dashboard can pull the backlog via the REST API.

## 🛠️ Tech Stack

-   **Runtime**: Python 3.11+
-   **Framework**: [Django 5.2](https://www.djangoproject.com/)
-   **API**: [Django REST Framework](https://www.django-rest-framework.org/)
-   **Database**: SQLite (Zero-configuration, server-less)
-   **Server**: [Gunicorn](https://gunicorn.org/) (Production WSGI)
-   **Auth**: SimpleJWT (Shared Secret)

## 🚀 Getting Started

### Prerequisites

-   Python 3.11+
-   pip

### 1. Installation

```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Database Setup

Initialize the local SQLite database:

```bash
python manage.py migrate
```

### 3. Running Locally

Start the development server:

```bash
python manage.py runserver 0.0.0.0:8000
```

The API will be available at `http://localhost:8000/api/`.

## 🐳 Docker Deployment

The backend is designed to run as a container alongside the agent infrastructure.

```bash
# Build the image
docker build -t fim-backend .

# Run deeply coupled with the host (Production mode)
docker run -d -p 8000:8000 -v $(pwd)/db.sqlite3:/app/db.sqlite3 fim-backend
```

## 🔌 API Endpoints

### 🔐 Authentication

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :--- |
| **POST** | `/api/login/` | Authenticate and receive `HttpOnly` JWT cookie. | No |
| **POST** | `/api/logout/` | Clear authentication session. | No |
| **GET** | `/api/check-auth/` | Verify current token validity. | Yes |

### 📥 Agent Ingestion

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :--- |
| **POST** | `/api/ingest/fim/` | Receives JSON alerts from the Python Agent. | No (Public/Internal) |

### 📊 Dashboard & Analytics

| Method | Endpoint | Description | Query Params |
| :--- | :--- | :--- | :--- |
| **GET** | `/api/logs/` | List all logs with pagination & filtering. | `?page=1` `?search=php` `?status=malware` |
| **DELETE** | `/api/logs/` | Bulk delete logs. | JSON Body: `{"ids": [1, 2]}` |
| **GET** | `/api/logs/analytics/` | Get summary stats (total/malware) for **today**. | - |
| **GET** | `/api/logs/analytics/historical/` | Get 7-day trend data for charts. | `?days=7` |
| **GET** | `/api/logs/today/` | Get detailed logs for today grouped by severity. | - |
| **GET** | `/api/logs/by-date/` | Get detailed logs for a specific date. | `?date=YYYY-MM-DD` |
| **GET** | `/api/logs/stats-by-date/` | Get summary stats for a specific date. | `?date=YYYY-MM-DD` |

### ⚙️ System Status

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| **GET** | `/api/incron/control/` | Check if the Incron file watcher service is active. |

## 🔑 Authentication

The API is secured using a **Shared-Secret JWT** mechanism. The Dashboard and the Agent must mimic the relevant headers to talk to this API. Ensure your `SECRET_KEY` in `settings.py` is secure.
