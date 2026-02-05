# 🛡️ DHIMP - Centralized Dashboard

This is the **Centralized Dashboard** (Single Pane of Glass) for the Distributed Host Integrity Monitoring Platform. It provides a real-time visualization layer that aggregates security events, system health, and threat intelligence from all distributed agents.

## 📖 Overview

Built with **Next.js 16** and **Tailwind CSS v4**, this dashboard is designed for high performance and rapid response. It connects to the distributed Django backends to fetch alerts and metrics, presenting them in an actionable format for security analysts.

## 🛠️ Tech Stack

-   **Framework**: [Next.js 16](https://nextjs.org/) (App Router & Turbopack)
-   **Language**: [TypeScript](https://www.typescriptlang.org/)
-   **Styling**: [Tailwind CSS v4](https://tailwindcss.com/)
-   **Visualization**: [Visx](https://airbnb.io/visx/) & Recharts
-   **Icons**: [Lucide React](https://lucide.dev/)
-   **Animations**: [Framer Motion](https://www.framer.com/motion/)
-   **Auth**: [Jose](https://github.com/panva/jose) (JWT)

## 🚀 Getting Started

### Prerequisites

-   Node.js 20+
-   npm or pnpm

### 1. Installation

```bash
cd frontend
npm install
```

### 2. Configuration

Copy the example environment file:

```bash
cp .env.local.example .env.local
```

Configure your backend server endpoints in `.env.local`:

```env
# List of distributed backends to monitor
NEXT_PUBLIC_API_MAIN=https://server-a.com/api
NEXT_PUBLIC_API_SERVER2=https://server-b.com/api
NEXT_PUBLIC_API_SERVER3=https://server-c.com/api
```

### 3. Development Server

Start the development server with Turbopack:

```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) to view the dashboard.

## 🐳 Docker Deployment

To build and run the dashboard as a container:

```bash
# Build the image
docker build -t fim-dashboard .

# Run the container (Port 3000)
docker run -p 3000:3000 fim-dashboard
```

## 🏗️ Project Structure

-   `src/app/`: App Router pages and layouts.
-   `src/components/`: Reusable UI components and charts.
-   `src/lib/`: Utility functions and API clients.
-   `public/`: Static assets.
