# ThreatLens — Security Operations Center Dashboard

ThreatLens is a full-stack cybersecurity log analysis and threat detection application built using **React, Vite, Python, FastAPI, and Pandas**.

It analyzes uploaded security logs, detects suspicious activities using rule-based detection, assigns risk scores, and displays alerts through a SOC-style dashboard.

> **Disclaimer:** ThreatLens is an educational portfolio project. It does not perform live network monitoring or real-time surveillance. All bundled sample data is fictional.

**Deployed Website:** https://threatlens-security-operations-cent.vercel.app/

## Features

- **Security Dashboard:** View event summaries, threat metrics, charts, and activity timelines.
- **Threat Detection:** Detect brute-force attacks, port scans, privilege escalation, and suspicious account activities using 14 detection rules.
- **Alert Investigation:** View risk scores, supporting evidence, and recommended investigation steps.
- **Log Analysis:** Upload ThreatLens CSV files and Windows Security Event Log CSV exports.
- **IP Activity:** Identify suspicious IP addresses based on their activity.
- **Filtering & Export:** Filter alerts and export results to CSV.
- **Detection Settings:** Customize detection thresholds.
- **Live & Demo Modes:** Analyze uploaded logs or explore sample data.
- **Session Isolation:** Keep visitors' uploaded datasets separate.

## Technology Stack

| Component | Technologies |
|---|---|
| Frontend | React, Vite, Recharts |
| Backend | Python, FastAPI, Pandas |
| Icons | Lucide React |
| Testing | Pytest |
| Deployment | Vercel, Render |

## Installation & Setup

### Prerequisites

- Node.js and npm
- Python 3.10+
- Git

### 1. Clone the Repository

```bash
git clone https://github.com/nitesh-pawar24/ThreatLens---Security-Operations-Center-Dashboard.git
cd ThreatLens---Security-Operations-Center-Dashboard
```

### 2. Start the Backend

Create and activate a virtual environment:

```bash
python -m venv backend/.venv
```

Windows PowerShell:

```powershell
.\backend\.venv\Scripts\Activate.ps1
```

Install dependencies and start the backend:

```bash
pip install -r backend/requirements.txt
```

```powershell
$env:MULTI_TENANT_SESSIONS="true"
python -m uvicorn backend.api:app --reload --port 8000
```

### 3. Start the Frontend

Open a second terminal:

```bash
npm install
npm run dev
```

Open **http://localhost:5173** in your browser.

## How to Use

1. Open ThreatLens in your browser.
2. Explore sample security data using Demo Mode.
3. Switch to Live Mode to analyze your own logs.
4. Upload a supported CSV file through Log Analysis.
5. Review detected threats and alerts.
6. Explore IP activity and customize detection settings.

**Supported formats:**
- ThreatLens CSV files.
- Windows Event Viewer Security logs exported as CSV.

Native `.evtx` files are not supported.

## Project Structure

```text
ThreatLens/
├── backend/
│   ├── api.py
│   ├── detector.py
│   ├── log_parser.py
│   ├── session.py
│   ├── windows_log_importer.py
│   ├── requirements.txt
│   ├── data/
│   └── tests/
├── public/
├── src/
│   ├── components/
│   ├── context/
│   ├── data/
│   ├── pages/
│   ├── services/
│   ├── App.jsx
│   └── main.jsx
├── package.json
├── vite.config.js
└── README.md
```

## Running Tests

Run the backend tests:

```bash
python -m pytest backend/tests/ -v
```

Build the frontend:

```bash
npm run build
```

## Security & Privacy

- Each visitor receives an independent session when multi-tenant mode is enabled.
- Uploaded logs are processed in temporary server memory.
- Session data is cleared when the session expires or the backend restarts.
- Upload size and resource limits help protect the backend.
- Detection is rule-based and intended for demonstration purposes.

## Deployment

- **Frontend:** Vercel
- **Backend:** Render

Public uploads require multi-tenant sessions to be enabled on the backend.

---

**ThreatLens — Turning Security Logs into Actionable Insights.**
