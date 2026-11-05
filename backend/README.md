# ThreatLens – Phase 2: Python Detection Engine

> **Standalone Python backend · No network access · Demo data only**

⚠️ **Disclaimer** – All log data, IP addresses, and alerts in this phase are
**completely simulated**. This engine does **not** perform network scanning,
packet capture, external IP lookups, or any real system monitoring. IP addresses
use [RFC 5737](https://www.rfc-editor.org/rfc/rfc5737) documentation ranges.

---

## Overview

The detection engine parses a CSV log file, validates its structure, and applies
a set of transparent, rule-based detectors to produce structured security alerts.

```
backend/
├── __init__.py
├── main.py               ← CLI entry point
├── log_parser.py         ← CSV loading, validation, normalisation
├── detector.py           ← Detection rules + alert generation
├── requirements.txt
├── data/
│   └── sample_logs.csv   ← Synthetic demo dataset
├── tests/
│   ├── __init__.py
│   └── test_engine.py    ← Unit tests (pytest)
└── README.md             ← This file
```

---

## Prerequisites

- Python **3.10** or later
- `pip` (bundled with Python)

Verify:
```bash
python --version   # must be 3.10+
pip --version
```

---

## Installation

It is strongly recommended to use a virtual environment:

```bash
# From the ThreatLens project root
python -m venv .venv

# Activate (Windows PowerShell)
.venv\Scripts\Activate.ps1

# Activate (macOS / Linux)
source .venv/bin/activate

# Install dependencies
pip install -r backend/requirements.txt
```

---

## Running the engine

```bash
# Against the bundled sample dataset (human-readable output)
python -m backend.main

# Against a custom log file
python -m backend.main path/to/your/logfile.csv

# JSON output (useful for piping)
python -m backend.main --json
```

---

## CSV Log Schema

All CSV files must use the following columns (order does not matter;
extra columns are silently ignored):

| Column | Type | Required | Description |
|---|---|---|---|
| `timestamp` | ISO-8601 datetime string | ✅ | e.g. `2026-10-20 14:58:03` |
| `source_ip` | IPv4 address string | ✅ | Source host (RFC 5737 in samples) |
| `event_type` | String (see table below) | ✅ | Category of log event |
| `username` | String | ✅ | Account involved (may be empty) |
| `status` | `SUCCESS` \| `FAILURE` \| `BLOCKED` \| `UNKNOWN` | ✅ | Outcome |

### Accepted `event_type` values

| Value | Description |
|---|---|
| `LOGIN_FAILURE` | Failed authentication attempt |
| `LOGIN_SUCCESS` | Successful authentication |
| `PORT_SCAN` | Port scan probe detected |
| `CONNECTION_ATTEMPT` | Inbound connection attempt |
| `MALWARE_DETECTED` | Malware signature match |
| `PRIVILEGE_ESCALATION` | Unexpected privilege elevation |
| `POLICY_VIOLATION` | Access policy breach |
| `DATA_TRANSFER` | Large/suspicious data transfer |
| `DNS_QUERY` | DNS lookup |
| `FILE_ACCESS` | File system access |

> Unrecognised values are kept in the DataFrame but trigger a log warning.

### Minimal valid CSV example

```csv
timestamp,source_ip,event_type,username,status
2026-10-20 08:00:00,192.0.2.10,LOGIN_SUCCESS,alice,SUCCESS
2026-10-20 08:00:05,203.0.113.42,LOGIN_FAILURE,admin,FAILURE
```

---

## Detection Rules

All thresholds are configurable via `DetectorConfig` in `detector.py`.

| Rule | Trigger | Severity | Default threshold | Window |
|---|---|---|---|---|
| **BruteForce** | ≥ 5 `LOGIN_FAILURE` from same IP | Critical | 5 events | 60 s |
| **PortScan** | ≥ 3 `PORT_SCAN` from same IP | High | 3 events | 60 s |
| **RepeatedConnect** | ≥ 10 `CONNECTION_ATTEMPT` from same IP | Medium | 10 events | 120 s |
| **MalwareEvent** | Any `MALWARE_DETECTED` event | Critical | 1 event | immediate |
| **PrivEsc** | Any `PRIVILEGE_ESCALATION` event | Critical | 1 event | immediate |

### Alert deduplication

A log row can match multiple rules. To avoid inflating alert counts:

1. Each matching row is tagged with every rule that matched it.
2. Matches from the same source IP whose **evidence sets overlap** (at least one
   shared `timestamp + event_type`) are merged into a single alert.
3. The merged alert carries the **union** of all evidence rows (no duplicates),
   **all** matching rule names in `rules_matched`, and the **highest** severity
   of the contributing rules.

---

## Alert Schema

Each alert is a structured object with:

```json
{
  "alert_id":      "TL-A1B2C3D4",
  "generated_at":  "2026-10-20T10:30:00+00:00",
  "source_ip":     "203.0.113.42",
  "event_type":    "LOGIN_FAILURE",
  "severity":      "Critical",
  "rules_matched": ["BruteForce"],
  "evidence":      [
    { "timestamp": "...", "source_ip": "...", "event_type": "...",
      "username": "...", "status": "..." }
  ],
  "explanation":   "BruteForce: 7 LOGIN_FAILURE events from 203.0.113.42 within 60 seconds."
}
```

---

## FastAPI Server & REST API (Phase 3)

Run the backend server locally with Uvicorn:

```bash
python -m uvicorn backend.api:app --reload --port 8000
```

### Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Health check & engine status |
| `GET` | `/api/summary` | Summary stats, activity timeline, severity breakdown, suspicious IPs |
| `GET` | `/api/alerts` | Filterable alerts (`?severity=Critical&status=Open&search=...`) |
| `GET` | `/api/logs` | Parsed log rows (`?level=WARN&search=...&limit=200`) |
| `POST` | `/api/analyze` | Multipart CSV file upload, schema validation & threat detection |
| `POST` | `/api/reset` | Reset dataset back to `sample_logs.csv` |

---

## Running the tests

Tests use [pytest](https://pytest.org). Run from the **project root**:

```bash
# Run all 55 tests (detector + FastAPI)
python -m pytest backend/tests/ -v

# Run with short summary
python -m pytest backend/tests/ -v --tb=short

# Run only API tests
python -m pytest backend/tests/test_api.py -v
```

### Test categories

| Class | What it covers |
|---|---|
| `TestLogParser` | CSV loading, validation, timestamp parsing, edge cases |
| `TestDetectorNoThreats` | Normal/benign logs → zero alerts |
| `TestBruteForceRule` | BruteForce trigger, threshold, evidence count |
| `TestPortScanRule` | PortScan trigger and threshold |
| `TestRepeatedConnectRule` | RepeatedConnect trigger and threshold |
| `TestImmediateRules` | MalwareEvent and PrivEsc |
| `TestDeduplication` | Multi-rule merge, unique alert IDs |
| `TestSampleData` | Integration test against `sample_logs.csv` |
| `TestHealthEndpoint` | GET `/api/health` status and metadata |
| `TestSummaryEndpoint` | GET `/api/summary` metrics and chart structures |
| `TestAlertsEndpoint` | GET `/api/alerts` filtering by severity and search |
| `TestLogsEndpoint` | GET `/api/logs` filtering by level and search |
| `TestAnalyzeEndpoint` | POST `/api/analyze` valid CSVs and rejection of invalid formats/schemas |
| `TestResetEndpoint` | POST `/api/reset` state restore |

---

## Limitations & Scope

- All data is synthetic and designed for demonstration/testing.
- No live network sniffing, packet capture, or raw socket listeners.
- No external outbound network requests.
- No authentication or production deployment infrastructure.
