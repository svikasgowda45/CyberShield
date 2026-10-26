# CyberShield

CyberShield is a local-first security log monitoring dashboard. All application code—including log parsing, detection rules, SQLite storage, and the Streamlit interface—is in the single file `vikas_cybershield.py`.

## Features

- Parses common Linux authentication logs and Windows Event Viewer XML/text exports.
- Detects repeated failed logins from one IP within a configurable time window.
- Flags IP addresses on a manually maintained watchlist.
- Identifies successful logins during unusual local hours (22:00–05:00).
- Raises critical alerts when a successful login follows repeated failures.
- Stores analyzed events locally in SQLite and displays severity summaries.

## Run on Windows

Open PowerShell in this folder and run:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
streamlit run vikas_cybershield.py
```

If PowerShell blocks activation, use the virtual environment's Python directly:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m streamlit run vikas_cybershield.py
```

## Run on Linux or macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
streamlit run vikas_cybershield.py
```

Upload a `.txt`, `.log`, or `.xml` log file, or paste log text into the app. Detection thresholds and watched IPs can be configured in the sidebar. The SQLite database is created locally when the application runs.

This project is a rule-based triage aid, not a replacement for a SIEM or human investigation. Log content is analyzed locally; the app does not call external IP reputation services.

## Project files

The project consists of exactly four files:

- `vikas_cybershield.py` — all application code
- `README.md` — project and run instructions
- `requirements.txt` — Python dependency list
- `.gitignore` — generated files excluded from version control
