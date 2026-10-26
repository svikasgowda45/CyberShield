from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import xml.etree.ElementTree as ET
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

import streamlit as st

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "cybershield.db"

FAILED_PATTERNS = (
    re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)", re.I),
    re.compile(r"Failed publickey for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)", re.I),
    re.compile(r"authentication failure;.*?user=(?P<user>\S+).*?rhost=(?P<ip>[0-9a-fA-F:.]+)", re.I),
)
SUCCESS_PATTERNS = (
    re.compile(r"Accepted \S+ for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)", re.I),
)
SYSLOG_TIME = re.compile(r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<clock>\d{2}:\d{2}:\d{2})")
ISO_TIME = re.compile(r"(?P<time>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _parse_timestamp(value: str | None) -> str:
    if not value:
        return _utc_now()

    iso_match = ISO_TIME.search(value)
    if iso_match:
        candidate = iso_match.group("time").replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(candidate)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc).isoformat(timespec="seconds")
        except ValueError:
            pass

    syslog_match = SYSLOG_TIME.search(value)
    if syslog_match:
        try:
            parsed = datetime.strptime(
                f"{datetime.now().year} {syslog_match.group('month')} {syslog_match.group('day')} {syslog_match.group('clock')}",
                "%Y %b %d %H:%M:%S",
            ).replace(tzinfo=timezone.utc)
            return parsed.isoformat(timespec="seconds")
        except ValueError:
            pass

    return _utc_now()


def _normalize_ip(value: str) -> str:
    cleaned = (value or "").strip()
    if cleaned in {"-", "::1", "127.0.0.1"}:
        return ""
    return cleaned


def parse_log(text: str) -> list[dict]:
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        root = None

    if root is not None:
        events: list[dict] = []
        for event in root.iter():
            if event.tag.rsplit("}", 1)[-1] != "Event":
                continue
            event_id = None
            timestamp = None
            fields: dict[str, str] = {}
            for element in event.iter():
                tag = element.tag.rsplit("}", 1)[-1]
                if tag == "EventID" and element.text:
                    event_id = element.text.strip()
                elif tag == "TimeCreated":
                    timestamp = element.attrib.get("SystemTime")
                elif tag == "Data" and element.attrib.get("Name"):
                    fields[element.attrib["Name"]] = element.text or ""
            outcome = {"4625": "FAILURE", "4624": "SUCCESS"}.get(event_id or "")
            if outcome is None:
                continue
            raw = ET.tostring(event, encoding="unicode")
            ip = _normalize_ip(fields.get("IpAddress", ""))
            events.append(
                {
                    "timestamp": _parse_timestamp(timestamp or raw),
                    "username": fields.get("TargetUserName", "").strip(),
                    "ip": ip,
                    "outcome": outcome,
                    "source": "Windows Event Log XML",
                    "raw": raw,
                }
            )
        if events:
            return events

    events: list[dict] = []
    for line in text.splitlines():
        if not line.strip():
            continue

        outcome = None
        username = ""
        ip = ""

        for pattern in FAILED_PATTERNS:
            match = pattern.search(line)
            if match:
                outcome = "FAILURE"
                username = match.group("user")
                ip = _normalize_ip(match.group("ip"))
                break

        if outcome is None:
            for pattern in SUCCESS_PATTERNS:
                match = pattern.search(line)
                if match:
                    outcome = "SUCCESS"
                    username = match.group("user")
                    ip = _normalize_ip(match.group("ip"))
                    break

        windows_id = re.search(r"\bEventID\s*=\s*(4624|4625)\b", line, re.I)
        if outcome is None and windows_id:
            outcome = "FAILURE" if windows_id.group(1) == "4625" else "SUCCESS"
            user_match = re.search(r"\b(?:TargetUserName|AccountName)\s*=\s*['\"]?([^\s,'\"]+)", line, re.I)
            ip_match = re.search(r"\b(?:IpAddress|SourceNetworkAddress)\s*=\s*['\"]?([0-9a-fA-F:.]+)", line, re.I)
            username = user_match.group(1) if user_match else ""
            ip = _normalize_ip(ip_match.group(1)) if ip_match else ""

        if outcome:
            events.append(
                {
                    "timestamp": _parse_timestamp(line),
                    "username": username,
                    "ip": ip,
                    "outcome": outcome,
                    "source": "Linux auth log" if not windows_id else "Windows Event Log text",
                    "raw": line.strip(),
                }
            )

    return events


def init_db(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint TEXT NOT NULL UNIQUE,
            timestamp TEXT NOT NULL,
            username TEXT NOT NULL DEFAULT '',
            ip TEXT NOT NULL DEFAULT '',
            outcome TEXT NOT NULL,
            source TEXT NOT NULL,
            raw TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'INFO',
            rules TEXT NOT NULL DEFAULT ''
        );
        """
    )
    return connection


def ingest_events(conn: sqlite3.Connection, events: list[dict]) -> int:
    inserted = 0
    for event in events:
        fingerprint = hashlib.sha256(
            json.dumps(
                [event["timestamp"], event["username"], event["ip"], event["outcome"], event["raw"]],
                ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()
        cursor = conn.execute(
            """
            INSERT OR IGNORE INTO events
                (fingerprint, timestamp, username, ip, outcome, source, raw)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                fingerprint,
                event["timestamp"],
                event["username"],
                event["ip"],
                event["outcome"],
                event["source"],
                event["raw"],
            ),
        )
        inserted += cursor.rowcount
    conn.commit()
    return inserted


def get_events(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM events ORDER BY timestamp DESC, id DESC"
    ).fetchall()
    return [dict(row) for row in rows]


def _time_value(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def evaluate_events(events: list[dict], threshold: int, window_minutes: int, watchlist: set[str]) -> dict[int, dict[str, str]]:
    normalized_watchlist = {ip.strip() for ip in watchlist if ip.strip()}
    ordered = sorted(events, key=lambda item: (_time_value(item["timestamp"]), item["id"]))
    failures: dict[str, deque] = defaultdict(deque)
    results: dict[int, dict[str, str]] = {}
    window = timedelta(minutes=window_minutes)

    for event in ordered:
        timestamp = _time_value(event["timestamp"])
        ip = event.get("ip", "").strip()
        rules: list[str] = []
        severity = "INFO"

        if ip and ip in normalized_watchlist:
            severity = "HIGH"
            rules.append("Watched IP address")

        if event["outcome"] == "FAILURE" and ip:
            attempts = failures[ip]
            cutoff = timestamp - window
            while attempts and attempts[0] < cutoff:
                attempts.popleft()
            attempts.append(timestamp)
            if len(attempts) >= threshold:
                severity = "HIGH"
                rules.append(f"Repeated failures ({len(attempts)} within {window_minutes}m)")

        if event["outcome"] == "SUCCESS":
            local_hour = timestamp.astimezone().hour
            if local_hour >= 22 or local_hour < 5:
                if severity == "INFO":
                    severity = "MEDIUM"
                rules.append("Unusual login time (22:00–05:00 local)")

            if ip and failures.get(ip):
                cutoff = timestamp - window
                while failures[ip] and failures[ip][0] < cutoff:
                    failures[ip].popleft()
                if len(failures[ip]) >= threshold:
                    severity = "CRITICAL"
                    rules.append("Successful login after repeated failures")

        results[event["id"]] = {"severity": severity, "rules": "; ".join(rules)}

    return results


def create_summary_text(events: list[dict]) -> str:
    total = len(events)
    failures = sum(event["outcome"] == "FAILURE" for event in events)
    critical = sum(event["severity"] == "CRITICAL" for event in events)
    high = sum(event["severity"] == "HIGH" for event in events)
    medium = sum(event["severity"] == "MEDIUM" for event in events)
    return (
        f"Events: {total}\n"
        f"Failures: {failures}\n"
        f"Critical: {critical}\n"
        f"High: {high}\n"
        f"Medium: {medium}"
    )


st.set_page_config(page_title="CyberShield", page_icon="🛡️", layout="wide")
st.title("🛡️ CyberShield")
st.caption("Local security log triage dashboard")

conn = init_db(DB_PATH)

with st.sidebar:
    st.header("Detection rules")
    threshold = st.number_input("Failed attempts trigger", min_value=2, max_value=100, value=5)
    window_minutes = st.number_input("Window (minutes)", min_value=1, max_value=1440, value=10)
    watchlist_text = st.text_area("Watched IP addresses", placeholder="One IP per line")
    watchlist = {line.strip() for line in watchlist_text.splitlines() if line.strip()}

col_upload, col_info = st.columns([2, 1])
with col_upload:
    uploaded = st.file_uploader("Upload a log file", type=["txt", "log", "xml"])
    pasted = st.text_area("Or paste log text here", height=140)
    if st.button("Analyze logs", type="primary", use_container_width=True):
        text = ""
        if uploaded is not None:
            text = uploaded.getvalue().decode("utf-8", errors="replace")
        elif pasted.strip():
            text = pasted
        if not text.strip():
            st.warning("Upload a file or paste log lines before analyzing.")
        else:
            parsed_events = parse_log(text)
            inserted = ingest_events(conn, parsed_events)
            st.success(f"Analyzed {len(parsed_events)} records and stored {inserted} new events.")
            st.rerun()

with col_info:
    st.subheader("Supported inputs")
    st.markdown(
        "- Linux auth log text\n"
        "- Windows Event Log XML\n"
        "- Windows line-based log entries with EventID=4624 / 4625"
    )

all_events = get_events(conn)
if all_events:
    for row in all_events:
        row["severity"] = "INFO"
        row["rules"] = ""

    evaluations = evaluate_events(all_events, threshold, window_minutes, watchlist)
    for event in all_events:
        result = evaluations.get(event["id"], {"severity": "INFO", "rules": ""})
        event["severity"] = result["severity"]
        event["rules"] = result["rules"]
        conn.execute(
            "UPDATE events SET severity = ?, rules = ? WHERE id = ?",
            (result["severity"], result["rules"], event["id"]),
        )
    conn.commit()

all_events = get_events(conn)
failed_count = sum(event["outcome"] == "FAILURE" for event in all_events)
critical_count = sum(event["severity"] == "CRITICAL" for event in all_events)
high_count = sum(event["severity"] == "HIGH" for event in all_events)
medium_count = sum(event["severity"] == "MEDIUM" for event in all_events)

st.divider()
st.subheader("Security dashboard")
metric_cols = st.columns(5)
metric_cols[0].metric("Events", len(all_events))
metric_cols[1].metric("Failures", failed_count)
metric_cols[2].metric("Critical", critical_count)
metric_cols[3].metric("High", high_count)
metric_cols[4].metric("Medium", medium_count)

left, right = st.columns([3, 2])
with left:
    st.markdown("#### Recent events")
    if all_events:
        rows = [
            {
                "Time": datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00")).astimezone().strftime("%Y-%m-%d %H:%M:%S"),
                "Severity": event["severity"],
                "Outcome": event["outcome"],
                "Account": event["username"] or "—",
                "IP": event["ip"] or "—",
                "Rules": event["rules"] or "—",
            }
            for event in all_events[:200]
        ]
        st.dataframe(rows, use_container_width=True, hide_index=True)
    else:
        st.info("No events yet. Upload or paste a log sample to begin.")

with right:
    st.markdown("#### Severity distribution")
    severity_counts = {
        level: sum(event["severity"] == level for event in all_events)
        for level in ("CRITICAL", "HIGH", "MEDIUM", "INFO")
    }
    st.bar_chart(severity_counts)
    st.code(create_summary_text(all_events), language="text")

st.divider()
if all_events:
    st.subheader("Data export")
    text_output = "\n".join(
        f"{event['timestamp']} | {event['severity']} | {event['outcome']} | {event['username']} | {event['ip']} | {event['rules']}"
        for event in all_events[:100]
    )
    st.download_button("Download event summary", data=text_output, file_name="cybershield-events.txt", mime="text/plain")

conn.close()
