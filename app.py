# app.py — Log Analyzer Web Interface
# Efraín Rojas Artavia

import os
from flask import Flask, render_template, request, jsonify
from collections import defaultdict

from patterns import PATTERNS, SEVERITY, DEFAULT_THRESHOLDS as THRESHOLDS

app = Flask(__name__)

MAX_LOG_LINES = 20000  # evita que un pegado gigante congele una petición

SAMPLE_LOGS = """Mar 15 08:01:22 router-cr-01 %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down
Mar 15 08:01:25 router-cr-01 %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to up
Mar 15 08:02:10 router-cr-01 %LINK-3-UPDOWN: Interface GigabitEthernet0/2, changed state to down
Mar 15 08:03:00 router-cr-01 %BGP-5-ADJCHANGE: BGP peer 10.0.0.2 session dropped
Mar 15 08:03:30 router-cr-01 %OSPF-5-ADJCHG: OSPF neighbor 192.168.1.1 went down
Mar 15 08:04:00 router-cr-01 %CPU-4-HIGH: CPU utilization: 92% for 5 minutes
Mar 15 08:05:00 router-cr-01 %CPU-4-HIGH: CPU utilization: 88% for 5 minutes
Mar 15 08:06:00 router-cr-01 %SEC-6-IPACCESSLOGP: Authentication failure for user admin from 192.168.1.50
Mar 15 08:07:00 router-cr-01 %SEC-6-IPACCESSLOGP: login failed user root from 10.10.1.5
Mar 15 08:08:00 router-cr-01 %SEC-6-IPACCESSLOGP: auth fail user cisco from 10.0.0.99
Mar 15 08:09:00 router-cr-01 %SEC-6-IPACCESSLOGP: invalid password user admin from 192.168.1.51
Mar 15 08:10:00 router-cr-01 %SEC-6-IPACCESSLOGP: Authentication failure for user test from 192.168.1.100
Mar 15 08:11:00 router-cr-01 %SYS-2-MALLOCFAIL: Memory allocation failed, memory usage: 91%
Mar 15 08:12:00 router-cr-01 %LINK-3-UPDOWN: Interface GigabitEthernet0/1, line protocol went down
Mar 15 08:13:00 router-cr-01 %BGP-5-ADJCHANGE: BGP peer session dropped neighbor 10.0.0.3 reset
Mar 15 08:14:00 router-cr-01 ERROR: Routing table update failed
Mar 15 08:15:00 router-cr-01 CRITICAL: Core dump generated
Mar 15 08:16:00 router-cr-01 %CPU-4-HIGH: CPU utilization: 95% for 10 minutes
Mar 15 08:17:00 switch-floor2 %LINK-3-UPDOWN: Interface FastEthernet0/24 changed state to down
Mar 15 08:18:00 switch-floor2 %SEC-6-IPACCESSLOGP: Authentication failure for user admin from 10.1.1.5
Mar 15 08:19:00 switch-floor2 %CPU-4-HIGH: CPU utilization: 87%
Mar 15 08:20:00 switch-floor2 %SYS-2-MALLOCFAIL: memory warning usage: 88%
Mar 15 08:21:00 switch-floor2 CRITICAL: Stack member unreachable
Mar 15 08:22:00 switch-floor2 ERROR: VLAN database corruption detected"""


def parse_logs(text):
    events = []
    lines = text.splitlines()[:MAX_LOG_LINES]
    for lineno, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue
        for event_type, pattern in PATTERNS.items():
            m = pattern.search(line)
            if m:
                groups = m.groupdict()
                events.append({
                    "event_type": event_type,
                    "severity":   SEVERITY.get(event_type, "INFO"),
                    "timestamp":  groups.get("timestamp", ""),
                    "interface":  groups.get("interface", ""),
                    "value":      groups.get("value", ""),
                    "user":       groups.get("user", ""),
                    "raw_line":   line[:200],
                    "line_no":    lineno,
                })
                break
    return events


def detect_anomalies(events, thresholds=None):
    thresholds = thresholds or THRESHOLDS
    anomalies = []
    counts = defaultdict(int)
    for e in events:
        counts[e["event_type"]] += 1

    for event_type, count in counts.items():
        threshold = thresholds.get(event_type, thresholds.get("default", 5))
        if count >= threshold:
            anomalies.append({
                "event_type": event_type,
                "count":      count,
                "threshold":  threshold,
                "severity":   SEVERITY.get(event_type, "WARNING"),
                "message":    f"{event_type.replace('_',' ').title()} — {count} occurrences (threshold: {threshold})"
            })

    for e in events:
        if e["event_type"] in ("high_cpu", "memory_warning") and e.get("value"):
            try:
                val = int(e["value"])
                limit = thresholds.get(e["event_type"] + "_pct", 85)
                if val >= limit:
                    anomalies.append({
                        "event_type": e["event_type"],
                        "count":      1,
                        "threshold":  limit,
                        "severity":   "CRITICAL" if val >= 95 else "WARNING",
                        "message":    f"{e['event_type'].replace('_',' ').title()}: {val}% (limit: {limit}%)"
                    })
            except ValueError:
                pass

    seen = set()
    unique = []
    for a in anomalies:
        key = a["event_type"] + a["message"]
        if key not in seen:
            seen.add(key)
            unique.append(a)
    return unique


def _parse_thresholds_override(raw):
    """Valida un dict de umbrales personalizados que venga del cliente.
    Solo acepta claves conocidas y valores enteros positivos; el resto se ignora."""
    if not isinstance(raw, dict):
        return None
    merged = dict(THRESHOLDS)
    for key, value in raw.items():
        if key not in THRESHOLDS:
            continue
        try:
            ival = int(value)
            if ival > 0:
                merged[key] = ival
        except (TypeError, ValueError):
            continue
    return merged


# ── Routes ─────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid or missing JSON body"}), 400

    log_text = (data.get("log_text") or "").strip()
    if not log_text:
        return jsonify({"error": "No log text provided"}), 400

    if len(log_text) > 5_000_000:  # ~5 MB de texto
        return jsonify({"error": "Log text too large (max ~5 MB)"}), 413

    thresholds = _parse_thresholds_override(data.get("thresholds"))

    events    = parse_logs(log_text)
    anomalies = detect_anomalies(events, thresholds)

    counts = defaultdict(int)
    for e in events:
        counts[e["severity"]] += 1

    return jsonify({
        "events":    events,
        "anomalies": anomalies,
        "stats": {
            "total":    len(events),
            "critical": counts["CRITICAL"],
            "warning":  counts["WARNING"],
            "error":    counts["ERROR"],
            "anomalies_count": len(anomalies),
        }
    })


@app.route("/api/sample")
def sample():
    return jsonify({"log_text": SAMPLE_LOGS})


@app.route("/api/config")
def get_config():
    """Expone los umbrales y la severidad por defecto para que el frontend
    no tenga que mantener una copia hardcodeada separada (single source of
    truth = patterns.py)."""
    return jsonify({"thresholds": THRESHOLDS, "severity": SEVERITY})


if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug_mode)
