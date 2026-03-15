# 🔍 Log Analyzer Script

Python CLI tool that parses network device logs, detects anomalies and sends email alerts when thresholds are exceeded.

Built by **Efraín Rojas Artavia**

---

## Features

- ✅ Parses **router, switch and firewall** log files
- ✅ Detects: interface down, high CPU, auth failures, link flaps, memory warnings, BGP/OSPF drops
- ✅ **Configurable thresholds** per event type
- ✅ Exports color-coded **Excel report** with Events + Anomalies sheets
- ✅ Sends **email alerts** when anomalies are found
- ✅ Clean **CLI interface** with arguments

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/efrabuilder/log-analyzer.git
cd log-analyzer

# 2. Install
py -m pip install -r requirements.txt

# 3. Generate sample logs
py generate_sample_logs.py

# 4. Run
py log_analyzer.py
```

---

## Usage

```bash
# Analyze logs/ folder (default)
py log_analyzer.py

# Analyze specific files
py log_analyzer.py router.log switch.log

# Analyze a directory
py log_analyzer.py --dir /var/log/network

# Summary only (no Excel export)
py log_analyzer.py --summary

# Skip email alerts
py log_analyzer.py --no-email
```

---

## Detected Events

| Event | Default Threshold |
|-------|------------------|
| Interface down | 2 occurrences |
| High CPU (>85%) | 3 occurrences |
| Auth failures | 5 occurrences |
| Link flap | 3 occurrences |
| Memory warning | 2 occurrences |
| OSPF neighbor down | 1 occurrence |
| BGP session drop | 1 occurrence |

---

## Sample Output

```
══════════════════════════════════════════════════
  LOG ANALYZER — SUMMARY
══════════════════════════════════════════════════
  Log files analyzed : 2
  Total events       : 31
  CRITICAL           : 8
  WARNING            : 14
  ERROR              : 6
  Anomalies detected : 5
══════════════════════════════════════════════════

ANOMALIES:
  [CRITICAL] Interface Down occurred 6x (threshold: 2)
  [CRITICAL] Bgp Session Drop occurred 2x (threshold: 1)
  [WARNING]  Authentication Failure occurred 8x (threshold: 5)
  [CRITICAL] High Cpu: 95% on router-cr-01 (limit: 85%)
```

---

## Tech Stack

| Tool | Purpose |
|------|---------|
| `re` | Regex log parsing |
| `pandas` | Data processing |
| `openpyxl` | Excel report |
| `smtplib` | Email alerts |
| `argparse` | CLI interface |

---

## License
MIT
