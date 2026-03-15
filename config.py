# config.py — Log Analyzer configuration

CONFIG = {
    # ── Thresholds ─────────────────────────────────────────────────────────────
    # How many occurrences before flagging as anomaly
    "thresholds": {
        "interface_down":         2,
        "high_cpu":               3,
        "authentication_failure": 5,
        "link_flap":              3,
        "memory_warning":         2,
        "ospf_neighbor_down":     1,
        "bgp_session_drop":       1,
        "error_generic":          10,
        "default":                5,
        # Percentage thresholds
        "high_cpu_pct":           85,
        "memory_warning_pct":     85,
    },

    # ── Email Alerts ───────────────────────────────────────────────────────────
    "email": {
        "enabled":    False,           # Set True to enable
        "sender":     "you@gmail.com",
        "password":   "your_app_password",
        "smtp_host":  "smtp.gmail.com",
        "smtp_port":  587,
        "recipients": ["noc@company.com", "admin@company.com"],
    }
}
