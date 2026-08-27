# patterns.py — Efraín Rojas Artavia
#
# Fuente única de verdad para los patrones de detección, severidades y
# umbrales por defecto. Tanto app.py (web) como log_analyzer.py (CLI)
# importan de aquí para que nunca queden dos copias divergentes.

import re

PATTERNS = {
    "interface_down": re.compile(
        r"(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}).*"
        r"(?P<device>\S+).*"
        r"(?:interface|line protocol|Interface)\s+(?P<interface>\S+).*"
        r"(?:down|DOWN|went down)", re.IGNORECASE
    ),
    "high_cpu": re.compile(
        r"(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}).*"
        r"CPU\s+(?:utilization|usage)[:\s]+(?P<value>\d+)%", re.IGNORECASE
    ),
    "authentication_failure": re.compile(
        r"(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}).*"
        r"(?:authentication failure|login failed|invalid password|auth fail)"
        r".*(?:user|from)?\s*(?P<user>\S+)?",
        re.IGNORECASE
    ),
    "link_flap": re.compile(
        r"(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}).*"
        r"(?P<interface>\S+).*(?:changed state|flap|up/down)", re.IGNORECASE
    ),
    "memory_warning": re.compile(
        r"(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}).*"
        r"(?:memory|mem)\s+(?:warning|critical|low|usage)[:\s]+(?P<value>\d+)%",
        re.IGNORECASE
    ),
    "ospf_neighbor_down": re.compile(
        r"(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}).*"
        r"OSPF.*neighbor.*(?:down|dead|timeout)", re.IGNORECASE
    ),
    "bgp_session_drop": re.compile(
        r"(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}).*"
        r"BGP.*(?:session|peer).*(?:dropped|down|reset|closed)", re.IGNORECASE
    ),
    "error_generic": re.compile(
        r"(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}).*"
        r"\b(?:ERROR|CRITICAL|FATAL|EMERG|ALERT)\b", re.IGNORECASE
    ),
}

SEVERITY = {
    "interface_down":         "CRITICAL",
    "high_cpu":               "WARNING",
    "authentication_failure": "WARNING",
    "link_flap":              "WARNING",
    "memory_warning":         "WARNING",
    "ospf_neighbor_down":     "CRITICAL",
    "bgp_session_drop":       "CRITICAL",
    "error_generic":          "ERROR",
}

# Umbrales por defecto (# de ocurrencias antes de marcar como anomalía).
# config.py (CLI) y app.py (web) parten de este mismo diccionario.
DEFAULT_THRESHOLDS = {
    "interface_down":         2,
    "high_cpu":               3,
    "authentication_failure": 5,
    "link_flap":              3,
    "memory_warning":         2,
    "ospf_neighbor_down":     1,
    "bgp_session_drop":       1,
    "error_generic":          10,
    "default":                5,
    # Umbrales de porcentaje (independientes del conteo de ocurrencias)
    "high_cpu_pct":           85,
    "memory_warning_pct":     85,
}


def parse_line(line, event_types=PATTERNS.keys()):
    """Intenta matchear una línea de log contra los patrones conocidos.
    Devuelve (event_type, match) o (None, None) si no matchea ninguno."""
    for event_type in event_types:
        m = PATTERNS[event_type].search(line)
        if m:
            return event_type, m
    return None, None
