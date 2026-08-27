# config.py — Log Analyzer configuration
#
# Los umbrales viven en patterns.py (fuente única compartida con app.py).
# Las credenciales de correo NUNCA van hardcodeadas: se leen de variables
# de entorno (ver .env.example) para que no queden expuestas en git.

import os
from dotenv import load_dotenv

from patterns import DEFAULT_THRESHOLDS

load_dotenv()  # lee un archivo .env local si existe (no se sube a git)


def _split_recipients(raw: str) -> list:
    return [r.strip() for r in raw.split(",") if r.strip()]


CONFIG = {
    # ── Thresholds ─────────────────────────────────────────────────────────────
    "thresholds": DEFAULT_THRESHOLDS,

    # ── Email Alerts ───────────────────────────────────────────────────────────
    # Definí estas variables en un archivo .env (ver .env.example) o en el
    # entorno del sistema/CI. Si SMTP_SENDER o SMTP_PASSWORD no están
    # definidas, el envío de alertas queda deshabilitado automáticamente.
    "email": {
        "enabled":    os.environ.get("EMAIL_ALERTS_ENABLED", "false").lower() == "true",
        "sender":     os.environ.get("SMTP_SENDER", ""),
        "password":   os.environ.get("SMTP_PASSWORD", ""),
        "smtp_host":  os.environ.get("SMTP_HOST", "smtp.gmail.com"),
        "smtp_port":  int(os.environ.get("SMTP_PORT", "587")),
        "recipients": _split_recipients(os.environ.get("SMTP_RECIPIENTS", "")),
    }
}

# Si falta sender/password/recipients, no tiene sentido intentar enviar
# aunque EMAIL_ALERTS_ENABLED esté en true — evita errores confusos en runtime.
_email = CONFIG["email"]
if _email["enabled"] and not (_email["sender"] and _email["password"] and _email["recipients"]):
    _email["enabled"] = False
