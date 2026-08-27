# 🔍 Log Analyzer

Herramienta en Python que parsea logs de dispositivos de red, detecta anomalías contra umbrales configurables y envía alertas por correo. Incluye una **CLI** y una **app web** (Flask), ambas usando el mismo motor de detección.

Built by **Efraín Rojas Artavia**

---

## Features

- ✅ Parsea logs de **routers, switches y firewalls**
- ✅ Detecta: interfaz caída, CPU alta, fallos de autenticación, link flaps, avisos de memoria, caídas de BGP/OSPF, errores genéricos
- ✅ **Umbrales configurables** por tipo de evento (y ajustables en vivo desde la web)
- ✅ Exporta **reporte Excel** con hojas de Events + Anomalies
- ✅ Envía **alertas por correo** cuando se detectan anomalías
- ✅ CLI con argumentos y **demo web interactiva** con gráficos
- ✅ Un solo motor de parsing (`patterns.py`) compartido entre CLI y web — nunca divergen

---

## Estructura del proyecto

```
log-analyzer/
├── patterns.py             # Patrones, severidad y umbrales — fuente única de verdad
├── log_analyzer.py         # CLI: parsea logs/, exporta Excel, envía alertas
├── config.py                # Carga umbrales + credenciales de correo (desde .env)
├── generate_sample_logs.py # Genera logs de ejemplo para probar
├── app.py                   # App web Flask (usa patterns.py, no duplica lógica)
├── templates/index.html    # Frontend de la demo web (tema, i18n, gráficos)
├── requirements.txt
├── Procfile                 # Deploy con gunicorn (Heroku/Railway/etc.)
└── .env.example             # Plantilla de variables de entorno
```

---

## Quick Start — CLI

```bash
# 1. Clonar
git clone https://github.com/efrabuilder/log-analyzer.git
cd log-analyzer

# 2. Instalar dependencias
py -m pip install -r requirements.txt

# 3. (Opcional) configurar alertas por correo
cp .env.example .env
# editá .env con tus credenciales reales — nunca se sube a git

# 4. Generar logs de ejemplo
py generate_sample_logs.py

# 5. Correr
py log_analyzer.py
```

### Uso

```bash
# Analiza la carpeta logs/ (default)
py log_analyzer.py

# Analiza archivos específicos
py log_analyzer.py router.log switch.log

# Analiza un directorio
py log_analyzer.py --dir /var/log/network

# Solo resumen (sin exportar Excel)
py log_analyzer.py --summary

# Sin alertas por correo
py log_analyzer.py --no-email
```

---

## Quick Start — App web

La demo web deja pegar/subir logs y ver el análisis con gráficos, umbrales editables en vivo, vista previa de la alerta por correo y exportación a Excel, todo corriendo contra el mismo motor de parsing que la CLI.

```bash
py -m pip install -r requirements.txt
py app.py
```

Abrí `http://127.0.0.1:5000`. Para producción se usa gunicorn (ver `Procfile`):

```bash
gunicorn app:app
```

Variable de entorno opcional: `FLASK_DEBUG=1` activa el modo debug de Flask solo en desarrollo local (nunca en producción).

---

## Configuración por variables de entorno

Las credenciales de correo **no van en el código** — se leen de variables de entorno (vía `python-dotenv`). Copiá `.env.example` a `.env` y completá:

| Variable | Descripción |
|---|---|
| `EMAIL_ALERTS_ENABLED` | `true`/`false` — activa el envío de alertas |
| `SMTP_SENDER` | Cuenta remitente |
| `SMTP_PASSWORD` | Contraseña / app password |
| `SMTP_HOST`, `SMTP_PORT` | Servidor SMTP |
| `SMTP_RECIPIENTS` | Lista separada por comas |

`.env` está en `.gitignore` — nunca se sube al repositorio.

---

## Eventos detectados

| Evento | Umbral por defecto |
|-------|------------------|
| Interfaz caída | 2 ocurrencias |
| CPU alta (>85%) | 3 ocurrencias |
| Fallos de autenticación | 5 ocurrencias |
| Link flap | 3 ocurrencias |
| Aviso de memoria | 2 ocurrencias |
| Vecino OSPF caído | 1 ocurrencia |
| Caída de sesión BGP | 1 ocurrencia |
| Error genérico | 10 ocurrencias |

Todos los umbrales viven en `patterns.py` (`DEFAULT_THRESHOLDS`) y se pueden ajustar ahí, en `.env`/`config.py` para la CLI, o en vivo desde la interfaz web.

---

## Sample Output (CLI)

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
| `re` | Regex log parsing (`patterns.py`) |
| `openpyxl` | Reporte Excel |
| `smtplib` | Alertas por correo |
| `argparse` | Interfaz CLI |
| `Flask` + `gunicorn` | App web |
| `python-dotenv` | Variables de entorno / credenciales |
| Chart.js + SheetJS (CDN) | Gráficos y exportación xlsx en el frontend |

---

## License
MIT
