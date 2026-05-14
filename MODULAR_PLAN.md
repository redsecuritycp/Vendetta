# Plan de modularización vendetta

**Fecha**: 2026-05-14
**Autor**: ARM Oraculo (Claude) bajo regla arquitectura modular de Pablo
**Estado**: PROPUESTO (Fase 0 — solo plan + carpeta placeholder)

## Por qué este plan existe

Pablo (12/05/2026): *"si modificás un módulo y se daña, solo se daña ese módulo. si agregás un módulo nuevo, no tocamos el resto."*

Hoy vendetta es un **monolito flat**: 27 archivos `.py` viven en el root del proyecto, todos importándose entre sí por nombre absoluto (`from full_scan import FullScanner`). El entry real en producción es `api_server.py` (Flask, 147 líneas, PM2 `vendetta-api` en port 3004) — el `main.py` de 10 líneas del root es un **stub legacy de Replit** (devuelve `'OK'` y nunca se ejecuta). La UI Streamlit (`streamlit_app.py`, 857 líneas) **NO corre en ARM**, es código heredado del Replit. La división es por **herramienta técnica** (`xss_test.py`, `dir_fuzzer.py`, `recon.py`, etc.), no por feature — cada tool tiene una clase pero comparten `report_generator`, `db_manager`, `rate_limiter`, `auth_manager` sin frontera clara.

Encima hay **duplicación visible**: `recon.py` (317 líneas) y `security_tools/recon.py` (263), `sslstrip_sim.py` (217) y `security_tools/sslstrip_sim.py` (173), `xss_test.py` (286) y `security_tools/xss_test.py` (219), `load_test_engine.py` (220) y `load_test/load_test_engine.py` (220). Cualquier fix a una herramienta hoy implica decidir cuál de las dos copias es la verdadera.

Resultado: agregar un scanner nuevo significa tocar `full_scan.py` + `api_server.py` + `streamlit_app.py` + `template_engine.py`. Y nadie se acuerda cuál copia de `recon.py` es la canónica.

## Estado actual (auditado 2026-05-14)

| Métrica | Valor |
|---|---|
| Stack | Python 3.11 + Flask 3.1 + SQLite (vendetta.db) — Streamlit 1.52 presente pero NO corriendo en ARM |
| Entry point REAL | `api_server.py` (corrido por PM2 `vendetta-api`, port 3004) |
| Entry point STUB | `main.py` (10 líneas, legacy Replit, devuelve `'OK'`) |
| Entry secundario (sin uso) | `streamlit_app.py` (857 líneas, UI Streamlit — quedó en el repo desde Replit) |
| Líneas (entry real) | **147** |
| Total archivos `.py` | 27 (sin venv, sin __pycache__, sin .git) |
| Líneas totales `.py` | **7066** |
| DB | SQLite local `vendetta.db` (en `shared/`, persistente entre releases) |
| Endpoints API | 7 (GET /, POST /api/scan, POST /api/templates, GET /api/scans, GET /api/scans/<id>, GET /api/scans/<id>/report, GET /api/targets) |
| Modular hoy | **NO** — 27 archivos flat en el root, duplicación entre root y `security_tools/`, división por tool técnica no por feature |
| Dominio | https://vendetta-arm.duckdns.org |

Archivos grandes (>200 líneas) y dónde viven hoy:

- `streamlit_app.py` — 857 (UI no usada en ARM)
- `exploit_demo.py` — 762
- `full_scan.py` — 351
- `dir_fuzzer.py` — 362
- `recon.py` (root) — 317 / `security_tools/recon.py` — 263 (duplicado)
- `clickjacking_test.py` — 313
- `bypass_403.py` — 308
- `template_engine.py` — 303
- `xss_test.py` (root) — 286 / `security_tools/xss_test.py` — 219 (duplicado)
- `form_analyzer.py` — 267
- `subdomain_enum.py` — 254
- `slowloris.py` — 232
- `report_generator.py` — 224
- `load_test_engine.py` (root) — 220 / `load_test/load_test_engine.py` — 220 (duplicado idéntico)
- `sslstrip_sim.py` (root) — 217 / `security_tools/sslstrip_sim.py` — 173 (duplicado)

## Features identificados (candidatos a módulos)

Tabla con TODOS los scanners distinguibles + infra. Cada uno es un módulo candidato; los scanners se aíslan con interfaz común (`run(target, options) -> List[Finding]`).

| # | Feature | Archivo(s) hoy | Trigger / endpoint | Prioridad |
|---|---|---|---|---|
| 1 | **recon** (passive) | `recon.py` (+ duplicado en `security_tools/`) | `FullScanner._run_recon`, paso 1 del scan | media |
| 2 | **hsts-ssl** | `sslstrip_sim.py` (+ duplicado) | `FullScanner._run_hsts`, paso 2 | media |
| 3 | **xss** | `xss_test.py` (+ duplicado) | `FullScanner._run_xss`, paso 3 | media |
| 4 | **clickjacking** | `clickjacking_test.py` (+ `security_tools/clickjacking_test.html`) | paso 4 | media |
| 5 | **dir-fuzz** | `dir_fuzzer.py` | paso 5 | media |
| 6 | **forms** | `form_analyzer.py` | paso 6 | media |
| 7 | **subdomain-enum** | `subdomain_enum.py` | paso 7 | media |
| 8 | **bypass-403** | `bypass_403.py` | paso 8 | media |
| 9 | **slowloris** (DoS sim) | `slowloris.py` | UI Streamlit / standalone (no en `full_scan`) | baja |
| 10 | **load-test** | `load_test_engine.py` (+ `load_test/` standalone) | UI Streamlit / standalone | baja |
| 11 | **exploit-demo** | `exploit_demo.py` | UI Streamlit (educativo) | baja |
| 12 | **template-engine** (nuclei-like) | `template_engine.py` | `POST /api/templates` | alta (endpoint API live) |
| 13 | **scan-orchestrator** | `full_scan.py` | `POST /api/scan` (orquesta 1..8) | alta |
| 14 | **report-generator** | `report_generator.py` | `GET /api/scans/<id>/report` (HTML) | media (infra cross-feature) |
| 15 | **scan-storage** (DB) | `db_manager.py` (+ SQLite) | `GET /api/scans`, `GET /api/targets` | alta (infra) |
| 16 | **rate-limiter** | `rate_limiter.py` | usado por todos los scanners | infra (core) |
| 17 | **auth-manager** | `auth_manager.py` | inyecta headers/cookies a scanners | infra (core) |
| 18 | **url-validator** | `url_validator.py` (74 líneas) | guard pre-scan | utilidad chica — queda en `core/` |
| 19 | **streamlit-ui** | `streamlit_app.py` | NO corre en ARM (legacy Replit) | candidato a borrar o aislar como módulo opt-in |

## Estrategia

**A — Refactor incremental.** El stack (Flask + SQLite + clases-tool con interfaz simple) es liviano y funcional; un Strangler no se justifica para 7k líneas de pentest tooling que ya está en producción. La duplicación root↔`security_tools/` se resuelve **eligiendo la versión canónica del root** (más reciente, abril 2026 vs diciembre 2025) y borrando la copia en Fase 0.5. Cada scanner pasa a `modules/<feature>/` con la misma firma; `FullScanner` queda como **orquestador slim** que importa de los módulos.

## Estructura objetivo

```
vendetta/
├── api_server.py                      ← entry slim Flask (50-80 líneas: registro de blueprints)
├── core/
│   ├── __init__.py
│   ├── config.py                      ← env vars, paths
│   ├── db.py                          ← DBManager (de db_manager.py)
│   ├── rate_limiter.py                ← SmartRequester + RateLimitConfig
│   ├── auth.py                        ← AuthConfig + helpers
│   ├── url_validator.py               ← validate_url (utility chica)
│   └── findings.py                    ← Finding, ScanReport (movidos de report_generator)
├── modules/
│   ├── scanners/
│   │   ├── recon/
│   │   │   ├── README.md
│   │   │   ├── __init__.py            ← exporta PassiveRecon, run(target, opts)
│   │   │   ├── service.py
│   │   │   └── tests/
│   │   ├── hsts_ssl/                  (ex sslstrip_sim)
│   │   ├── xss/
│   │   ├── clickjacking/
│   │   ├── dir_fuzz/
│   │   ├── forms/
│   │   ├── subdomain_enum/
│   │   ├── bypass_403/
│   │   ├── slowloris/                 (opt-in, fuera de full-scan)
│   │   └── load_test/
│   ├── exploit_demo/
│   │   ├── README.md
│   │   └── service.py
│   ├── templates/                     (template engine, nuclei-like)
│   │   ├── README.md
│   │   ├── __init__.py
│   │   ├── engine.py                  ← TemplateEngine
│   │   ├── builtin.py                 ← BUILTIN_TEMPLATES
│   │   ├── routes.py                  ← POST /api/templates
│   │   └── tests/
│   ├── scan_orchestrator/
│   │   ├── README.md
│   │   ├── __init__.py
│   │   ├── orchestrator.py            ← FullScanner — registra scanners y los corre
│   │   ├── routes.py                  ← POST /api/scan
│   │   └── tests/
│   ├── reports/
│   │   ├── README.md
│   │   ├── generator.py               ← ReportGenerator (HTML)
│   │   └── routes.py                  ← GET /api/scans/<id>/report
│   ├── scan_storage/
│   │   ├── README.md
│   │   ├── repository.py              ← queries leídas (get_scans, get_scan_report, get_targets)
│   │   └── routes.py                  ← GET /api/scans, GET /api/scans/<id>, GET /api/targets
│   └── streamlit_ui/                  (opt-in, NO se levanta en ARM; queda como módulo aparte)
│       ├── README.md
│       └── app.py                     ← (de streamlit_app.py — solo se corre con `streamlit run`)
└── _deprecated/                       ← stubs para 2-4 semanas
    └── README.md                      ← mapa de qué se movió y desde dónde
```

`api_server.py` queda como:

```python
from flask import Flask
from core.config import settings
from modules.scan_orchestrator import routes as scan_routes
from modules.templates import routes as template_routes
from modules.scan_storage import routes as storage_routes
from modules.reports import routes as report_routes

app = Flask(__name__)

@app.route("/")
def health():
    return {"status": "ok", "service": "vendetta-api"}, 200

app.register_blueprint(scan_routes.bp)        # POST /api/scan
app.register_blueprint(template_routes.bp)    # POST /api/templates
app.register_blueprint(storage_routes.bp)     # GET /api/scans, /api/scans/<id>, /api/targets
app.register_blueprint(report_routes.bp)      # GET /api/scans/<id>/report

if __name__ == "__main__":
    import os
    app.run(host="0.0.0.0", port=int(os.environ.get("VENDETTA_API_PORT", "3004")))
```

Si querés desactivar un scanner: comentás su import en `modules/scan_orchestrator/orchestrator.py`. Si rompe en producción → `rollback-arm.sh vendetta-api` (~5 seg).

## Fases (cada fase = un PR + deploy + rollback testeado)

### Fase 0 — preparación (este documento)
- [x] Auditoría completa (27 archivos, 7066 líneas, entry real = `api_server.py`)
- [x] `MODULAR_PLAN.md` commiteado
- [x] Carpeta placeholder `modules/.gitkeep`
- [ ] (siguiente sesión) Crear `core/` y mover `db_manager.py` + `rate_limiter.py` + `auth_manager.py` + `url_validator.py` con wrappers de retro-compat (`from db_manager import DBManager` sigue funcionando vía `db_manager.py` que reexporta de `core/db.py`).

### Fase 0.5 — borrar duplicados (0.5 día, riesgo bajo)
Antes de mover nada, eliminar la duplicación que hoy ensucia el repo:
- Canónica = versión del **root** (más reciente, abril 2026).
- Borrar `security_tools/recon.py`, `security_tools/sslstrip_sim.py`, `security_tools/xss_test.py`, `load_test/load_test_engine.py`.
- Dejar `security_tools/clickjacking_test.html` (asset HTML, no código).
- Dejar `load_test/app.py` + `load_test/main.py` SI son una standalone separada que aún se usa; si no, borrar la carpeta entera.
- Smoke: `curl POST /api/scan` con target dummy → mismas findings que antes.

### Fase 1 — `core/` (0.5 día, riesgo bajo)
Mover infra compartida (no scanners):
- `db_manager.py` → `core/db.py` (+ wrapper retrocompat)
- `rate_limiter.py` → `core/rate_limiter.py`
- `auth_manager.py` → `core/auth.py`
- `url_validator.py` → `core/url_validator.py`
- `report_generator.py` Finding/ScanReport → `core/findings.py` (queda `ReportGenerator` separado para Fase 6)
- Smoke: API responde 7/7 endpoints + scan dummy guarda en SQLite + report HTML se genera.

### Fase 2 — primer scanner: `recon` (0.5 día, riesgo bajo)
Por qué empezar acá: es el primer paso del pipeline (`FullScanner._run_recon`), bien aislado, sin dependencias entre scanners.
- Crear `modules/scanners/recon/{__init__.py, service.py, README.md}`
- Mover `recon.py` → `modules/scanners/recon/service.py` (PassiveRecon, ReconResult)
- Dejar `recon.py` en root como wrapper que reexporta (2-4 semanas)
- Actualizar `full_scan.py` para importar de `modules.scanners.recon`
- Smoke: `curl POST /api/scan` con target → recon step corre, hosts encontrados, no regression.

### Fases 3-9 — un scanner por fase (≈0.5 día c/u, riesgo bajo)
Orden propuesto: `hsts_ssl`, `xss`, `clickjacking`, `dir_fuzz`, `forms`, `subdomain_enum`, `bypass_403`. Cada uno = mismo patrón Fase 2. Después de cada fase, smoke completo + rollback test.

### Fase 10 — `scan_orchestrator` (0.5 día, riesgo medio)
- `full_scan.py` → `modules/scan_orchestrator/orchestrator.py`
- Crear `routes.py` con `POST /api/scan` (movido de `api_server.py`)
- Convertir orchestrator a registro dinámico: `SCANNERS = [recon, hsts_ssl, ...]` listadas, no hardcoded.

### Fase 11 — `templates` (0.5 día)
- `template_engine.py` → `modules/templates/{engine.py, builtin.py, routes.py}`
- `POST /api/templates` se mueve a `modules/templates/routes.py`.
- Smoke: `curl POST /api/templates` con URL pública conocida → matches esperados.

### Fase 12 — `scan_storage` + `reports` (0.5 día, riesgo medio)
- Mover queries leídas a `modules/scan_storage/repository.py`.
- `GET /api/scans`, `GET /api/scans/<id>`, `GET /api/targets` → `modules/scan_storage/routes.py`.
- `ReportGenerator` HTML → `modules/reports/generator.py`.
- `GET /api/scans/<id>/report` → `modules/reports/routes.py`.

### Fase 13 — opt-in modules: `slowloris`, `load_test`, `exploit_demo` (0.5 día)
Estos no corren en el full-scan pipeline; tienen UI standalone (hoy Streamlit). Pasan a módulos opt-in. La UI Streamlit se moverá en Fase 14.

### Fase 14 — `streamlit_ui` (0.5 día, opcional)
Decisión Pablo: o (a) **borrar** `streamlit_app.py` si nadie la usa en ARM (es legacy Replit), o (b) **aislar** como `modules/streamlit_ui/app.py` con su propio `pip install streamlit` opt-in, sin correr en PM2.

Recomendación: **borrar** salvo que Pablo confirme uso. Hoy no escucha en port 8501 ni hay nginx para Streamlit.

### Fase 15 — `api_server.py` slim + limpieza
- Entry queda en 50-80 líneas (registro de blueprints).
- Borrar wrappers de `_deprecated/` después de 2-4 semanas sin reportes de imports rotos.
- Actualizar `CLAUDE.md` de vendetta con mapa modular nuevo.

## Rollback strategy

- `rollback-arm.sh vendetta-api` (5 seg) vuelve al release anterior.
- Cada fase es independiente — Fase 5 rompe XSS scan, rollback a Fase 4 y los scanners ya migrados (recon, hsts_ssl, clickjacking) siguen funcionando.
- Smoke test mínimo post-fase:
  ```bash
  curl -s -o /dev/null -w "%{http_code}\n" https://vendetta-arm.duckdns.org/                 # 200
  curl -s -X POST https://vendetta-arm.duckdns.org/api/scan \
       -H 'Content-Type: application/json' \
       -d '{"url":"https://example.com","skip_tools":["dirs","subs","forms"]}' | jq .scan_id
  pm2 list | grep vendetta-api | grep -c online                                              # 1
  pm2 logs vendetta-api --err --lines 100 --nostream | grep -c "Traceback\|Error"            # 0 o bajo
  ```

## Lo que NO se va a modularizar (intencional)

- `url_validator.py` (74 líneas): utilidad chica, una sola responsabilidad. Va a `core/url_validator.py` pero NO se promueve a módulo (regla: <100 líneas + una responsabilidad → utility, no módulo).
- `main.py` (10 líneas stub Replit): **se borra** en Fase 0.5. No tiene función en ARM (PM2 corre `api_server.py` directo). Se documenta el descarte en `_deprecated/README.md`.
- `attached_assets/` (3 PNGs de Replit): no es código, no se toca.
- `.streamlit/config.toml`: queda al lado de `streamlit_ui` si se conserva la UI; se borra si Fase 14 elige borrar Streamlit.
- `vendetta.db` (SQLite shared): no es código, vive en `/home/ubuntu/deployments/vendetta-api/shared/vendetta.db`, queda como está.

## Riesgos identificados

- **Imports flat heredados de Replit**: hoy todo es `from xss_test import XSSAnalyzer`. Cada movimiento a `modules.scanners.xss` requiere actualizar 2-3 archivos (`full_scan.py`, `streamlit_app.py`, posiblemente `api_server.py`). Mitigación: dejar un wrapper en el root (`xss_test.py` que hace `from modules.scanners.xss import *`) durante 2-4 semanas.
- **Duplicación scanner root vs `security_tools/`**: si alguna sesión Claude editó la copia equivocada en el pasado, hay drift silencioso. Fase 0.5 hace diff de cada par antes de borrar y reporta diffs no triviales. Si hay drift, Pablo decide cuál es canónica.
- **Streamlit como import cross-module**: `streamlit_app.py` importa 15+ módulos del root. Si lo conservamos en Fase 14, tiene que actualizarse a los paths nuevos. Si lo borramos, una preocupación menos.
- **SQLite single-writer**: si Fase 12 separa `scan_storage` y agregamos workers paralelos, contención. Hoy `vendetta-api` corre 1 worker (Flask `app.run` directo, no gunicorn), así que es teórico — pero documentado para que no se introduzca regresión.
- **`api_server.py.bak` + `main.py.bak`**: bakups quedaron en el repo. Borrar en Fase 0.5 (la regla de backup pre-edit ya no aplica porque tenemos releases versionados con rollback).

## Estimación

| Fase | Esfuerzo (días) | Riesgo |
|---|---|---|
| 0 | 0.5 (este doc + carpeta) | nulo |
| 0.5 — borrar duplicados + .bak + stub main.py | 0.5 | bajo |
| 1 — `core/` | 0.5 | bajo |
| 2 — `recon` (primer scanner) | 0.5 | bajo |
| 3-9 — 7 scanners restantes (1 por fase) | 3.5 | bajo |
| 10 — `scan_orchestrator` + dynamic registry | 0.5 | medio |
| 11 — `templates` | 0.5 | bajo |
| 12 — `scan_storage` + `reports` | 0.5 | medio |
| 13 — opt-in (slowloris, load_test, exploit_demo) | 0.5 | bajo |
| 14 — `streamlit_ui` (decidir borrar o aislar) | 0.5 | nulo |
| 15 — entry slim + limpieza _deprecated | 0.5 | nulo |
| **Total** | **~8 días** distribuidos | — |

## Regla operativa nueva (mientras el monolito existe)

**Cualquier scanner o feature NUEVO en vendetta va como módulo desde el día 1.** No se acepta agregar más archivos `.py` al root del proyecto. Ejemplo: si Pablo pide agregar un scanner SQL injection, va a `modules/scanners/sql_injection/` directo desde el primer commit, y `FullScanner` lo registra en su lista — no se mete en `full_scan.py` con un `_run_sqli()` hardcoded.
