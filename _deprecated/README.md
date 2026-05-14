# _deprecated — vendetta

Archivos movidos durante la modularización (Fase 0.5, 2026-05-14). Quedan acá 2-4 semanas como red de seguridad; si nadie reclama, se borran definitivamente.

Para restaurar cualquiera: `git mv _deprecated/<path> <path-original>`.

## Movido en Fase 0.5 (2026-05-14)

### Duplicados de scanners (canónica = root, esta era la copia vieja/chica)

| Archivo | Origen | LOC | Notas |
|---|---|---|---|
| `security_tools/recon.py` | `security_tools/recon.py` | 263 | Copia más vieja (dic 2025). Root tiene 317 LOC actualizado abril 2026. Sin imports activos. |
| `security_tools/xss_test.py` | `security_tools/xss_test.py` | 219 | Idem — root tiene 286 LOC. Sin imports activos. |
| `security_tools/sslstrip_sim.py` | `security_tools/sslstrip_sim.py` | 173 | Idem — root tiene 217 LOC. Sin imports activos. |
| `security_tools/clickjacking_test.html` | `security_tools/clickjacking_test.html` | — | Asset HTML, no código. Movido junto con el resto de la carpeta. |
| `security_tools/README.md`, `.gitignore`, `requirements.txt` | `security_tools/` | — | Documentación de la carpeta legacy. |

### `load_test/` standalone (Replit-era)

| Archivo | Origen | LOC | Notas |
|---|---|---|---|
| `load_test/load_test_engine.py` | `load_test/` | 220 | **Idéntico bit-a-bit** al root `load_test_engine.py`. El root es el que usan `full_scan.py` y `streamlit_app.py`. |
| `load_test/app.py`, `load_test/main.py`, `load_test/README.md`, etc. | `load_test/` | — | Standalone Replit. No tiene PM2 process, no escucha en puerto, no hay nginx upstream. Sin uso activo en ARM. |

### Stubs y backups legacy Replit

| Archivo | Origen | LOC | Notas |
|---|---|---|---|
| `main.py` | root | 10 | **Stub Replit**: Flask app que devuelve `'OK'` en `/` por puerto 5000. **NO se ejecuta en ARM**: PM2 corre `api_server.py` directo (ver `ecosystem.config.cjs`, `script: venv/bin/python args: api_server.py`). Histórico de cuando Replit usaba `main.py` como entry de health-check. |
| `main.py.bak` | root | — | Backup pre-edit de abril 2026. Ya no aplica (releases versionados con `rollback-arm.sh` cubren ese rol). |
| `api_server.py.bak` | root | — | Idem — backup pre-edit del api server. |
| `CLAUDE.md.bak` | root | — | Backup viejo del CLAUDE.md del proyecto. |

### UI Streamlit (Replit-era)

| Archivo | Origen | LOC | Notas |
|---|---|---|---|
| `streamlit_app.py` | root | 857 | **NO se ejecuta en ARM**: no hay PM2 process Streamlit, no escucha en port 8501, no hay nginx upstream para `streamlit run`. Era la UI del Replit original. Nadie la importa desde código activo (solo importa scanners del root). Si se decide rescatar como módulo opt-in, va a `modules/streamlit_ui/` (ver MODULAR_PLAN.md Fase 14). |

## Cómo verificar que no hay regresión

```bash
# entry real responde
curl -sS -o /dev/null -w "%{http_code}\n" https://vendetta-arm.duckdns.org

# api_server importa sin error
cd /home/ubuntu/projects/vendetta && venv/bin/python -c "import api_server"

# PM2 online
pm2 list | grep vendetta-api | grep online
```
