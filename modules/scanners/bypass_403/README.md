# scanners/bypass_403

Bypass de protecciones 403 Forbidden. Intenta múltiples técnicas para
acceder a recursos que devuelven 403, reportando bypasses exitosos
(status 200) con preview del contenido.

## Qué hace

1. Para cada path objetivo, captura el status original (referencia).
2. Aplica baterías de técnicas en orden:
   - **Backup extensions** (`.bak`, `.backup`, `.old`, `.save`, `~`,
     `.swp`, `.txt`, `.log`, ~18 variantes) sobre el path original.
   - **Case variants** (UPPER, lower, Capitalize, sWaPCaSe).
   - **URL encoding** (single, double, `%2f`, `%2F`, `%2e`, `%2E`).
   - **Path manipulation** (`/path`, `//path`, `..;/`, `;/`, `path/`,
     `path/.`, `path%20`, `path?`, `path#`, sufijos `.html`/`.php`/`.json`,
     ~19 variantes).
   - **Header spoofing** (`X-Original-URL`, `X-Rewrite-URL`,
     `X-Forwarded-For`, `X-Real-IP`, `Forwarded`, `Referer`, ~19
     headers con valor `127.0.0.1`).
   - **HTTP methods alternativos** (POST/PUT/PATCH/DELETE/HEAD/OPTIONS/
     TRACE/CONNECT, opt-in vía `include_methods`).
3. Toda request con timeout 5s, sin redirects, captura status, size,
   `Content-Type`, preview de hasta 500 bytes y contenido completo.
4. Reporta solo respuestas 200 como bypass exitoso.

## Interfaz pública

```python
from modules.scanners.bypass_403 import (
    Bypass403,
    BypassResult,
    FullBypassReport,
    analyze,
)

# Análisis múltiples paths
bypasser = Bypass403()
report: FullBypassReport = bypasser.analyze(
    "https://target.com",
    paths=["/admin", "/secret.txt"],
    include_backups=True,
    include_encoding=True,
    include_headers=True,
    include_methods=False,
)

print(report.total_bypasses)            # int
for r in report.results:
    print(r.original_path, r.original_status, len(r.bypasses_found))
for dl in report.downloadable_files:
    print(dl["bypass_url"], dl["technique"], dl["size"])

# Helper de conveniencia (equivale a las 3 líneas de arriba)
report = analyze("https://target.com", ["/admin"])
```

## Dependencias

- `requests`
- stdlib: `dataclasses`, `typing`, `urllib.parse`, `concurrent.futures`,
  `time`

No depende de otros módulos vendetta.

## Retro-compatibilidad

`bypass_403.py` en la raíz del repo es un wrapper que reexporta de este
módulo. Se borrará 2-4 semanas después de Fase 8 (2026-05-14) salvo que
algún consumer externo lo siga importando.

Imports flat soportados:

```python
from bypass_403 import Bypass403
from bypass_403 import Bypass403, BypassResult, FullBypassReport, analyze
```

`full_scan.py` sigue importando `from bypass_403 import Bypass403` —
funciona vía el wrapper. En la fase final de scan_orchestrator se
migrará al import canónico de `modules.scanners.bypass_403`.

## Tests

Pendiente. Smoke test: `POST /api/scan` con target real ->
`raw_results` corre `Bypass403` sin levantar excepción y `tools_used`
incluye `"Bypass403"` si hay paths 403 detectados upstream.

## Cómo desinstalar / desactivar

Pasar `skip_tools=["bypass"]` al `POST /api/scan`, o comentar el paso
en `full_scan.py` (futuro: `modules/scan_orchestrator/orchestrator.py`).
