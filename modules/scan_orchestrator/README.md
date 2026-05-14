# Módulo `scan_orchestrator`

**Fecha**: 2026-05-14 (Fase 13 de modularización)
**Estado**: activo en producción
**Entrypoint API**: `POST /api/scan` (Flask `api_server.py`)

## Qué hace

Orquesta la ejecución secuencial de los 8 scanners core de vendetta contra
una URL objetivo y consolida los hallazgos en un único `ScanReport`:

1. `recon` — Reconocimiento Pasivo (`PassiveRecon`)
2. `hsts` — Análisis HSTS / SSLStrip (`SSLStripAnalyzer`)
3. `xss` — Análisis XSS (`XSSAnalyzer`)
4. `clickjack` — Clickjacking (`ClickjackingAnalyzer`)
5. `dirs` — Fuzzing de directorios (`DirectoryFuzzer`)
6. `forms` — Análisis de formularios (`FormAnalyzer`)
7. `subs` — Enumeración de subdominios (`SubdomainEnumerator`)
8. `bypass` — Bypass 403 (`Bypass403`) — solo si se pasan paths

Reporta progreso vía callback `on_progress(ScanProgress)` para que el
endpoint pueda emitir actualizaciones a la UI.

## Interfaz pública

```python
from modules.scan_orchestrator import FullScanner, ScanProgress

scanner = FullScanner(auth_config=None)
report = scanner.scan(
    url="https://example.com",
    skip_tools=["bypass"],          # opcional
    xss_test_url="...",             # opcional, URL con params para XSS
    bypass_paths=["/admin"],        # opcional
    on_progress=lambda p: print(p), # opcional
)
```

Retorna un `ScanReport` (de `report_generator.py`) con `findings`, `tools_used`,
`raw_results`, `duration`.

## Dependencias

Importa los scanners desde sus módulos modernos:

- `modules.scanners.recon`
- `modules.scanners.hsts_ssl`
- `modules.scanners.xss`
- `modules.scanners.clickjacking`
- `modules.scanners.dir_fuzz`
- `modules.scanners.forms`
- `modules.scanners.subdomain_enum`
- `modules.scanners.bypass_403`

Y `report_generator` (root, infra cross-feature pendiente de migrar a `core/`).

## Retrocompat

El archivo `full_scan.py` del root queda como **wrapper de re-export** durante
2-4 semanas: `from full_scan import FullScanner` sigue funcionando, pero el
código vive aquí. No editar el wrapper — modificar este módulo.

## Cómo se prueba

```bash
curl -X POST https://vendetta-arm.duckdns.org/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com","skip_tools":["bypass","subs","dirs"]}'
# → {"scan_id": "...", "status": "running"}
```

Sin `url` → HTTP 400.

## Cómo se desinstala

NO desinstalar — es el orquestador core del endpoint `POST /api/scan`.
Si querés desactivarlo, hay que sacar también ese endpoint en `api_server.py`.
