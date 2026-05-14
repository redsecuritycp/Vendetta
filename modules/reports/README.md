# Módulo `reports`

**Fecha**: 2026-05-14 (Fase 14 de modularización)
**Estado**: activo en producción
**Endpoint API que lo usa**: `GET /api/scans/<id>/report` (HTML descargable).
**Consumido por**: `modules.scan_orchestrator` (para construir `ScanReport` /
`Finding`), `api_server.py` (para render HTML).

## Qué hace

Define el modelo de datos del reporte de auditoría y renderiza la versión
HTML lista para distribuir.

- **`Finding`** (dataclass): un hallazgo individual con `tool`, `title`,
  `severity` (`critico`/`alto`/`medio`/`bajo`/`info`), `description`,
  `evidence`, `recommendation` y `cvss_approx`.
- **`ScanReport`** (dataclass): agrega `findings`, `tools_used`, `summary`,
  `raw_results` y calcula `risk_score` (0-100 con pesos por severidad) y
  `to_json()` para persistir.
- **`ReportGenerator`**: `generate_html(report) -> str` produce un HTML
  autocontenido (CSS inline, print-friendly) con header, score card,
  resumen por severidad y lista detallada de hallazgos.

## Interfaz pública

```python
from modules.reports import Finding, ScanReport, ReportGenerator

report = ScanReport(target="https://example.com")
report.add_finding(Finding(
    tool="xss", title="Reflected XSS en /search",
    severity="alto",
    description="Payload reflejado sin sanitizar",
    evidence="<script>alert(1)</script>",
    recommendation="Encode HTML antes de renderizar"
))
print(report.get_risk_score())
print(report.to_json())

html = ReportGenerator().generate_html(report)
```

## Severidades y scoring

| Severidad | Peso | Color |
|---|---|---|
| `critico` | 25 | `#dc2626` |
| `alto`    | 15 | `#ea580c` |
| `medio`   | 8  | `#d97706` |
| `bajo`    | 3  | `#2563eb` |
| `info`    | 0  | `#6b7280` |

`get_risk_score()` suma pesos y satura en 100.

## Dependencias

- `json`, `datetime`, `dataclasses`, `typing` (stdlib). Sin deps externas.

## Retro-compatibilidad

`report_generator.py` en el root sigue funcionando como wrapper:

```python
from report_generator import ScanReport, Finding, ReportGenerator
```

El wrapper se mantiene 2-4 semanas. Después se borra. **NO editarlo** — cambios
van en `modules/reports/generator.py`.

## Cómo se prueba

```bash
cd /home/ubuntu/projects/vendetta
python3 -c "
from modules.reports import Finding, ScanReport, ReportGenerator
r = ScanReport(target='https://test')
r.add_finding(Finding('xss', 'demo', 'medio', 'desc'))
html = ReportGenerator().generate_html(r)
print('OK', len(html), 'bytes, score=', r.get_risk_score())
"
```

## Cómo se desinstala

No aplica — es infra cross-feature. Si se quisiera reemplazar el renderer
(ej: PDF en vez de HTML), mantener la API pública (`Finding`, `ScanReport`,
`ReportGenerator.generate_html`) para no romper `scan_orchestrator` ni el
endpoint `GET /api/scans/<id>/report`.
