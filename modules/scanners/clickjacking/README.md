# scanners/clickjacking

Detector de vulnerabilidad a Clickjacking. Verifica si un sitio puede ser
embebido en iframes (ausencia o configuración débil de `X-Frame-Options` y
CSP `frame-ancestors`).

## Qué hace

Hace una request GET al target y analiza dos defensas:

1. **`X-Frame-Options`** — `DENY` o `SAMEORIGIN` se consideran protegidos.
2. **CSP `frame-ancestors`** — `'none'` o `'self'` se consideran protegidos.

Calcula `risk_level` (`alto`, `medio`, `bajo`) y genera un HTML de prueba
visual (iframe + overlay) para verificación manual del finding.

## Interfaz pública

```python
from modules.scanners.clickjacking import ClickjackingAnalyzer, ClickjackingResult

analyzer = ClickjackingAnalyzer()
result: ClickjackingResult = analyzer.analyze("https://target.com")

print(result.vulnerable)           # bool
print(result.risk_level)           # 'alto' | 'medio' | 'bajo'
print(result.x_frame_options)      # str | None
print(result.csp_frame_ancestors)  # str | None
print(result.details)              # list[str]
print(result.recommendations)      # list[str]
print(result.test_html)            # HTML standalone para test visual
```

## Dependencias

- `requests`
- stdlib: `urllib.parse`, `dataclasses`, `typing`

No depende de otros módulos vendetta.

## CLI

```bash
python -m modules.scanners.clickjacking.scanner 'https://ejemplo.com'
# o vía wrapper compat:
python clickjacking_test.py 'https://ejemplo.com'
```

Escribe `clickjacking_test.html` en el cwd con el iframe de prueba visual.

## Retro-compatibilidad

`clickjacking_test.py` en la raíz del repo es un wrapper que reexporta de este
módulo. Se borrará 2-4 semanas después de Fase 3 (2026-05-14) salvo que algún
consumer externo lo siga importando. `full_scan.py` lo importa hoy por el
path viejo y sigue funcionando via wrapper.

## Tests

Pendiente. Smoke test: `POST /api/scan` con target real → `raw_results.clickjacking`
debe contener `vulnerable`, `risk_level`, `x_frame_options`, `csp_frame_ancestors`.

## Cómo desinstalar / desactivar

Comentar el paso clickjacking en `full_scan.py` (`_run_clickjacking`) o pasar
`skip_tools=["clickjacking"]` al `POST /api/scan`.
