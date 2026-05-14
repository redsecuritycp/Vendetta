# scanners/xss

Detector de vulnerabilidades XSS reflejado (Cross-Site Scripting).

## Qué hace

Analiza los parámetros de query string de una URL inyectando payloads de prueba
no ejecutables y detectando reflexión en la respuesta HTML. Clasifica el
contexto de reflexión (dentro de `<script>`, atributo HTML, contenido HTML) y
asigna severidad (`critico`, `alto`, `medio`, `bajo`).

## Interfaz pública

```python
from modules.scanners.xss import XSSAnalyzer, XSSResult

analyzer = XSSAnalyzer()
result: XSSResult = analyzer.analyze("https://target.com/buscar?q=test")

print(result.risk_level)        # 'critico' | 'alto' | 'medio' | 'bajo' | 'ninguno' | 'info'
print(result.vulnerable_params) # list[dict] con param, payload, context, severity
print(result.reflected_params)  # list[str]
```

## Payloads

8 payloads seguros (no ejecutan código). Ver `TEST_PAYLOADS` en `scanner.py`.

## Dependencias

- `requests`
- stdlib: `re`, `urllib.parse`, `dataclasses`, `html.parser`

No depende de otros módulos vendetta.

## CLI

```bash
python -m modules.scanners.xss.scanner 'https://ejemplo.com/buscar?q=test'
# o vía wrapper compat:
python xss_test.py 'https://ejemplo.com/buscar?q=test'
```

## Retro-compatibilidad

`xss_test.py` en la raíz del repo es un wrapper que reexporta de este módulo.
Se borrará 2-4 semanas después de Fase 2 (2026-05-14) salvo que algún consumer
externo lo siga importando.

## Tests

Pendiente. Smoke test: `POST /api/scan` con target que tenga `?q=test` →
`raw_results.xss` no debe estar vacío.

## Cómo desinstalar / desactivar

Comentar el paso XSS en `modules/scan_orchestrator/orchestrator.py` (futuro;
hoy en `full_scan.py`) o pasar `skip_tools=["xss"]` al `POST /api/scan`.
