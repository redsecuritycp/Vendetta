# scanners/hsts_ssl

Analizador de vulnerabilidades HSTS / SSLStrip. Detecta configuraciones de
TLS/HSTS que habilitan ataques de downgrade SSL (SSLStrip) y problemas
básicos en el certificado del target.

## Qué hace

1. Hace `GET http://<dominio>` con `allow_redirects=False` para ver si hay
   redirección 301/302/307/308 a `https://`.
2. Hace `GET https://<dominio>` y lee el header
   `Strict-Transport-Security`. Si existe, parsea:
   - `max-age=<segundos>` (recomendado ≥ 31536000, o sea 1 año).
   - `includeSubDomains` (booleano).
   - `preload` (booleano).
3. Abre un socket TLS (`ssl.create_default_context`) contra el puerto 443
   y captura errores de verificación de certificado.
4. Compone `vulnerabilities[]` y `recommendations[]` segun lo encontrado,
   y asigna `risk_level`:
   - `critico`  → sin HSTS y sin redirect HTTP→HTTPS.
   - `alto`     → sin HSTS pero con redirect.
   - `medio`    → con HSTS y >2 hallazgos menores.
   - `bajo`     → 1-2 hallazgos menores.
   - `ninguno`  → todo OK.

## Interfaz pública

```python
from modules.scanners.hsts_ssl import SSLStripAnalyzer, HSTSResult

analyzer = SSLStripAnalyzer()
result: HSTSResult = analyzer.analyze("https://target.com")

print(result.has_hsts)            # bool
print(result.max_age)             # int | None
print(result.include_subdomains)  # bool
print(result.preload)             # bool
print(result.redirects_to_https)  # bool
print(result.risk_level)          # 'critico' | 'alto' | 'medio' | 'bajo' | 'ninguno'
for v in result.vulnerabilities:
    print("[!]", v)
for r in result.recommendations:
    print("[*]", r)
```

## Dependencias

- `requests`
- stdlib: `ssl`, `socket`, `urllib.parse`, `dataclasses`, `typing`

No depende de otros módulos vendetta.

## CLI

```bash
python -m modules.scanners.hsts_ssl.scanner 'https://ejemplo.com'
# o vía wrapper compat:
python sslstrip_sim.py 'https://ejemplo.com'
```

## Retro-compatibilidad

`sslstrip_sim.py` en la raíz del repo es un wrapper que reexporta de este
módulo. Se borrará 2-4 semanas después de Fase 6 (2026-05-14) salvo que
algún consumer externo lo siga importando.

Imports flat soportados:

```python
from sslstrip_sim import SSLStripAnalyzer
from sslstrip_sim import SSLStripAnalyzer, HSTSResult
```

Identidad preservada:

```python
import sslstrip_sim
from modules.scanners.hsts_ssl import SSLStripAnalyzer
assert sslstrip_sim.SSLStripAnalyzer is SSLStripAnalyzer
```

## Limitaciones conocidas

- `_check_ssl_cert` solo captura errores de verificación; no valida fecha
  de expiración, cadena, ni algoritmos débiles. Pendiente endurecer en
  fase futura.
- `_get_hsts_header` solo mira la respuesta HTTPS final; si el server
  agrega HSTS recién después de un redirect interno, se ve igual.

## Tests

Pendiente. Smoke test: `POST /api/scan` con target real →
`raw_results.hsts.risk_level` debe existir y no ser `error`.

## Cómo desinstalar / desactivar

Pasar `skip_tools=["hsts"]` al `POST /api/scan`, o comentar el paso en
`full_scan.py` (futuro: `modules/scan_orchestrator/orchestrator.py`).
