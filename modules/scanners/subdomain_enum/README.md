# scanners/subdomain_enum

Enumerador de subdominios por fuerza bruta con diccionario común. Resuelve
DNS para cada candidato, prueba HTTP y HTTPS, y reporta los subdominios
vivos con sus IPs, status codes, server header y título HTML.

## Qué hace

1. Extrae el dominio base de una URL o dominio (ej: `https://www.ejemplo.com/x`
   -> `ejemplo.com`).
2. Recorre el diccionario `COMMON_SUBDOMAINS` (~120 nombres comunes: `www`,
   `api`, `admin`, `dev`, `staging`, `vpn`, `cpanel`, `wp`, etc.). Acepta
   `custom_wordlist` opcional para extender.
3. Por cada candidato `<sub>.<base>`: resuelve DNS (`socket.gethostbyname_ex`).
   Si no resuelve, descarta.
4. Si resuelve, hace `GET http://<full>` y `GET https://<full>` con timeout
   5s. Captura status, `Server` y `<title>` del HTML.
5. Corre con `ThreadPoolExecutor` (20 hilos por defecto) y timeout global
   120s.
6. Marca como sensibles los subs en `{admin, dev, staging, test, backup,
   internal, vpn}` y arma recomendaciones (sensibles encontrados, múltiples
   IPs, subdominios solo-HTTP).

## Interfaz pública

```python
from modules.scanners.subdomain_enum import (
    SubdomainEnumerator,
    SubdomainResult,
    SubdomainInfo,
)

enumerator = SubdomainEnumerator()
result: SubdomainResult = enumerator.analyze("ejemplo.com")

print(result.target_domain)           # 'ejemplo.com'
print(len(result.subdomains_found))   # int
for sub in result.subdomains_found:
    print(sub.full_domain, sub.ip_addresses, sub.http_status, sub.https_status)
print(result.recommendations)
```

## Dependencias

- `requests`
- `beautifulsoup4` (para extraer `<title>`)
- stdlib: `socket`, `dataclasses`, `typing`, `urllib.parse`,
  `concurrent.futures`, `time`

No depende de otros módulos vendetta.

## CLI

```bash
python -m modules.scanners.subdomain_enum.scanner ejemplo.com
# o vía wrapper compat:
python subdomain_enum.py ejemplo.com
```

## Retro-compatibilidad

`subdomain_enum.py` en la raíz del repo es un wrapper que reexporta de este
módulo. Se borrará 2-4 semanas después de Fase 7 (2026-05-14) salvo que algún
consumer externo lo siga importando.

Imports flat soportados:

```python
from subdomain_enum import SubdomainEnumerator
from subdomain_enum import SubdomainEnumerator, SubdomainResult, SubdomainInfo
```

## Tests

Pendiente. Smoke test: `POST /api/scan` con target real ->
`raw_results.subs` debe traer `total_checked > 0` y un `target_domain`
correcto, sin levantar excepciones.

## Cómo desinstalar / desactivar

Pasar `skip_tools=["subs"]` al `POST /api/scan`, o comentar el paso en
`full_scan.py` (futuro: `modules/scan_orchestrator/orchestrator.py`).
