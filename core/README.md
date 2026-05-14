# core/ — infraestructura cross-feature

Consolidación Fase 15 modular (2026-05-14). Reúne las utilidades infra que
todos los scanners y el orquestador usan en común.

## Contenido

| Archivo | Qué expone | Quién lo usa |
|---|---|---|
| `rate_limiter.py` | `SmartRequester`, `RateLimitConfig`, `WAFInfo`, `USER_AGENTS`, `WAF_SIGNATURES` | scanners HTTP (recon, xss, dir_fuzz, forms, bypass_403, subdomain_enum, ...) |
| `auth.py` | `AuthConfig`, `create_authenticated_session` | scanners que necesitan inyectar headers/cookies/Bearer |
| `url_validator.py` | `validate_url`, `extract_domain`, `normalize_url` | guard pre-scan + utilidades en `full_scan` / scan_orchestrator |

## Retrocompat

Cada archivo del root (`rate_limiter.py`, `auth_manager.py`, `url_validator.py`)
es un **wrapper** que reexporta desde `core/` para no romper imports viejos
durante 2-4 semanas. Después se borran (la limpieza queda agendada en
`_deprecated/README.md`).

Import canónico para código nuevo:

```python
from core.rate_limiter import SmartRequester, RateLimitConfig
from core.auth import AuthConfig, create_authenticated_session
from core.url_validator import validate_url
```

Import viejo (sigue funcionando vía wrapper):

```python
from rate_limiter import SmartRequester      # wrapper → core.rate_limiter
from auth_manager import AuthConfig          # wrapper → core.auth
from url_validator import validate_url       # wrapper → core.url_validator
```

## Regla

- `core/` no depende de `modules/`. Si necesitás algo de un módulo desde acá,
  está mal el grafo de dependencias.
- Bug en `core/` rompe todo. Cambios acá pasan por health-check + smoke de
  `/api/scan` antes de mergear.
