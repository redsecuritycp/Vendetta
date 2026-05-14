"""
DEPRECATED PATH — wrapper de retro-compatibilidad.

El código real vive en `core/url_validator.py` desde 2026-05-14
(Fase 15 modular según MODULAR_PLAN.md).

Este wrapper queda durante 2-4 semanas para no romper:
    from url_validator import validate_url, extract_domain, normalize_url

Después se borra. NO editar — modificar `core/url_validator.py`.
"""

from core.url_validator import validate_url, extract_domain, normalize_url  # noqa: F401

__all__ = ["validate_url", "extract_domain", "normalize_url"]
