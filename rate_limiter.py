"""
DEPRECATED PATH — wrapper de retro-compatibilidad.

El código real vive en `core/rate_limiter.py` desde 2026-05-14
(Fase 15 modular según MODULAR_PLAN.md).

Este wrapper queda durante 2-4 semanas para no romper:
    from rate_limiter import SmartRequester, RateLimitConfig, WAFInfo

Después se borra. NO editar — modificar `core/rate_limiter.py`.
"""

from core.rate_limiter import (  # noqa: F401
    SmartRequester,
    RateLimitConfig,
    WAFInfo,
    USER_AGENTS,
    WAF_SIGNATURES,
)

__all__ = [
    "SmartRequester",
    "RateLimitConfig",
    "WAFInfo",
    "USER_AGENTS",
    "WAF_SIGNATURES",
]
