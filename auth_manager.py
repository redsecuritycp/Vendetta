"""
DEPRECATED PATH — wrapper de retro-compatibilidad.

El código real vive en `core/auth.py` desde 2026-05-14
(Fase 15 modular según MODULAR_PLAN.md).

Este wrapper queda durante 2-4 semanas para no romper:
    from auth_manager import AuthConfig, create_authenticated_session

Después se borra. NO editar — modificar `core/auth.py`.
"""

from core.auth import AuthConfig, create_authenticated_session  # noqa: F401

__all__ = ["AuthConfig", "create_authenticated_session"]
