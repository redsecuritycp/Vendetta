"""
DEPRECATED PATH — wrapper de retro-compatibilidad.

El código real vive en `modules/templates/engine.py` desde 2026-05-14
(Fase 12 modular según MODULAR_PLAN.md).

Este wrapper queda durante 2-4 semanas para no romper:
    from template_engine import TemplateEngine, Template, TemplateMatch, BUILTIN_TEMPLATES

Después se borra. NO editar — modificar el módulo nuevo.
"""

from modules.templates import (  # noqa: F401
    TemplateEngine,
    Template,
    TemplateMatch,
    BUILTIN_TEMPLATES,
)

__all__ = ["TemplateEngine", "Template", "TemplateMatch", "BUILTIN_TEMPLATES"]
