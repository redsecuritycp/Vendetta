"""
Módulo de Template Engine (nuclei-like).

Ejecuta templates declarativos (built-in + custom) contra una URL y devuelve
matches. Expuesto via `POST /api/templates` por `routes.py` (Blueprint Flask).

Interfaz pública:
    from modules.templates import TemplateEngine, Template, TemplateMatch
    from modules.templates.routes import bp as templates_bp
"""

from .engine import TemplateEngine, Template, TemplateMatch, BUILTIN_TEMPLATES

__all__ = ["TemplateEngine", "Template", "TemplateMatch", "BUILTIN_TEMPLATES"]
