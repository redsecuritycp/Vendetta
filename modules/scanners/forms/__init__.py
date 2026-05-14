"""
Módulo de análisis de formularios HTML.

Detecta problemas de seguridad en formularios: CSRF token ausente,
campos sensibles mal tipados, login sobre HTTP, autocomplete en
campos password, validación HTML5 faltante, etc.

Interfaz pública:
    from modules.scanners.forms import FormAnalyzer, FormAnalyzerResult, FormInfo
"""

from .scanner import FormAnalyzer, FormAnalyzerResult, FormInfo

__all__ = ["FormAnalyzer", "FormAnalyzerResult", "FormInfo"]
