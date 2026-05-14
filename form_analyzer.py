"""
DEPRECATED PATH — wrapper de retro-compatibilidad.

El código real vive en `modules/scanners/forms/scanner.py` desde 2026-05-14
(Fase 5 modular según MODULAR_PLAN.md).

Este wrapper queda durante 2-4 semanas para no romper imports flat existentes:
    from form_analyzer import FormAnalyzer
    from form_analyzer import FormAnalyzer, FormAnalyzerResult, FormInfo

Después se borra. NO editar — modificar el módulo nuevo.

Identidad preservada:
    form_analyzer.FormAnalyzer is modules.scanners.forms.FormAnalyzer  # True
"""

from modules.scanners.forms import FormAnalyzer, FormAnalyzerResult, FormInfo  # noqa: F401

__all__ = ["FormAnalyzer", "FormAnalyzerResult", "FormInfo"]


def main():
    """Compat: `python form_analyzer.py <url>` sigue funcionando."""
    from modules.scanners.forms.scanner import main as _main
    _main()


if __name__ == "__main__":
    main()
