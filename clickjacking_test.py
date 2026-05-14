"""
DEPRECATED PATH — wrapper de retro-compatibilidad.

El código real vive en `modules/scanners/clickjacking/scanner.py` desde 2026-05-14
(Fase 3 modular según MODULAR_PLAN.md).

Este wrapper queda durante 2-4 semanas para no romper imports flat existentes:
    from clickjacking_test import ClickjackingAnalyzer
    from clickjacking_test import ClickjackingAnalyzer, ClickjackingResult

Después se borra. NO editar — modificar el módulo nuevo.

Identidad preservada:
    clickjacking_test.ClickjackingAnalyzer is modules.scanners.clickjacking.ClickjackingAnalyzer  # True
"""

from modules.scanners.clickjacking import ClickjackingAnalyzer, ClickjackingResult  # noqa: F401

__all__ = ["ClickjackingAnalyzer", "ClickjackingResult"]


def main():
    """Compat: `python clickjacking_test.py <url>` sigue funcionando."""
    from modules.scanners.clickjacking.scanner import main as _main
    _main()


if __name__ == "__main__":
    main()
