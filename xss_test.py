"""
DEPRECATED PATH — wrapper de retro-compatibilidad.

El código real vive en `modules/scanners/xss/scanner.py` desde 2026-05-14
(Fase 2 modular según MODULAR_PLAN.md).

Este wrapper queda durante 2-4 semanas para no romper imports flat existentes:
    from xss_test import XSSAnalyzer
    from xss_test import XSSAnalyzer, XSSResult, ReflectionChecker

Después se borra. NO editar — modificar el módulo nuevo.

Identidad preservada:
    xss_test.XSSAnalyzer is modules.scanners.xss.XSSAnalyzer  # True
"""

from modules.scanners.xss import XSSAnalyzer, XSSResult, ReflectionChecker  # noqa: F401

__all__ = ["XSSAnalyzer", "XSSResult", "ReflectionChecker"]


def main():
    """Compat: `python xss_test.py <url>` sigue funcionando."""
    from modules.scanners.xss.scanner import main as _main
    _main()


if __name__ == "__main__":
    main()
