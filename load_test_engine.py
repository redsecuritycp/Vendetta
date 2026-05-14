"""
DEPRECATED PATH — wrapper de retro-compatibilidad.

El código real vive en `modules/scanners/load_test/scanner.py` desde
2026-05-14 (Fase 10 modular según MODULAR_PLAN.md).

load_test es un scanner OPT-IN (NO se ejecuta desde `POST /api/scan`).
Solo invocar manualmente contra sistemas propios o con autorización.

Este wrapper queda durante 2-4 semanas para no romper imports flat existentes:
    from load_test_engine import LoadTestEngine
    from load_test_engine import LoadTestEngine, analyze

Después se borra. NO editar — modificar el módulo nuevo.

Identidad preservada:
    load_test_engine.LoadTestEngine is modules.scanners.load_test.LoadTestEngine  # True
"""

from modules.scanners.load_test import (  # noqa: F401
    LoadTestEngine,
    analyze,
)

__all__ = ["LoadTestEngine", "analyze"]


if __name__ == "__main__":
    # Mantener CLI legacy `python load_test_engine.py <url> [concurrent] [duracion]`
    from modules.scanners.load_test.scanner import main
    main()
