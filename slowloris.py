"""
DEPRECATED PATH — wrapper de retro-compatibilidad.

El código real vive en `modules/scanners/slowloris/scanner.py` desde
2026-05-14 (Fase 9 modular según MODULAR_PLAN.md).

slowloris es un scanner OPT-IN (NO se ejecuta desde `POST /api/scan`).
Solo invocar manualmente contra sistemas propios o con autorización.

Este wrapper queda durante 2-4 semanas para no romper imports flat existentes:
    from slowloris import SlowlorisAttacker
    from slowloris import SlowlorisAttacker, SlowlorisResult, analyze

Después se borra. NO editar — modificar el módulo nuevo.

Identidad preservada:
    slowloris.SlowlorisAttacker is modules.scanners.slowloris.SlowlorisAttacker  # True
"""

from modules.scanners.slowloris import (  # noqa: F401
    SlowlorisAttacker,
    SlowlorisResult,
    analyze,
)

__all__ = ["SlowlorisAttacker", "SlowlorisResult", "analyze"]


if __name__ == "__main__":
    # Mantener CLI legacy `python slowloris.py <url> [sockets] [duracion]`
    from modules.scanners.slowloris.scanner import main
    main()
