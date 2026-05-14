"""
DEPRECATED PATH — wrapper de retro-compatibilidad.

El código real vive en `modules/scanners/bypass_403/scanner.py` desde
2026-05-14 (Fase 8 modular según MODULAR_PLAN.md).

Este wrapper queda durante 2-4 semanas para no romper imports flat existentes:
    from bypass_403 import Bypass403
    from bypass_403 import Bypass403, BypassResult, FullBypassReport, analyze

Después se borra. NO editar — modificar el módulo nuevo.

Identidad preservada:
    bypass_403.Bypass403 is modules.scanners.bypass_403.Bypass403  # True
"""

from modules.scanners.bypass_403 import (  # noqa: F401
    Bypass403,
    BypassResult,
    FullBypassReport,
    analyze,
)

__all__ = ["Bypass403", "BypassResult", "FullBypassReport", "analyze"]
