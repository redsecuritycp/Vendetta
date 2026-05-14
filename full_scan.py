"""
DEPRECATED PATH — wrapper de retro-compatibilidad.

El código real vive en `modules/scan_orchestrator/orchestrator.py` desde
2026-05-14 (Fase 13 modular según MODULAR_PLAN.md).

Este wrapper queda durante 2-4 semanas para no romper:
    from full_scan import FullScanner, ScanProgress

Después se borra. NO editar — modificar el módulo nuevo.
"""

from modules.scan_orchestrator import FullScanner, ScanProgress  # noqa: F401

__all__ = ["FullScanner", "ScanProgress"]
