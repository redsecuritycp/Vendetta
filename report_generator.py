"""
DEPRECATED PATH — wrapper de retro-compatibilidad.

El código real vive en `modules/reports/generator.py` desde
2026-05-14 (Fase 14 modular según MODULAR_PLAN.md).

Este wrapper queda durante 2-4 semanas para no romper:
    from report_generator import Finding, ScanReport, ReportGenerator

Después se borra. NO editar — modificar el módulo nuevo.
"""

from modules.reports import Finding, ScanReport, ReportGenerator  # noqa: F401

__all__ = ["Finding", "ScanReport", "ReportGenerator"]
