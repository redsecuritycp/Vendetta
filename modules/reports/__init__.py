"""
Módulo Reports
Modelo de datos (`Finding`, `ScanReport`) y generador HTML
(`ReportGenerator`) para los reportes de auditoría de seguridad.

Interfaz pública:
    from modules.reports import Finding, ScanReport, ReportGenerator
"""

from .generator import Finding, ScanReport, ReportGenerator

__all__ = ["Finding", "ScanReport", "ReportGenerator"]
