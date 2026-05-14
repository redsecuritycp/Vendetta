"""
Módulo Scan Orchestrator
Orquesta la ejecución secuencial de todos los scanners (recon, hsts/ssl,
xss, clickjacking, dir-fuzz, forms, subdomain-enum, bypass-403) y consolida
los hallazgos en un `ScanReport` unificado.

Interfaz pública:
    from modules.scan_orchestrator import FullScanner, ScanProgress
"""

from .orchestrator import FullScanner, ScanProgress

__all__ = ["FullScanner", "ScanProgress"]
