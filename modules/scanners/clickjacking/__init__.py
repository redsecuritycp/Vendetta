"""
Módulo de detección de Clickjacking
Verifica si un sitio puede ser embebido en iframes (X-Frame-Options + CSP frame-ancestors).

Interfaz pública:
    from modules.scanners.clickjacking import ClickjackingAnalyzer, ClickjackingResult
"""

from .scanner import ClickjackingAnalyzer, ClickjackingResult

__all__ = ["ClickjackingAnalyzer", "ClickjackingResult"]
