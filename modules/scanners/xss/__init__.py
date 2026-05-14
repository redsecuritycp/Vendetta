"""
Módulo de detección XSS (Cross-Site Scripting)
Analiza parámetros de URL para detectar puntos de inyección XSS reflejado.

Interfaz pública:
    from modules.scanners.xss import XSSAnalyzer, XSSResult, ReflectionChecker
"""

from .scanner import XSSAnalyzer, XSSResult, ReflectionChecker

__all__ = ["XSSAnalyzer", "XSSResult", "ReflectionChecker"]
