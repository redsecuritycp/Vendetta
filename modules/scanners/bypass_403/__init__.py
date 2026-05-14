"""
Módulo de bypass de protecciones 403 Forbidden.

Intenta evadir 403 con múltiples técnicas: variantes de backup, case,
URL encoding, manipulación de path, headers de spoofing y métodos HTTP
alternativos. Solo para uso en sistemas propios o con autorización
explícita.

Interfaz pública:
    from modules.scanners.bypass_403 import (
        Bypass403,
        BypassResult,
        FullBypassReport,
        analyze,
    )
"""

from .scanner import (
    Bypass403,
    BypassResult,
    FullBypassReport,
    analyze,
)

__all__ = ["Bypass403", "BypassResult", "FullBypassReport", "analyze"]
