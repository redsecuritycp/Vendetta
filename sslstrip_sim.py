"""
DEPRECATED PATH — wrapper de retro-compatibilidad.

El código real vive en `modules/scanners/hsts_ssl/scanner.py` desde 2026-05-14
(Fase 6 modular según MODULAR_PLAN.md).

Este wrapper queda durante 2-4 semanas para no romper imports flat existentes:
    from sslstrip_sim import SSLStripAnalyzer
    from sslstrip_sim import SSLStripAnalyzer, HSTSResult

Después se borra. NO editar — modificar el módulo nuevo.

Identidad preservada:
    sslstrip_sim.SSLStripAnalyzer is modules.scanners.hsts_ssl.SSLStripAnalyzer  # True
"""

from modules.scanners.hsts_ssl import SSLStripAnalyzer, HSTSResult  # noqa: F401

__all__ = ["SSLStripAnalyzer", "HSTSResult"]


def main():
    """Compat: `python sslstrip_sim.py <url>` sigue funcionando."""
    from modules.scanners.hsts_ssl.scanner import main as _main
    _main()


if __name__ == "__main__":
    main()
