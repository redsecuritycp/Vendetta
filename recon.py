"""
DEPRECATED PATH — wrapper de retro-compatibilidad.

El código real vive en `modules/scanners/recon/scanner.py` desde 2026-05-14
(Fase 1 modular según MODULAR_PLAN.md).

Este wrapper queda durante 2-4 semanas para no romper:
    from recon import PassiveRecon, ReconResult

Después se borra. NO editar — modificar el módulo nuevo.
"""

from modules.scanners.recon import PassiveRecon, ReconResult  # noqa: F401

__all__ = ["PassiveRecon", "ReconResult"]


def main():
    """Compat: `python recon.py <url>` sigue funcionando."""
    from modules.scanners.recon.scanner import main as _main
    _main()


if __name__ == "__main__":
    main()
