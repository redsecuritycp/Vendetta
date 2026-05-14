"""
DEPRECATED PATH — wrapper de retro-compatibilidad.

El código real vive en `modules/scanners/subdomain_enum/scanner.py` desde
2026-05-14 (Fase 7 modular según MODULAR_PLAN.md).

Este wrapper queda durante 2-4 semanas para no romper imports flat existentes:
    from subdomain_enum import SubdomainEnumerator
    from subdomain_enum import SubdomainEnumerator, SubdomainResult, SubdomainInfo

Después se borra. NO editar — modificar el módulo nuevo.

Identidad preservada:
    subdomain_enum.SubdomainEnumerator is modules.scanners.subdomain_enum.SubdomainEnumerator  # True
"""

from modules.scanners.subdomain_enum import (  # noqa: F401
    SubdomainEnumerator,
    SubdomainResult,
    SubdomainInfo,
)

__all__ = ["SubdomainEnumerator", "SubdomainResult", "SubdomainInfo"]


def main():
    """Compat: `python subdomain_enum.py <dominio>` sigue funcionando."""
    from modules.scanners.subdomain_enum.scanner import main as _main
    _main()


if __name__ == "__main__":
    main()
