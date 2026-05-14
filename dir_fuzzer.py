"""
DEPRECATED PATH — wrapper de retro-compatibilidad.

El código real vive en `modules/scanners/dir_fuzz/scanner.py` desde 2026-05-14
(Fase 4 modular según MODULAR_PLAN.md).

Este wrapper queda durante 2-4 semanas para no romper imports flat existentes:
    from dir_fuzzer import DirectoryFuzzer
    from dir_fuzzer import DirectoryFuzzer, FuzzerResult

Después se borra. NO editar — modificar el módulo nuevo.

Identidad preservada:
    dir_fuzzer.DirectoryFuzzer is modules.scanners.dir_fuzz.DirectoryFuzzer  # True
"""

from modules.scanners.dir_fuzz import DirectoryFuzzer, FuzzerResult  # noqa: F401

__all__ = ["DirectoryFuzzer", "FuzzerResult"]


def main():
    """Compat: `python dir_fuzzer.py <url>` sigue funcionando."""
    from modules.scanners.dir_fuzz.scanner import main as _main
    _main()


if __name__ == "__main__":
    main()
