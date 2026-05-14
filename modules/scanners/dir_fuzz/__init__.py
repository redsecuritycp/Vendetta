"""
Módulo de fuzzing de directorios y archivos expuestos.

Busca paths comunes (.git, .env, backup.sql, wp-config.php, panels admin, etc.)
y archivos sensibles por extensión, clasificando hallazgos por nivel de riesgo.

Interfaz pública:
    from modules.scanners.dir_fuzz import DirectoryFuzzer, FuzzerResult
"""

from .scanner import DirectoryFuzzer, FuzzerResult

__all__ = ["DirectoryFuzzer", "FuzzerResult"]
