"""
Módulo Load Test — motor de prueba de carga HTTP concurrente (DoS sim).

ADVERTENCIA: este scanner es OPT-IN. NO forma parte del pipeline de
`FullScanner` (`POST /api/scan` NO lo ejecuta) — es destructivo por
naturaleza (genera tráfico HTTP de alta concurrencia contra el target).
Solo se invoca manualmente contra sistemas propios o con autorización
explícita.

Interfaz pública:
    from modules.scanners.load_test import (
        LoadTestEngine,
        analyze,
    )
"""

from .scanner import (
    LoadTestEngine,
    analyze,
)

__all__ = ["LoadTestEngine", "analyze"]
