"""
Módulo Slowloris — prueba de estrés HTTP lenta (DoS sim).

ADVERTENCIA: este scanner es OPT-IN. NO forma parte del pipeline de
`FullScanner` (`POST /api/scan` NO lo ejecuta) — es destructivo por
naturaleza (consume sockets del target). Solo se invoca manualmente
contra sistemas propios o con autorización explícita.

Interfaz pública:
    from modules.scanners.slowloris import (
        SlowlorisAttacker,
        SlowlorisResult,
        analyze,
    )
"""

from .scanner import (
    SlowlorisAttacker,
    SlowlorisResult,
    analyze,
)

__all__ = ["SlowlorisAttacker", "SlowlorisResult", "analyze"]
