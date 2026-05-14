"""
Módulo de Reconocimiento Pasivo
Recopila información pública sobre un dominio sin realizar ataques activos.

Interfaz pública:
    from modules.scanners.recon import PassiveRecon, ReconResult
"""

from .scanner import PassiveRecon, ReconResult

__all__ = ["PassiveRecon", "ReconResult"]
