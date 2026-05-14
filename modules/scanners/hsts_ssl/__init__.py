"""
Módulo de análisis HSTS / SSLStrip.

Detecta configuraciones inseguras de HSTS (`Strict-Transport-Security`),
falta de redirección HTTP→HTTPS y problemas básicos del certificado SSL
que habilitan ataques de downgrade tipo SSLStrip.

Interfaz pública:
    from modules.scanners.hsts_ssl import SSLStripAnalyzer, HSTSResult
"""

from .scanner import SSLStripAnalyzer, HSTSResult

__all__ = ["SSLStripAnalyzer", "HSTSResult"]
