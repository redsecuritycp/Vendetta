"""
Módulo de enumeración de subdominios.

Fuerza bruta con diccionario común (~120 nombres) sobre un dominio base,
resuelve DNS, prueba HTTP/HTTPS y reporta subdominios vivos con título,
servidor e IPs.

Interfaz pública:
    from modules.scanners.subdomain_enum import (
        SubdomainEnumerator,
        SubdomainResult,
        SubdomainInfo,
    )
"""

from .scanner import SubdomainEnumerator, SubdomainResult, SubdomainInfo

__all__ = ["SubdomainEnumerator", "SubdomainResult", "SubdomainInfo"]
