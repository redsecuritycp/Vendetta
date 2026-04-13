"""
Validacion y sanitizacion de URLs
"""

import re
from urllib.parse import urlparse
from typing import Tuple


def validate_url(url: str) -> Tuple[bool, str, str]:
    """
    Valida y normaliza una URL.

    Returns:
        Tuple de (es_valida, url_normalizada, mensaje_error)
    """
    if not url or not url.strip():
        return False, "", "URL vacia"

    url = url.strip()

    # Agregar scheme si falta
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)
    except Exception:
        return False, "", "URL malformada"

    if not parsed.scheme or parsed.scheme not in ("http", "https"):
        return False, "", "Scheme invalido (debe ser http o https)"

    if not parsed.netloc:
        return False, "", "Falta el dominio"

    # Validar que el dominio tenga formato correcto
    hostname = parsed.hostname or ""
    if not hostname:
        return False, "", "Hostname vacio"

    # No permitir IPs privadas ni localhost (seguridad SSRF basica)
    # Esto se puede deshabilitar para pentesting interno
    # if hostname in ("localhost", "127.0.0.1", "0.0.0.0"):
    #     return False, "", "No se permiten direcciones locales"

    # Validar formato de dominio basico
    domain_pattern = re.compile(
        r'^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)*'
        r'[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?'
        r'(\.[a-zA-Z]{2,})?$'
    )
    # Permitir IPs tambien
    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

    if not domain_pattern.match(hostname) and not ip_pattern.match(hostname):
        return False, "", f"Dominio invalido: {hostname}"

    return True, url, ""


def extract_domain(url: str) -> str:
    """Extrae solo el dominio de una URL"""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    return parsed.netloc or parsed.path


def normalize_url(url: str) -> str:
    """Normaliza una URL agregando scheme si falta"""
    if not url.startswith(("http://", "https://")):
        return "https://" + url
    return url
