"""
Utilidades para normalización de URLs, validación y helpers generales
"""

import re
import socket
from urllib.parse import urlparse, urljoin, urlunparse, parse_qs
from typing import Optional, Tuple, Set
import time


def normalize_url(url: str) -> Optional[str]:
    """
    Normaliza una URL eliminando fragmentos, parámetros de tracking comunes
    y asegurando un formato consistente.
    
    Args:
        url: URL a normalizar
        
    Returns:
        URL normalizada o None si es inválida
    """
    if not url or not isinstance(url, str):
        return None
    
    # Limpiar espacios
    url = url.strip()
    
    # Si no tiene scheme, agregar https://
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        parsed = urlparse(url)
        
        # Normalizar scheme y netloc a minúsculas
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        
        # Remover puerto por defecto
        if scheme == 'https' and netloc.endswith(':443'):
            netloc = netloc[:-4]
        elif scheme == 'http' and netloc.endswith(':80'):
            netloc = netloc[:-4]
        
        # Remover fragmento
        fragment = ''
        
        # Remover parámetros de tracking comunes (opcional, solo query string)
        query = parsed.query
        if query:
            # Remover parámetros comunes de tracking
            tracking_params = ['utm_source', 'utm_medium', 'utm_campaign', 
                             'utm_term', 'utm_content', 'fbclid', 'gclid']
            params = parse_qs(query, keep_blank_values=True)
            filtered_params = {k: v for k, v in params.items() 
                             if k.lower() not in tracking_params}
            
            # Reconstruir query string
            if filtered_params:
                query_parts = []
                for key, values in filtered_params.items():
                    for value in values:
                        if value:
                            query_parts.append(f"{key}={value}")
                        else:
                            query_parts.append(key)
                query = '&'.join(query_parts)
            else:
                query = ''
        
        # Reconstruir URL
        normalized = urlunparse((
            scheme,
            netloc,
            parsed.path or '/',
            parsed.params,
            query,
            fragment
        ))
        
        return normalized
        
    except Exception:
        return None


def get_host_from_url(url: str) -> Optional[str]:
    """
    Extrae el host de una URL.
    
    Args:
        url: URL de la cual extraer el host
        
    Returns:
        Host o None si es inválida
    """
    try:
        parsed = urlparse(url)
        return parsed.netloc.lower()
    except Exception:
        return None


def is_same_host(url1: str, url2: str) -> bool:
    """
    Verifica si dos URLs pertenecen al mismo host.
    
    Args:
        url1: Primera URL
        url2: Segunda URL
        
    Returns:
        True si son del mismo host
    """
    host1 = get_host_from_url(url1)
    host2 = get_host_from_url(url2)
    
    if not host1 or not host2:
        return False
    
    # Remover puertos para comparación
    host1 = host1.split(':')[0]
    host2 = host2.split(':')[0]
    
    return host1 == host2


def is_in_scope(url: str, scope_url: str) -> bool:
    """
    Verifica si una URL está dentro del scope definido.
    
    Args:
        url: URL a verificar
        scope_url: URL del scope base
        
    Returns:
        True si está en el scope
    """
    if not url or not scope_url:
        return False
    
    # Normalizar ambas URLs
    url = normalize_url(url)
    scope_url = normalize_url(scope_url)
    
    if not url or not scope_url:
        return False
    
    # Verificar mismo host
    if not is_same_host(url, scope_url):
        return False
    
    # Verificar que el path esté dentro del scope
    parsed_url = urlparse(url)
    parsed_scope = urlparse(scope_url)
    
    url_path = parsed_url.path.rstrip('/')
    scope_path = parsed_scope.path.rstrip('/')
    
    # Si el scope tiene un path específico, la URL debe estar dentro
    if scope_path and scope_path != '/':
        if not url_path.startswith(scope_path):
            return False
    
    return True


def resolve_ip(hostname: str) -> Optional[str]:
    """
    Resuelve la IP de un hostname.
    
    Args:
        hostname: Hostname a resolver
        
    Returns:
        IP o None si no se puede resolver
    """
    try:
        # Remover puerto si existe
        hostname = hostname.split(':')[0]
        ip = socket.gethostbyname(hostname)
        return ip
    except (socket.gaierror, socket.herror, OSError):
        return None


def get_port_from_url(url: str) -> Optional[int]:
    """
    Extrae el puerto de una URL.
    
    Args:
        url: URL de la cual extraer el puerto
        
    Returns:
        Puerto o None si no está especificado
    """
    try:
        parsed = urlparse(url)
        if parsed.port:
            return parsed.port
        elif parsed.scheme == 'https':
            return 443
        elif parsed.scheme == 'http':
            return 80
        return None
    except Exception:
        return None


def sanitize_content(content: str, max_length: int = 2048) -> str:
    """
    Sanitiza contenido para almacenamiento seguro, limitando tamaño.
    
    Args:
        content: Contenido a sanitizar
        max_length: Longitud máxima
        
    Returns:
        Contenido sanitizado
    """
    if not content:
        return ""
    
    # Convertir a string si no lo es
    if not isinstance(content, bytes):
        content = str(content)
    else:
        try:
            content = content.decode('utf-8', errors='ignore')
        except Exception:
            return "[Contenido binario no decodificable]"
    
    # Limitar longitud
    if len(content) > max_length:
        content = content[:max_length] + "\n... [truncado]"
    
    # Remover caracteres de control problemáticos (mantener \n, \t, \r)
    content = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]', '', content)
    
    return content


def extract_links(html_content: str, base_url: str) -> Set[str]:
    """
    Extrae links de una página HTML.
    
    Args:
        html_content: Contenido HTML
        base_url: URL base para resolver links relativos
        
    Returns:
        Set de URLs absolutas encontradas
    """
    from bs4 import BeautifulSoup
    
    links = set()
    
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Buscar todos los tags <a> con href
        for tag in soup.find_all('a', href=True):
            href = tag.get('href', '').strip()
            if not href:
                continue
            
            # Resolver URL relativa
            try:
                absolute_url = urljoin(base_url, href)
                normalized = normalize_url(absolute_url)
                if normalized:
                    links.add(normalized)
            except Exception:
                continue
                
    except Exception:
        pass
    
    return links


class RateLimiter:
    """Rate limiter simple para controlar requests por segundo"""
    
    def __init__(self, requests_per_second: float = 1.0):
        """
        Args:
            requests_per_second: Número de requests por segundo permitidos
        """
        self.requests_per_second = requests_per_second
        self.min_interval = 1.0 / requests_per_second
        self.last_request_time = {}
    
    def wait_if_needed(self, host: str):
        """
        Espera si es necesario para respetar el rate limit.
        
        Args:
            host: Host para el cual aplicar el rate limit
        """
        now = time.time()
        
        if host in self.last_request_time:
            elapsed = now - self.last_request_time[host]
            if elapsed < self.min_interval:
                sleep_time = self.min_interval - elapsed
                time.sleep(sleep_time)
        
        self.last_request_time[host] = time.time()

