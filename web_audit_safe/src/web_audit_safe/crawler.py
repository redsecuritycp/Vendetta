"""
Crawler BFS para recorrer páginas web de forma pasiva
"""

import time
from typing import Dict, List, Set, Optional, Tuple
from urllib.parse import urlparse, urljoin
from collections import deque
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .utils import (
    normalize_url, get_host_from_url, is_in_scope,
    RateLimiter, sanitize_content, extract_links
)


class WebCrawler:
    """Crawler BFS para análisis pasivo de sitios web"""
    
    def __init__(
        self,
        scope_url: str,
        max_pages: int = 20,
        max_requests: int = 200,
        timeout: int = 10,
        max_redirects: int = 5,
        max_file_size: int = 5 * 1024 * 1024,  # 5MB
        delay: float = 1.0
    ):
        """
        Args:
            scope_url: URL base del scope a analizar
            max_pages: Máximo de páginas a analizar
            max_requests: Máximo de requests totales
            timeout: Timeout por request en segundos
            max_redirects: Máximo de redirects a seguir
            max_file_size: Tamaño máximo de archivo a descargar
            delay: Delay entre requests en segundos (default: 1.0)
        """
        self.scope_url = normalize_url(scope_url)
        self.max_pages = max_pages
        self.max_requests = max_requests
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.max_file_size = max_file_size
        
        # Estado del crawler
        self.visited: Set[str] = set()
        self.queue: deque = deque()
        self.responses: List[Dict] = []
        self.request_count = 0
        self.robots_txt_content: Optional[str] = None
        self.robots_txt_url: Optional[str] = None
        
        # Rate limiter con delay configurable
        requests_per_second = 1.0 / delay if delay > 0 else 1.0
        self.rate_limiter = RateLimiter(requests_per_second=requests_per_second)
        
        # Configurar sesión HTTP
        self.session = self._create_session()
        
        # Agregar URL inicial a la cola
        if self.scope_url:
            self.queue.append(self.scope_url)
    
    def _create_session(self) -> requests.Session:
        """Crea una sesión HTTP configurada con retries y timeouts"""
        session = requests.Session()
        
        # Configurar retries (1 retry adicional)
        retry_strategy = Retry(
            total=1,
            backoff_factor=0.3,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Headers por defecto
        session.headers.update({
            'User-Agent': 'web-audit-safe/1.0 (Security Audit Tool)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        
        return session
    
    def _check_robots_txt(self) -> bool:
        """
        Verifica y lee robots.txt del sitio.
        
        Returns:
            True si robots.txt existe y fue leído
        """
        if self.robots_txt_content is not None:
            return self.robots_txt_content != ""
        
        parsed = urlparse(self.scope_url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        
        try:
            host = get_host_from_url(robots_url)
            if host:
                self.rate_limiter.wait_if_needed(host)
            
            response = self.session.head(robots_url, timeout=self.timeout, allow_redirects=False)
            
            if response.status_code == 200:
                # Leer contenido (limitado)
                content_response = self.session.get(
                    robots_url,
                    timeout=self.timeout,
                    stream=True
                )
                if content_response.status_code == 200:
                    content = ""
                    for chunk in content_response.iter_content(chunk_size=1024, decode_unicode=True):
                        content += chunk
                        if len(content) > 8192:  # Limitar a 8KB
                            break
                    self.robots_txt_content = content
                    self.robots_txt_url = robots_url
                    self.request_count += 2  # HEAD + GET
                    return True
            
            self.robots_txt_content = ""
            self.request_count += 1
            return False
            
        except Exception:
            self.robots_txt_content = ""
            return False
    
    def _fetch_page(self, url: str) -> Optional[Dict]:
        """
        Obtiene una página y retorna información estructurada.
        
        Args:
            url: URL a obtener
            
        Returns:
            Diccionario con información de la respuesta o None si falla
        """
        if self.request_count >= self.max_requests:
            return None
        
        host = get_host_from_url(url)
        if not host:
            return None
        
        # Rate limiting
        self.rate_limiter.wait_if_needed(host)
        
        try:
            # Intentar HEAD primero para archivos grandes
            head_response = self.session.head(
                url,
                timeout=self.timeout,
                allow_redirects=False
            )
            
            self.request_count += 1
            
            # Verificar tamaño de contenido
            content_length = head_response.headers.get('Content-Length')
            if content_length:
                try:
                    size = int(content_length)
                    if size > self.max_file_size:
                        return {
                            'url': url,
                            'status_code': head_response.status_code,
                            'headers': dict(head_response.headers),
                            'content': None,
                            'content_type': head_response.headers.get('Content-Type', ''),
                            'size': size,
                            'error': f'Archivo demasiado grande ({size} bytes)'
                        }
                except ValueError:
                    pass
            
            # Seguir redirects (máx max_redirects)
            redirect_count = 0
            current_url = url
            response = head_response
            
            while (response.status_code in [301, 302, 303, 307, 308] and 
                   redirect_count < self.max_redirects):
                location = response.headers.get('Location')
                if not location:
                    break
                
                # Resolver URL relativa
                current_url = urljoin(current_url, location)
                
                # Verificar que esté en scope
                if not is_in_scope(current_url, self.scope_url):
                    break
                
                # Seguir redirect
                self.rate_limiter.wait_if_needed(get_host_from_url(current_url) or host)
                response = self.session.head(
                    current_url,
                    timeout=self.timeout,
                    allow_redirects=False
                )
                redirect_count += 1
                self.request_count += 1
                
                if self.request_count >= self.max_requests:
                    break
            
            # Obtener contenido solo si es HTML/texto y no es demasiado grande
            content = None
            content_type = response.headers.get('Content-Type', '').lower()
            
            if (response.status_code == 200 and 
                ('text/html' in content_type or 
                 'text/plain' in content_type or
                 'application/json' in content_type or
                 'application/xml' in content_type)):
                
                # GET para obtener contenido
                if self.request_count < self.max_requests:
                    self.rate_limiter.wait_if_needed(host)
                    get_response = self.session.get(
                        current_url,
                        timeout=self.timeout,
                        stream=True,
                        allow_redirects=False
                    )
                    self.request_count += 1
                    
                    # Leer contenido limitado
                    content_bytes = b""
                    for chunk in get_response.iter_content(chunk_size=8192):
                        content_bytes += chunk
                        if len(content_bytes) > self.max_file_size:
                            break
                    
                    content = sanitize_content(content_bytes, max_length=2048)
            
            return {
                'url': current_url,
                'original_url': url,
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content': content,
                'content_type': response.headers.get('Content-Type', ''),
                'size': len(content) if content else 0,
                'redirect_count': redirect_count,
                'final_url': current_url if redirect_count > 0 else url
            }
            
        except requests.exceptions.Timeout:
            return {
                'url': url,
                'status_code': None,
                'headers': {},
                'content': None,
                'content_type': '',
                'size': 0,
                'error': 'Timeout'
            }
        except requests.exceptions.RequestException as e:
            return {
                'url': url,
                'status_code': None,
                'headers': {},
                'content': None,
                'content_type': '',
                'size': 0,
                'error': str(e)
            }
        except Exception as e:
            return {
                'url': url,
                'status_code': None,
                'headers': {},
                'content': None,
                'content_type': '',
                'size': 0,
                'error': f'Error inesperado: {str(e)}'
            }
    
    def crawl(self) -> List[Dict]:
        """
        Ejecuta el crawler BFS.
        
        Returns:
            Lista de respuestas obtenidas
        """
        # Verificar robots.txt primero
        self._check_robots_txt()
        
        # BFS
        while self.queue and len(self.responses) < self.max_pages and self.request_count < self.max_requests:
            url = self.queue.popleft()
            
            # Verificar si ya fue visitada
            if url in self.visited:
                continue
            
            # Verificar que esté en scope
            if not is_in_scope(url, self.scope_url):
                continue
            
            # Marcar como visitada
            self.visited.add(url)
            
            # Obtener página
            response_data = self._fetch_page(url)
            
            if response_data:
                self.responses.append(response_data)
                
                # Extraer links si es HTML
                if (response_data.get('content') and 
                    'text/html' in response_data.get('content_type', '').lower()):
                    
                    links = extract_links(response_data['content'], response_data['url'])
                    
                    # Agregar links válidos a la cola
                    for link in links:
                        if (link not in self.visited and 
                            is_in_scope(link, self.scope_url) and
                            len(self.queue) < 100):  # Limitar tamaño de cola
                            self.queue.append(link)
        
        return self.responses
    
    def get_robots_txt(self) -> Tuple[Optional[str], Optional[str]]:
        """
        Retorna el contenido de robots.txt si fue encontrado.
        
        Returns:
            Tupla (contenido, url) o (None, None)
        """
        if self.robots_txt_content:
            return (self.robots_txt_content, self.robots_txt_url)
        return (None, None)

