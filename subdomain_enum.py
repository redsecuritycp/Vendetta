"""
Subdomain Enumerator - Encuentra subdominios de un dominio
Solo para uso en sistemas propios o con autorización explícita
"""

import socket
import requests
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import time


@dataclass
class SubdomainInfo:
    subdomain: str
    full_domain: str
    ip_addresses: List[str]
    http_status: Optional[int]
    https_status: Optional[int]
    title: Optional[str]
    server: Optional[str]


@dataclass
class SubdomainResult:
    target_domain: str
    subdomains_found: List[SubdomainInfo]
    total_checked: int
    duration: float
    details: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


class SubdomainEnumerator:
    """
    Enumera subdominios usando fuerza bruta con diccionario
    """
    
    COMMON_SUBDOMAINS = [
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
        "dns", "dns1", "dns2", "mx", "mx1", "mx2", "admin", "administrator",
        "blog", "shop", "store", "forum", "dev", "development", "staging", "stage",
        "test", "testing", "demo", "beta", "alpha", "api", "api2", "api-v2",
        "app", "apps", "mobile", "m", "static", "assets", "cdn", "media", "images",
        "img", "video", "downloads", "dl", "files", "docs", "doc", "documentation",
        "help", "support", "portal", "my", "account", "accounts", "login", "signin",
        "auth", "oauth", "sso", "secure", "vpn", "remote", "gateway", "gw",
        "proxy", "cache", "web", "www1", "www2", "www3", "server", "server1",
        "server2", "host", "node", "node1", "node2", "cluster", "db", "database",
        "mysql", "postgres", "postgresql", "mongo", "mongodb", "redis", "elastic",
        "elasticsearch", "kibana", "grafana", "prometheus", "jenkins", "ci", "cd",
        "git", "gitlab", "github", "bitbucket", "svn", "repo", "repository",
        "docker", "kubernetes", "k8s", "aws", "azure", "gcp", "cloud", "backup",
        "bk", "old", "new", "legacy", "archive", "internal", "intranet", "extranet",
        "partners", "partner", "vendor", "vendors", "client", "clients", "customer",
        "crm", "erp", "hr", "finance", "sales", "marketing", "analytics", "stats",
        "status", "monitor", "monitoring", "logs", "log", "track", "tracking",
        "payment", "payments", "pay", "billing", "invoice", "cart", "checkout",
        "order", "orders", "search", "find", "news", "press", "events", "calendar",
        "careers", "jobs", "about", "contact", "info", "legal", "privacy", "terms",
        "cpanel", "plesk", "whm", "webmin", "phpmyadmin", "pma", "adminer",
        "wp", "wordpress", "joomla", "drupal", "magento", "prestashop", "woocommerce"
    ]
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        self.session.verify = False
        requests.packages.urllib3.disable_warnings()
    
    def _extract_domain(self, url_or_domain: str) -> str:
        """Extrae el dominio base de una URL o dominio"""
        if "://" in url_or_domain:
            parsed = urlparse(url_or_domain)
            domain = parsed.hostname or url_or_domain
        else:
            domain = url_or_domain
        
        parts = domain.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return domain
    
    def _resolve_domain(self, domain: str) -> List[str]:
        """Resuelve un dominio a sus IPs"""
        try:
            ips = socket.gethostbyname_ex(domain)[2]
            return ips
        except:
            return []
    
    def _check_http(self, domain: str, use_https: bool = False) -> tuple:
        """Verifica si hay un servidor HTTP/HTTPS respondiendo"""
        scheme = "https" if use_https else "http"
        url = f"{scheme}://{domain}"
        
        try:
            response = self.session.get(url, timeout=5, allow_redirects=True)
            
            title = None
            if "text/html" in response.headers.get("Content-Type", ""):
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(response.text, "html.parser")
                if soup.title:
                    title = soup.title.string[:100] if soup.title.string else None
            
            server = response.headers.get("Server")
            
            return response.status_code, title, server
        except:
            return None, None, None
    
    def _check_subdomain(self, subdomain: str, base_domain: str) -> Optional[SubdomainInfo]:
        """Verifica si un subdominio existe"""
        full_domain = f"{subdomain}.{base_domain}"
        
        ips = self._resolve_domain(full_domain)
        if not ips:
            return None
        
        http_status, http_title, http_server = self._check_http(full_domain, use_https=False)
        https_status, https_title, https_server = self._check_http(full_domain, use_https=True)
        
        title = https_title or http_title
        server = https_server or http_server
        
        return SubdomainInfo(
            subdomain=subdomain,
            full_domain=full_domain,
            ip_addresses=ips,
            http_status=http_status,
            https_status=https_status,
            title=title,
            server=server
        )
    
    def analyze(self, domain: str, custom_wordlist: Optional[List[str]] = None,
                threads: int = 20, timeout: int = 120) -> SubdomainResult:
        """
        Enumera subdominios del dominio objetivo
        
        Args:
            domain: Dominio o URL objetivo
            custom_wordlist: Lista adicional de subdominios a probar
            threads: Número de hilos concurrentes
            timeout: Tiempo máximo de ejecución en segundos
        """
        base_domain = self._extract_domain(domain)
        
        subdomains_to_check = list(self.COMMON_SUBDOMAINS)
        if custom_wordlist:
            subdomains_to_check.extend(custom_wordlist)
        subdomains_to_check = list(set(subdomains_to_check))
        
        found_subdomains: List[SubdomainInfo] = []
        start_time = time.time()
        checked = 0
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(self._check_subdomain, sub, base_domain): sub
                for sub in subdomains_to_check
            }
            
            for future in as_completed(futures, timeout=timeout):
                checked += 1
                try:
                    result = future.result(timeout=5)
                    if result:
                        found_subdomains.append(result)
                except:
                    pass
                
                if time.time() - start_time > timeout:
                    break
        
        duration = time.time() - start_time
        
        found_subdomains.sort(key=lambda x: x.subdomain)
        
        details = [
            f"Dominio base: {base_domain}",
            f"Subdominios probados: {checked}",
            f"Subdominios encontrados: {len(found_subdomains)}",
            f"Duración: {duration:.1f}s"
        ]
        
        recommendations = []
        
        sensitive_subs = ["admin", "dev", "staging", "test", "backup", "internal", "vpn"]
        found_sensitive = [s for s in found_subdomains if s.subdomain in sensitive_subs]
        
        if found_sensitive:
            recommendations.append(f"Se encontraron {len(found_sensitive)} subdominios sensibles")
            recommendations.append("Considerar restringir acceso a subdominios de desarrollo/admin")
            recommendations.append("Verificar que no expongan información sensible")
        
        unique_ips = set()
        for sub in found_subdomains:
            unique_ips.update(sub.ip_addresses)
        
        if len(unique_ips) > 1:
            recommendations.append(f"Los subdominios apuntan a {len(unique_ips)} IPs diferentes")
            recommendations.append("Verificar que todos los servidores estén correctamente asegurados")
        
        http_only = [s for s in found_subdomains if s.http_status and not s.https_status]
        if http_only:
            recommendations.append(f"{len(http_only)} subdominios solo tienen HTTP (sin HTTPS)")
        
        if not recommendations:
            recommendations.append("Configuración de subdominios parece correcta")
        
        return SubdomainResult(
            target_domain=base_domain,
            subdomains_found=found_subdomains,
            total_checked=checked,
            duration=duration,
            details=details,
            recommendations=recommendations
        )


def main():
    import sys
    
    print("=" * 60)
    print("SUBDOMAIN ENUMERATOR - Búsqueda de Subdominios")
    print("=" * 60)
    print("\nADVERTENCIA: Solo para sistemas propios o autorizados")
    print("=" * 60)
    
    if len(sys.argv) < 2:
        print("\nUso: python subdomain_enum.py <dominio>")
        print("Ejemplo: python subdomain_enum.py example.com")
        sys.exit(1)
    
    domain = sys.argv[1]
    
    enumerator = SubdomainEnumerator()
    result = enumerator.analyze(domain)
    
    print(f"\nEncontrados: {len(result.subdomains_found)} subdominios")
    
    for sub in result.subdomains_found:
        status = f"HTTP:{sub.http_status or '-'} HTTPS:{sub.https_status or '-'}"
        print(f"  {sub.full_domain} -> {', '.join(sub.ip_addresses)} ({status})")


if __name__ == "__main__":
    main()
