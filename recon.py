"""
Herramienta de Reconocimiento Pasivo
Recopila información pública sobre un dominio sin realizar ataques activos
"""

import requests
import socket
import ssl
import re
from urllib.parse import urlparse
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class ReconResult:
    """Resultado del reconocimiento pasivo"""
    url: str
    domain: str
    ip_addresses: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    security_headers: Dict[str, str] = field(default_factory=dict)
    technologies: List[str] = field(default_factory=list)
    ssl_info: Dict = field(default_factory=dict)
    dns_info: Dict = field(default_factory=dict)
    server_info: Dict = field(default_factory=dict)
    findings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


class PassiveRecon:
    """Herramienta de reconocimiento pasivo"""
    
    # Headers de seguridad importantes
    SECURITY_HEADERS = [
        'Strict-Transport-Security',
        'Content-Security-Policy',
        'X-Frame-Options',
        'X-Content-Type-Options',
        'X-XSS-Protection',
        'Referrer-Policy',
        'Permissions-Policy',
        'Cross-Origin-Opener-Policy',
        'Cross-Origin-Resource-Policy',
    ]
    
    # Patrones para detectar tecnologías
    TECH_PATTERNS = {
        'Apache': r'Apache',
        'Nginx': r'nginx',
        'IIS': r'Microsoft-IIS',
        'PHP': r'PHP|PHPSESSID',
        'ASP.NET': r'ASP\.NET|__VIEWSTATE',
        'WordPress': r'wp-content|wp-includes',
        'Drupal': r'Drupal|drupal',
        'jQuery': r'jquery',
        'React': r'react|__REACT',
        'Vue.js': r'vue|__VUE',
        'Angular': r'ng-|angular',
        'Bootstrap': r'bootstrap',
        'Cloudflare': r'cloudflare|cf-ray',
        'AWS': r'AmazonS3|aws|x-amz',
        'Google Cloud': r'gcp|google-cloud',
    }
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SecurityAudit/1.0 (Passive Reconnaissance)'
        })
    
    def analyze(self, url: str) -> ReconResult:
        """
        Realiza reconocimiento pasivo de un sitio
        
        Args:
            url: URL del sitio a analizar
            
        Returns:
            ReconResult con la información recopilada
        """
        parsed = urlparse(url)
        if not parsed.scheme:
            url = f"https://{url}"
            parsed = urlparse(url)
        
        domain = parsed.netloc
        
        result = ReconResult(url=url, domain=domain)
        
        # Resolver DNS
        result.ip_addresses = self._resolve_dns(domain)
        
        # Obtener headers HTTP
        headers_info = self._get_headers(url)
        result.headers = headers_info.get('all', {})
        result.security_headers = headers_info.get('security', {})
        
        # Detectar tecnologías
        result.technologies = self._detect_technologies(url, result.headers)
        
        # Información SSL
        result.ssl_info = self._get_ssl_info(domain)
        
        # Información del servidor
        result.server_info = self._get_server_info(result.headers)
        
        # Generar hallazgos y recomendaciones
        self._generate_findings(result)
        
        return result
    
    def _resolve_dns(self, domain: str) -> List[str]:
        """Resuelve direcciones IP del dominio"""
        try:
            ips = socket.gethostbyname_ex(domain)[2]
            return ips
        except:
            return []
    
    def _get_headers(self, url: str) -> Dict:
        """Obtiene headers HTTP del sitio"""
        try:
            response = self.session.get(url, timeout=10)
            all_headers = dict(response.headers)
            
            security_headers = {}
            for header in self.SECURITY_HEADERS:
                if header in response.headers:
                    security_headers[header] = response.headers[header]
            
            return {
                'all': all_headers,
                'security': security_headers
            }
        except:
            return {'all': {}, 'security': {}}
    
    def _detect_technologies(self, url: str, headers: Dict) -> List[str]:
        """Detecta tecnologías usadas en el sitio"""
        technologies = []
        
        try:
            response = self.session.get(url, timeout=10)
            content = response.text
            headers_str = str(headers)
            combined = content + headers_str
            
            for tech, pattern in self.TECH_PATTERNS.items():
                if re.search(pattern, combined, re.IGNORECASE):
                    technologies.append(tech)
            
            if 'X-Powered-By' in headers:
                powered_by = self._sanitize(headers['X-Powered-By'])
                if powered_by not in technologies:
                    technologies.append(f"X-Powered-By: {powered_by}")
            
            if 'Server' in headers:
                server = self._sanitize(headers['Server'])
                if not any(t in server for t in technologies):
                    technologies.append(f"Server: {server}")
                    
        except:
            pass
        
        return list(set(technologies))
    
    def _sanitize(self, value: str) -> str:
        """Sanitiza valores para evitar XSS"""
        if not value:
            return ""
        return value.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')[:100]
    
    def _get_ssl_info(self, domain: str) -> Dict:
        """Obtiene información del certificado SSL"""
        info: Dict = {}
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    if cert:
                        subject = cert.get('subject', [])
                        issuer = cert.get('issuer', [])
                        info['subject'] = dict(x[0] for x in subject) if subject else {}
                        info['issuer'] = dict(x[0] for x in issuer) if issuer else {}
                        info['version'] = cert.get('version')
                        info['notBefore'] = cert.get('notBefore')
                        info['notAfter'] = cert.get('notAfter')
                        info['serialNumber'] = cert.get('serialNumber')
                        
                        san = cert.get('subjectAltName', [])
                        info['altNames'] = [x[1] for x in san if x[0] == 'DNS']
                    
                    info['protocol'] = ssock.version()
                    info['cipher'] = ssock.cipher()
                    
        except Exception as e:
            info['error'] = str(e)[:100]
        
        return info
    
    def _get_server_info(self, headers: Dict) -> Dict:
        """Extrae información del servidor de los headers"""
        info = {}
        
        if 'Server' in headers:
            info['server'] = headers['Server']
        
        if 'X-Powered-By' in headers:
            info['powered_by'] = headers['X-Powered-By']
        
        if 'X-AspNet-Version' in headers:
            info['aspnet_version'] = headers['X-AspNet-Version']
        
        return info
    
    def _generate_findings(self, result: ReconResult):
        """Genera hallazgos y recomendaciones basados en el análisis"""
        
        # Verificar headers de seguridad faltantes
        missing_headers = [h for h in self.SECURITY_HEADERS if h not in result.security_headers]
        
        if 'Strict-Transport-Security' in missing_headers:
            result.findings.append("Falta header HSTS - Vulnerable a ataques de downgrade")
            result.recommendations.append("Implementar Strict-Transport-Security header")
        
        if 'Content-Security-Policy' in missing_headers:
            result.findings.append("Falta Content-Security-Policy - Vulnerable a XSS")
            result.recommendations.append("Implementar Content-Security-Policy")
        
        if 'X-Frame-Options' in missing_headers:
            result.findings.append("Falta X-Frame-Options - Vulnerable a clickjacking")
            result.recommendations.append("Agregar header X-Frame-Options: DENY o SAMEORIGIN")
        
        # Verificar información expuesta
        if result.server_info.get('server'):
            result.findings.append(f"Servidor expone versión: {result.server_info['server']}")
            result.recommendations.append("Ocultar versión del servidor en headers")
        
        if result.server_info.get('powered_by'):
            result.findings.append(f"X-Powered-By expone tecnología: {result.server_info['powered_by']}")
            result.recommendations.append("Remover header X-Powered-By")
        
        # Verificar SSL
        if result.ssl_info.get('error'):
            result.findings.append(f"Problema con SSL: {result.ssl_info['error']}")
        elif result.ssl_info.get('protocol'):
            protocol = result.ssl_info['protocol']
            if 'TLSv1.0' in protocol or 'TLSv1.1' in protocol:
                result.findings.append(f"Protocolo SSL obsoleto: {protocol}")
                result.recommendations.append("Actualizar a TLS 1.2 o superior")


def main():
    """Función principal para uso CLI"""
    import sys
    import json
    
    print("=" * 60)
    print("RECONOCIMIENTO PASIVO")
    print("=" * 60)
    print("\nADVERTENCIA LEGAL:")
    print("Esta herramienta recopila solo información pública.")
    print("Úsela solo en sistemas propios o con autorización.")
    print("=" * 60)
    
    if len(sys.argv) < 2:
        print("\nUso: python recon.py <url>")
        print("Ejemplo: python recon.py https://ejemplo.com")
        sys.exit(1)
    
    url = sys.argv[1]
    recon = PassiveRecon()
    result = recon.analyze(url)
    
    print(f"\nResultados para: {result.url}")
    print(f"Dominio: {result.domain}")
    print("-" * 40)
    
    if result.ip_addresses:
        print(f"\nDirecciones IP: {', '.join(result.ip_addresses)}")
    
    if result.technologies:
        print(f"\nTecnologías detectadas:")
        for tech in result.technologies:
            print(f"  - {tech}")
    
    if result.ssl_info and not result.ssl_info.get('error'):
        print(f"\nInformación SSL:")
        if result.ssl_info.get('issuer'):
            issuer = result.ssl_info['issuer'].get('organizationName', 'Desconocido')
            print(f"  Emisor: {issuer}")
        if result.ssl_info.get('notAfter'):
            print(f"  Expira: {result.ssl_info['notAfter']}")
        if result.ssl_info.get('protocol'):
            print(f"  Protocolo: {result.ssl_info['protocol']}")
    
    print(f"\nHeaders de seguridad presentes: {len(result.security_headers)}/{len(PassiveRecon.SECURITY_HEADERS)}")
    for header, value in result.security_headers.items():
        print(f"  - {header}: {value[:50]}...")
    
    if result.findings:
        print("\nHALLAZGOS:")
        for f in result.findings:
            print(f"  - {f}")
    
    if result.recommendations:
        print("\nRECOMENDACIONES:")
        for r in result.recommendations:
            print(f"  - {r}")


if __name__ == "__main__":
    main()
