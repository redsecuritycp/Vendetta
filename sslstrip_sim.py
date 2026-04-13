"""
Analizador de vulnerabilidades HSTS/SSLStrip
Detecta configuraciones inseguras que podrían permitir ataques de downgrade SSL
"""

import requests
import ssl
import socket
from urllib.parse import urlparse
from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class HSTSResult:
    """Resultado del análisis HSTS"""
    url: str
    has_hsts: bool
    max_age: Optional[int]
    include_subdomains: bool
    preload: bool
    redirects_to_https: bool
    vulnerabilities: List[str]
    recommendations: List[str]
    risk_level: str  # "bajo", "medio", "alto", "critico"


class SSLStripAnalyzer:
    """Analizador de vulnerabilidades HSTS y SSLStrip"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SecurityAudit/1.0 (Authorized Test)'
        })
    
    def analyze(self, url: str) -> HSTSResult:
        """
        Analiza un sitio para detectar vulnerabilidades HSTS/SSLStrip
        
        Args:
            url: URL del sitio a analizar
            
        Returns:
            HSTSResult con los hallazgos
        """
        parsed = urlparse(url)
        if not parsed.scheme:
            url = f"https://{url}"
            parsed = urlparse(url)
        
        vulnerabilities = []
        recommendations = []
        
        # Verificar redirección HTTP -> HTTPS
        redirects_to_https = self._check_http_redirect(parsed.netloc)
        
        # Obtener headers HSTS
        hsts_header = self._get_hsts_header(url)
        
        has_hsts = hsts_header is not None
        max_age = None
        include_subdomains = False
        preload = False
        
        if hsts_header:
            max_age = self._parse_max_age(hsts_header)
            include_subdomains = 'includesubdomains' in hsts_header.lower()
            preload = 'preload' in hsts_header.lower()
        
        # Evaluar vulnerabilidades
        if not has_hsts:
            vulnerabilities.append("No tiene header HSTS - Vulnerable a SSLStrip")
            recommendations.append("Agregar header Strict-Transport-Security")
        else:
            if max_age and max_age < 31536000:  # Menos de 1 año
                vulnerabilities.append(f"HSTS max-age muy corto: {max_age}s (recomendado: 31536000)")
                recommendations.append("Aumentar max-age a al menos 1 año (31536000 segundos)")
            
            if not include_subdomains:
                vulnerabilities.append("HSTS no incluye subdominios")
                recommendations.append("Agregar directiva includeSubDomains")
            
            if not preload:
                recommendations.append("Considerar agregar directiva preload para HSTS Preload List")
        
        if not redirects_to_https:
            vulnerabilities.append("HTTP no redirige a HTTPS - Vulnerable en primera conexión")
            recommendations.append("Configurar redirección 301 de HTTP a HTTPS")
        
        # Verificar certificado SSL
        ssl_issues = self._check_ssl_cert(parsed.netloc)
        vulnerabilities.extend(ssl_issues)
        
        # Determinar nivel de riesgo
        risk_level = self._calculate_risk(vulnerabilities, has_hsts, redirects_to_https)
        
        return HSTSResult(
            url=url,
            has_hsts=has_hsts,
            max_age=max_age,
            include_subdomains=include_subdomains,
            preload=preload,
            redirects_to_https=redirects_to_https,
            vulnerabilities=vulnerabilities,
            recommendations=recommendations,
            risk_level=risk_level
        )
    
    def _check_http_redirect(self, domain: str) -> bool:
        """Verifica si HTTP redirige a HTTPS"""
        try:
            response = self.session.get(
                f"http://{domain}",
                allow_redirects=False,
                timeout=10
            )
            if response.status_code in [301, 302, 307, 308]:
                location = response.headers.get('Location', '')
                return location.startswith('https://')
            return False
        except:
            return False
    
    def _get_hsts_header(self, url: str) -> Optional[str]:
        """Obtiene el header HSTS del sitio"""
        try:
            response = self.session.get(url, timeout=10)
            return response.headers.get('Strict-Transport-Security')
        except:
            return None
    
    def _parse_max_age(self, hsts_header: str) -> Optional[int]:
        """Extrae el valor max-age del header HSTS"""
        try:
            for part in hsts_header.split(';'):
                part = part.strip().lower()
                if part.startswith('max-age='):
                    return int(part.split('=')[1])
        except:
            pass
        return None
    
    def _check_ssl_cert(self, domain: str) -> List[str]:
        """Verifica problemas con el certificado SSL"""
        issues = []
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    # Verificar fecha de expiración
                    # (simplificado - en producción verificar más detalles)
        except ssl.SSLCertVerificationError as e:
            issues.append(f"Error de certificado SSL: {str(e)[:100]}")
        except Exception as e:
            issues.append(f"Error conectando SSL: {str(e)[:100]}")
        return issues
    
    def _calculate_risk(self, vulnerabilities: List[str], has_hsts: bool, redirects: bool) -> str:
        """Calcula el nivel de riesgo basado en los hallazgos"""
        if not has_hsts and not redirects:
            return "critico"
        elif not has_hsts:
            return "alto"
        elif len(vulnerabilities) > 2:
            return "medio"
        elif len(vulnerabilities) > 0:
            return "bajo"
        return "ninguno"


def main():
    """Función principal para uso CLI"""
    import sys
    
    print("=" * 60)
    print("ANALIZADOR HSTS/SSLStrip")
    print("=" * 60)
    print("\nADVERTENCIA LEGAL:")
    print("Esta herramienta es solo para uso en sistemas propios o")
    print("con autorización explícita del propietario.")
    print("El uso no autorizado puede ser ilegal.")
    print("=" * 60)
    
    if len(sys.argv) < 2:
        print("\nUso: python sslstrip_sim.py <url>")
        print("Ejemplo: python sslstrip_sim.py https://ejemplo.com")
        sys.exit(1)
    
    url = sys.argv[1]
    analyzer = SSLStripAnalyzer()
    result = analyzer.analyze(url)
    
    print(f"\nResultados para: {result.url}")
    print("-" * 40)
    print(f"HSTS Habilitado: {'Sí' if result.has_hsts else 'No'}")
    if result.max_age:
        print(f"Max-Age: {result.max_age} segundos")
    print(f"Incluye Subdominios: {'Sí' if result.include_subdomains else 'No'}")
    print(f"Preload: {'Sí' if result.preload else 'No'}")
    print(f"Redirige HTTP->HTTPS: {'Sí' if result.redirects_to_https else 'No'}")
    print(f"Nivel de Riesgo: {result.risk_level.upper()}")
    
    if result.vulnerabilities:
        print("\nVULNERABILIDADES ENCONTRADAS:")
        for v in result.vulnerabilities:
            print(f"  - {v}")
    
    if result.recommendations:
        print("\nRECOMENDACIONES:")
        for r in result.recommendations:
            print(f"  - {r}")


if __name__ == "__main__":
    main()
