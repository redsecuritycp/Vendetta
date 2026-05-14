"""
Herramienta de Reconocimiento Pasivo - Información sobre el objetivo

⚠️ SOLO PARA USO EDUCATIVO Y EN SISTEMAS PROPIOS O AUTORIZADOS

Este script realiza reconocimiento pasivo:
- Análisis de robots.txt
- Headers informativos (X-Powered-By, Server, etc.)
- Fingerprinting básico
- Detección de tecnologías
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import sys
import re

def get_robots_txt(base_url):
    """Obtiene y analiza robots.txt"""
    parsed = urlparse(base_url)
    robots_url = urljoin(base_url, '/robots.txt')
    
    try:
        response = requests.get(robots_url, timeout=10)
        if response.status_code == 200:
            return response.text, robots_url
        return None, None
    except Exception:
        return None, None

def analyze_robots_txt(content):
    """Analiza robots.txt y extrae información sensible"""
    if not content:
        return []
    
    findings = []
    lines = content.split('\n')
    
    disallowed_paths = []
    for line in lines:
        line = line.strip()
        if line.lower().startswith('disallow:'):
            path = line[9:].strip()
            if path:
                disallowed_paths.append(path)
                
                # Detectar rutas sensibles
                sensitive_keywords = [
                    'admin', 'wp-admin', 'administrator', 'login', 'auth',
                    'sql', 'backup', 'logs', 'config', 'database', 'db',
                    'private', 'secret', 'api', 'internal'
                ]
                
                for keyword in sensitive_keywords:
                    if keyword.lower() in path.lower():
                        findings.append({
                            'type': 'sensitive_path',
                            'path': path,
                            'keyword': keyword,
                            'severity': 'medium'
                        })
    
    return findings

def get_headers_info(url):
    """Obtiene información de headers HTTP"""
    try:
        response = requests.head(url, allow_redirects=True, timeout=10)
        headers = {}
        
        # Headers informativos
        info_headers = [
            'Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Runtime',
            'X-Version', 'X-Framework', 'X-Generator'
        ]
        
        for header in info_headers:
            value = response.headers.get(header)
            if value:
                headers[header] = value
        
        # Headers de seguridad (para verificar qué falta)
        security_headers = {
            'Strict-Transport-Security': response.headers.get('Strict-Transport-Security'),
            'Content-Security-Policy': response.headers.get('Content-Security-Policy'),
            'X-Frame-Options': response.headers.get('X-Frame-Options'),
            'X-Content-Type-Options': response.headers.get('X-Content-Type-Options'),
        }
        
        return headers, security_headers
    
    except Exception as e:
        return {}, {}

def detect_technology(headers, html_content=None):
    """Detecta tecnologías usadas"""
    technologies = []
    
    # Por headers
    if 'X-Powered-By' in headers:
        tech = headers['X-Powered-By']
        technologies.append(f"Backend: {tech}")
    
    if 'Server' in headers:
        server = headers['Server']
        technologies.append(f"Servidor: {server}")
        
        # Detectar tecnologías específicas
        if 'nginx' in server.lower():
            technologies.append("Web Server: Nginx")
        elif 'apache' in server.lower():
            technologies.append("Web Server: Apache")
        elif 'cloudflare' in server.lower():
            technologies.append("CDN: Cloudflare")
    
    # Por HTML (si está disponible)
    if html_content:
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Meta generator (WordPress, etc.)
        generator = soup.find('meta', {'name': 'generator'})
        if generator:
            technologies.append(f"Generator: {generator.get('content', '')}")
        
        # Detectar WordPress
        if 'wp-content' in html_content or 'wp-includes' in html_content:
            technologies.append("CMS: WordPress")
        
        # Detectar React/Vue/Angular
        scripts = soup.find_all('script', src=True)
        for script in scripts:
            src = script.get('src', '')
            if 'react' in src.lower():
                technologies.append("Framework: React")
            elif 'vue' in src.lower():
                technologies.append("Framework: Vue.js")
            elif 'angular' in src.lower():
                technologies.append("Framework: Angular")
    
    return technologies

def main():
    print("=" * 60)
    print("🔍 HERRAMIENTA DE RECONOCIMIENTO PASIVO")
    print("=" * 60)
    print()
    print("⚠️  SOLO PARA USO EN SISTEMAS PROPIOS O AUTORIZADOS")
    print()
    
    if len(sys.argv) < 2:
        url = input("Ingresa la URL a analizar (ej: https://example.com): ").strip()
    else:
        url = sys.argv[1]
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    print(f"🎯 Analizando: {url}")
    print()
    
    # 1. Robots.txt
    print("1️⃣ Analizando robots.txt...")
    robots_content, robots_url = get_robots_txt(url)
    
    if robots_content:
        print(f"   ✅ robots.txt encontrado: {robots_url}")
        findings = analyze_robots_txt(robots_content)
        
        if findings:
            print(f"   ⚠️  Encontradas {len(findings)} rutas sensibles:")
            for finding in findings:
                print(f"      - {finding['path']} (keyword: {finding['keyword']})")
        else:
            print("   ℹ️  No se encontraron rutas obviamente sensibles")
        
        # Mostrar contenido (primeras líneas)
        print("\n   Contenido de robots.txt (primeras 20 líneas):")
        lines = robots_content.split('\n')[:20]
        for line in lines:
            if line.strip():
                print(f"      {line}")
    else:
        print("   ℹ️  robots.txt no encontrado o no accesible")
    print()
    
    # 2. Headers informativos
    print("2️⃣ Analizando headers HTTP...")
    info_headers, security_headers = get_headers_info(url)
    
    if info_headers:
        print("   ⚠️  Headers informativos encontrados:")
        for header, value in info_headers.items():
            print(f"      {header}: {value}")
    else:
        print("   ✅ No se encontraron headers informativos obvios")
    
    print("\n   Headers de seguridad:")
    for header, value in security_headers.items():
        if value:
            print(f"      ✅ {header}: {value[:50]}...")
        else:
            print(f"      ❌ {header}: NO configurado")
    print()
    
    # 3. Detección de tecnologías
    print("3️⃣ Detectando tecnologías...")
    try:
        response = requests.get(url, timeout=10)
        html_content = response.text
    except:
        html_content = None
    
    technologies = detect_technology(info_headers, html_content)
    
    if technologies:
        print("   Tecnologías detectadas:")
        for tech in technologies:
            print(f"      - {tech}")
    else:
        print("   ℹ️  No se pudieron detectar tecnologías específicas")
    print()
    
    # Resumen
    print("=" * 60)
    print("📊 RESUMEN")
    print("=" * 60)
    
    recommendations = []
    
    if info_headers:
        recommendations.append("❌ Ocultar headers informativos (Server, X-Powered-By)")
    
    if robots_content and findings:
        recommendations.append("⚠️  Revisar robots.txt - puede revelar rutas sensibles")
    
    if not security_headers.get('Strict-Transport-Security'):
        recommendations.append("❌ Agregar Strict-Transport-Security")
    
    if not security_headers.get('Content-Security-Policy'):
        recommendations.append("❌ Agregar Content-Security-Policy")
    
    if not security_headers.get('X-Frame-Options'):
        recommendations.append("❌ Agregar X-Frame-Options")
    
    if recommendations:
        print("HALLAZGOS:")
        for rec in recommendations:
            print(f"  {rec}")
        print()
        print("💡 RECOMENDACIONES:")
        print("  1. Ocultar headers informativos en configuración del servidor")
        print("  2. Revisar robots.txt y no exponer rutas sensibles")
        print("  3. Implementar todos los headers de seguridad")
        print("  4. Usar herramientas como SecurityHeaders.com para verificar")
    else:
        print("✅ No se encontraron problemas obvios")
    
    print()
    print("⚠️  Este análisis es educativo. Solo usa en sistemas propios o autorizados.")

if __name__ == '__main__':
    main()
