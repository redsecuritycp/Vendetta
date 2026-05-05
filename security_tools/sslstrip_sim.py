"""
Simulador de SSLStrip - Detecta vulnerabilidades relacionadas con falta de HSTS

⚠️ SOLO PARA USO EDUCATIVO Y EN SISTEMAS PROPIOS O AUTORIZADOS

Este script simula el comportamiento de un atacante SSLStrip detectando:
- Enlaces HTTP en páginas HTTPS (mixed content)
- Redirecciones inseguras
- Ausencia de HSTS
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import sys

def check_hsts(url):
    """Verifica si el sitio tiene HSTS configurado"""
    try:
        response = requests.head(url, allow_redirects=True, timeout=10)
        hsts = response.headers.get('Strict-Transport-Security', '')
        return hsts != '', hsts
    except Exception as e:
        return False, f"Error: {str(e)}"

def find_http_links(url):
    """Encuentra enlaces HTTP en una página HTTPS"""
    try:
        response = requests.get(url, timeout=10, verify=True)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        http_links = []
        mixed_content = []
        
        # Buscar todos los enlaces
        for tag in soup.find_all(['a', 'link', 'script', 'img', 'iframe'], 
                                src=True, href=True):
            attr = tag.get('href') or tag.get('src')
            if not attr:
                continue
            
            # Resolver URL completa
            full_url = urljoin(url, attr)
            parsed = urlparse(full_url)
            
            # Si es HTTP en una página HTTPS
            if parsed.scheme == 'http':
                if tag.name == 'a':
                    http_links.append(full_url)
                else:
                    mixed_content.append({
                        'tag': tag.name,
                        'url': full_url,
                        'attribute': 'href' if tag.get('href') else 'src'
                    })
        
        return http_links, mixed_content
    
    except Exception as e:
        print(f"❌ Error al analizar {url}: {str(e)}")
        return [], []

def check_redirects(url):
    """Verifica si hay redirecciones HTTP"""
    try:
        # Intentar HTTP primero
        http_url = url.replace('https://', 'http://')
        response = requests.get(http_url, allow_redirects=False, timeout=10)
        
        if response.status_code in [301, 302, 303, 307, 308]:
            location = response.headers.get('Location', '')
            if location.startswith('http://'):
                return True, location
            elif location.startswith('https://'):
                return False, location
        
        # Si responde 200 en HTTP, es vulnerable
        if response.status_code == 200:
            return True, "Sitio accesible vía HTTP"
        
        return False, None
    
    except Exception:
        return False, None

def main():
    print("=" * 60)
    print("🔍 SIMULADOR SSLSTRIP - Análisis de Vulnerabilidades HSTS")
    print("=" * 60)
    print()
    
    if len(sys.argv) < 2:
        url = input("Ingresa la URL a analizar (ej: https://example.com): ").strip()
    else:
        url = sys.argv[1]
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    print(f"🎯 Analizando: {url}")
    print()
    
    # 1. Verificar HSTS
    print("1️⃣ Verificando HSTS...")
    has_hsts, hsts_value = check_hsts(url)
    if has_hsts:
        print(f"   ✅ HSTS configurado: {hsts_value}")
    else:
        print(f"   ❌ HSTS NO configurado - VULNERABLE a SSLStrip")
    print()
    
    # 2. Buscar enlaces HTTP
    print("2️⃣ Buscando enlaces HTTP en la página...")
    http_links, mixed_content = find_http_links(url)
    
    if http_links:
        print(f"   ⚠️  Encontrados {len(http_links)} enlaces HTTP:")
        for link in http_links[:10]:  # Mostrar primeros 10
            print(f"      - {link}")
        if len(http_links) > 10:
            print(f"      ... y {len(http_links) - 10} más")
    else:
        print("   ✅ No se encontraron enlaces HTTP")
    
    if mixed_content:
        print(f"   ⚠️  Encontrado Mixed Content ({len(mixed_content)} elementos):")
        for item in mixed_content[:5]:
            print(f"      - <{item['tag']}> {item['url']}")
    print()
    
    # 3. Verificar redirecciones
    print("3️⃣ Verificando redirecciones HTTP...")
    vulnerable_redirect, redirect_info = check_redirects(url)
    if vulnerable_redirect:
        print(f"   ⚠️  Redirección HTTP detectada: {redirect_info}")
        print("   ❌ VULNERABLE - Un atacante puede interceptar")
    else:
        print("   ✅ No se detectaron redirecciones HTTP inseguras")
    print()
    
    # Resumen
    print("=" * 60)
    print("📊 RESUMEN")
    print("=" * 60)
    
    vulnerabilities = []
    if not has_hsts:
        vulnerabilities.append("❌ Falta HSTS")
    if http_links:
        vulnerabilities.append(f"⚠️  {len(http_links)} enlaces HTTP encontrados")
    if mixed_content:
        vulnerabilities.append(f"⚠️  {len(mixed_content)} elementos mixed content")
    if vulnerable_redirect:
        vulnerabilities.append("❌ Redirecciones HTTP activas")
    
    if vulnerabilities:
        print("VULNERABILIDADES ENCONTRADAS:")
        for vuln in vulnerabilities:
            print(f"  {vuln}")
        print()
        print("💡 RECOMENDACIONES:")
        print("  1. Agregar header Strict-Transport-Security")
        print("  2. Cambiar todos los enlaces HTTP a HTTPS")
        print("  3. Configurar redirección forzada HTTP → HTTPS")
        print("  4. Eliminar mixed content")
    else:
        print("✅ No se encontraron vulnerabilidades obvias")
    
    print()
    print("⚠️  Este análisis es educativo. Solo usa en sistemas propios o autorizados.")

if __name__ == '__main__':
    main()
