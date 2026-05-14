"""
Tester básico de XSS - Detecta vulnerabilidades de Cross-Site Scripting

⚠️ SOLO PARA USO EDUCATIVO Y EN SISTEMAS PROPIOS O AUTORIZADOS

Este script prueba vulnerabilidades XSS básicas:
- Reflected XSS (reflejado en la respuesta)
- Stored XSS (básico)
- Payloads comunes
"""

import requests
from bs4 import BeautifulSoup
import sys
import urllib.parse

# Payloads comunes de XSS (solo para pruebas educativas)
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<body onload=alert('XSS')>",
    "<iframe src=javascript:alert('XSS')>",
    "'\"><script>alert('XSS')</script>",
    "<input onfocus=alert('XSS') autofocus>",
    "<select onfocus=alert('XSS') autofocus>",
    "<textarea onfocus=alert('XSS') autofocus>",
]

def check_csp(url):
    """Verifica si el sitio tiene CSP configurado"""
    try:
        response = requests.get(url, timeout=10)
        csp = response.headers.get('Content-Security-Policy', '')
        return csp != '', csp
    except Exception:
        return False, ''

def test_reflected_xss(url, parameter, payload):
    """Prueba XSS reflejado en un parámetro"""
    try:
        # Probar GET
        params = {parameter: payload}
        response = requests.get(url, params=params, timeout=10)
        
        # Verificar si el payload aparece sin escapar
        if payload in response.text:
            # Verificar si está en contexto peligroso
            soup = BeautifulSoup(response.text, 'html.parser')
            text_content = soup.get_text()
            
            # Si el payload está en el HTML pero no solo en texto, es vulnerable
            if payload in response.text and payload not in text_content:
                return True, "Payload reflejado en HTML sin escapar"
            elif payload in response.text:
                return "maybe", "Payload reflejado pero puede estar escapado"
        
        return False, None
    
    except Exception as e:
        return False, f"Error: {str(e)}"

def test_form_xss(url, form_data, payload):
    """Prueba XSS en formularios POST"""
    try:
        # Encontrar formularios en la página
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        forms = soup.find_all('form')
        if not forms:
            return False, "No se encontraron formularios"
        
        results = []
        for form in forms:
            action = form.get('action', '')
            method = form.get('method', 'GET').upper()
            form_url = urllib.parse.urljoin(url, action) if action else url
            
            # Preparar datos del formulario
            data = {}
            for input_tag in form.find_all(['input', 'textarea']):
                name = input_tag.get('name')
                if name:
                    # Inyectar payload en el primer campo encontrado
                    if not data:
                        data[name] = payload
                    else:
                        data[name] = input_tag.get('value', '')
            
            if method == 'POST':
                test_response = requests.post(form_url, data=data, timeout=10)
            else:
                test_response = requests.get(form_url, params=data, timeout=10)
            
            if payload in test_response.text:
                results.append({
                    'form': form_url,
                    'method': method,
                    'vulnerable': True
                })
        
        return len(results) > 0, results
    
    except Exception as e:
        return False, f"Error: {str(e)}"

def main():
    print("=" * 60)
    print("🔍 TESTER DE XSS - Análisis de Vulnerabilidades")
    print("=" * 60)
    print()
    print("⚠️  SOLO PARA USO EN SISTEMAS PROPIOS O AUTORIZADOS")
    print()
    
    if len(sys.argv) < 2:
        url = input("Ingresa la URL a probar (ej: https://example.com/buscar?q=test): ").strip()
    else:
        url = sys.argv[1]
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    print(f"🎯 Analizando: {url}")
    print()
    
    # Verificar CSP
    print("1️⃣ Verificando Content-Security-Policy...")
    has_csp, csp_value = check_csp(url)
    if has_csp:
        print(f"   ✅ CSP configurado: {csp_value[:50]}...")
    else:
        print("   ❌ CSP NO configurado - Más vulnerable a XSS")
    print()
    
    # Probar XSS reflejado en parámetros GET
    print("2️⃣ Probando XSS reflejado en parámetros...")
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    
    if params:
        print(f"   Encontrados {len(params)} parámetros")
        vulnerable_params = []
        
        for param_name in params.keys():
            print(f"   Probando parámetro: {param_name}")
            for payload in XSS_PAYLOADS[:3]:  # Probar primeros 3 payloads
                result, info = test_reflected_xss(
                    f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                    param_name,
                    payload
                )
                
                if result == True:
                    print(f"      ⚠️  VULNERABLE con payload: {payload[:30]}...")
                    vulnerable_params.append({
                        'param': param_name,
                        'payload': payload,
                        'info': info
                    })
                    break  # Si es vulnerable, no probar más payloads
                elif result == "maybe":
                    print(f"      ⚠️  Posiblemente vulnerable: {payload[:30]}...")
        
        if vulnerable_params:
            print(f"\n   ❌ Encontradas {len(vulnerable_params)} vulnerabilidades XSS")
        else:
            print("\n   ✅ No se encontraron vulnerabilidades XSS reflejadas obvias")
    else:
        print("   ℹ️  No se encontraron parámetros en la URL")
    print()
    
    # Probar formularios
    print("3️⃣ Probando formularios...")
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    result, info = test_form_xss(base_url, {}, XSS_PAYLOADS[0])
    
    if result and isinstance(info, list):
        print(f"   ⚠️  Encontrados {len(info)} formularios potencialmente vulnerables")
    elif result:
        print(f"   ⚠️  Posible vulnerabilidad en formularios")
    else:
        print("   ✅ No se encontraron vulnerabilidades obvias en formularios")
    print()
    
    # Resumen
    print("=" * 60)
    print("📊 RESUMEN")
    print("=" * 60)
    
    recommendations = []
    if not has_csp:
        recommendations.append("❌ Agregar Content-Security-Policy header")
    
    if params and vulnerable_params:
        recommendations.append("❌ Sanitizar/escapar inputs de usuario")
        recommendations.append("❌ Validar y filtrar parámetros GET/POST")
    
    if recommendations:
        print("VULNERABILIDADES ENCONTRADAS:")
        for rec in recommendations:
            print(f"  {rec}")
        print()
        print("💡 RECOMENDACIONES:")
        print("  1. Implementar Content-Security-Policy (CSP)")
        print("  2. Escapar/sanitizar TODOS los inputs de usuario")
        print("  3. Usar librerías de sanitización (ej: DOMPurify para JS)")
        print("  4. Validar y filtrar parámetros en servidor")
        print("  5. Usar prepared statements para evitar SQL injection también")
    else:
        print("✅ No se encontraron vulnerabilidades XSS obvias")
        print("   (Nota: Este es un test básico. Pruebas más profundas requieren herramientas especializadas)")
    
    print()
    print("⚠️  Este análisis es educativo. Solo usa en sistemas propios o autorizados.")

if __name__ == '__main__':
    main()
