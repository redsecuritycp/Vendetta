"""
Verificación de cookies y sus flags de seguridad
"""

from typing import Dict, List
import re


def check_cookies(responses: List[Dict]) -> List[Dict]:
    """
    Verifica las cookies y sus flags de seguridad.
    
    Args:
        responses: Lista de respuestas HTTP obtenidas
        
    Returns:
        Lista de hallazgos
    """
    findings = []
    
    for response in responses:
        url = response.get('url', '')
        headers = response.get('headers', {})
        
        # Obtener todas las cookies (puede haber múltiples Set-Cookie)
        set_cookie_headers = []
        for key, value in headers.items():
            if key.lower() == 'set-cookie':
                set_cookie_headers.append(value)
            # Algunos servidores envían múltiples headers con el mismo nombre
            # requests los combina en una lista
            elif isinstance(value, list):
                for item in value:
                    if key.lower() == 'set-cookie':
                        set_cookie_headers.append(item)
        
        if not set_cookie_headers:
            continue
        
        # Analizar cada cookie
        for cookie_header in set_cookie_headers:
            cookie_name = extract_cookie_name(cookie_header)
            cookie_attrs = parse_cookie_attributes(cookie_header)
            
            # Verificar flags de seguridad
            is_secure = cookie_attrs.get('Secure', False)
            is_httponly = cookie_attrs.get('HttpOnly', False)
            samesite = cookie_attrs.get('SameSite', '').upper()
            
            # Detectar cookies de sesión (heurística)
            is_session_cookie = (
                'session' in cookie_name.lower() or
                'sessid' in cookie_name.lower() or
                'jsessionid' in cookie_name.lower() or
                'phpsessid' in cookie_name.lower() or
                'asp.net_sessionid' in cookie_name.lower()
            )
            
            # Severidad basada en tipo de cookie
            base_severity = 'High' if is_session_cookie else 'Medium'
            
            # Verificar Secure flag
            if not is_secure:
                findings.append({
                    'type': 'cookie_without_secure',
                    'severity': base_severity,
                    'title': f'Cookie sin flag Secure: {cookie_name}',
                    'description': f'La cookie "{cookie_name}" en {url} no tiene el flag Secure',
                    'recommendation': 'Agregar flag Secure a todas las cookies, especialmente en sitios HTTPS',
                    'evidence': {
                        'url': url,
                        'cookie_name': cookie_name,
                        'cookie_header': cookie_header[:200]  # Limitar tamaño
                    }
                })
            
            # Verificar HttpOnly flag
            if not is_httponly:
                findings.append({
                    'type': 'cookie_without_httponly',
                    'severity': base_severity,
                    'title': f'Cookie sin flag HttpOnly: {cookie_name}',
                    'description': f'La cookie "{cookie_name}" en {url} no tiene el flag HttpOnly',
                    'recommendation': 'Agregar flag HttpOnly para prevenir acceso vía JavaScript (protección XSS)',
                    'evidence': {
                        'url': url,
                        'cookie_name': cookie_name,
                        'cookie_header': cookie_header[:200]
                    }
                })
            
            # Verificar SameSite
            if not samesite or samesite not in ['STRICT', 'LAX', 'NONE']:
                if not samesite:
                    findings.append({
                        'type': 'cookie_without_samesite',
                        'severity': 'Medium' if is_session_cookie else 'Low',
                        'title': f'Cookie sin SameSite: {cookie_name}',
                        'description': f'La cookie "{cookie_name}" en {url} no tiene el atributo SameSite',
                        'recommendation': 'Agregar SameSite=Strict o SameSite=Lax para protección CSRF',
                        'evidence': {
                            'url': url,
                            'cookie_name': cookie_name,
                            'cookie_header': cookie_header[:200]
                        }
                    })
                elif samesite == 'NONE' and not is_secure:
                    findings.append({
                        'type': 'cookie_samesite_none_without_secure',
                        'severity': 'High',
                        'title': f'Cookie con SameSite=None sin Secure: {cookie_name}',
                        'description': f'La cookie "{cookie_name}" en {url} tiene SameSite=None pero no Secure (inválido)',
                        'recommendation': 'SameSite=None requiere Secure flag. Usar SameSite=Strict o Lax si es posible',
                        'evidence': {
                            'url': url,
                            'cookie_name': cookie_name,
                            'cookie_header': cookie_header[:200]
                        }
                    })
            
            # Cookie de sesión sin protección adecuada
            if is_session_cookie and (not is_secure or not is_httponly):
                findings.append({
                    'type': 'insecure_session_cookie',
                    'severity': 'High',
                    'title': f'Cookie de sesión insegura: {cookie_name}',
                    'description': f'La cookie de sesión "{cookie_name}" en {url} no tiene protección adecuada',
                    'recommendation': 'Las cookies de sesión deben tener Secure y HttpOnly siempre',
                    'evidence': {
                        'url': url,
                        'cookie_name': cookie_name,
                        'has_secure': is_secure,
                        'has_httponly': is_httponly,
                        'samesite': samesite or 'No configurado'
                    }
                })
    
    return findings


def extract_cookie_name(cookie_header: str) -> str:
    """
    Extrae el nombre de la cookie del header Set-Cookie.
    
    Args:
        cookie_header: Valor del header Set-Cookie
        
    Returns:
        Nombre de la cookie
    """
    if '=' in cookie_header:
        return cookie_header.split('=')[0].strip()
    return 'unknown'


def parse_cookie_attributes(cookie_header: str) -> Dict[str, any]:
    """
    Parsea los atributos de una cookie.
    
    Args:
        cookie_header: Valor del header Set-Cookie
        
    Returns:
        Diccionario con atributos parseados
    """
    attrs = {}
    
    # Buscar flags booleanos
    if 'Secure' in cookie_header or '; Secure' in cookie_header:
        attrs['Secure'] = True
    
    if 'HttpOnly' in cookie_header or '; HttpOnly' in cookie_header:
        attrs['HttpOnly'] = True
    
    # Buscar SameSite
    samesite_match = re.search(r'SameSite=([^;,\s]+)', cookie_header, re.IGNORECASE)
    if samesite_match:
        attrs['SameSite'] = samesite_match.group(1)
    
    # Buscar Domain
    domain_match = re.search(r'Domain=([^;,\s]+)', cookie_header, re.IGNORECASE)
    if domain_match:
        attrs['Domain'] = domain_match.group(1)
    
    # Buscar Path
    path_match = re.search(r'Path=([^;,\s]+)', cookie_header, re.IGNORECASE)
    if path_match:
        attrs['Path'] = path_match.group(1)
    
    # Buscar Max-Age
    maxage_match = re.search(r'Max-Age=(\d+)', cookie_header, re.IGNORECASE)
    if maxage_match:
        attrs['Max-Age'] = int(maxage_match.group(1))
    
    # Buscar Expires
    expires_match = re.search(r'Expires=([^;]+)', cookie_header, re.IGNORECASE)
    if expires_match:
        attrs['Expires'] = expires_match.group(1).strip()
    
    return attrs

