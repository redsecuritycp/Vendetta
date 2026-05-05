"""
Verificación de HTTP Security Headers
"""

from typing import Dict, List


def check_security_headers(responses: List[Dict]) -> List[Dict]:
    """
    Verifica la presencia y configuración de headers de seguridad.
    
    Args:
        responses: Lista de respuestas HTTP obtenidas
        
    Returns:
        Lista de hallazgos
    """
    findings = []
    
    # Headers a verificar
    security_headers = {
        'Strict-Transport-Security': {
            'name': 'HSTS',
            'severity': 'High',
            'description': 'Strict-Transport-Security (HSTS) no está presente',
            'recommendation': 'Agregar header Strict-Transport-Security con max-age>=31536000 e includeSubDomains'
        },
        'Content-Security-Policy': {
            'name': 'CSP',
            'severity': 'Medium',
            'description': 'Content-Security-Policy (CSP) no está presente',
            'recommendation': 'Implementar CSP para prevenir XSS y otros ataques de inyección'
        },
        'X-Frame-Options': {
            'name': 'X-Frame-Options',
            'severity': 'Medium',
            'description': 'X-Frame-Options no está presente',
            'recommendation': 'Agregar X-Frame-Options: DENY o SAMEORIGIN para prevenir clickjacking'
        },
        'X-Content-Type-Options': {
            'name': 'X-Content-Type-Options',
            'severity': 'Low',
            'description': 'X-Content-Type-Options no está presente',
            'recommendation': 'Agregar X-Content-Type-Options: nosniff para prevenir MIME sniffing'
        },
        'Referrer-Policy': {
            'name': 'Referrer-Policy',
            'severity': 'Low',
            'description': 'Referrer-Policy no está presente',
            'recommendation': 'Agregar Referrer-Policy para controlar información de referrer enviada'
        },
        'Permissions-Policy': {
            'name': 'Permissions-Policy',
            'severity': 'Low',
            'description': 'Permissions-Policy no está presente',
            'recommendation': 'Agregar Permissions-Policy para controlar características del navegador'
        },
        'Cross-Origin-Opener-Policy': {
            'name': 'COOP',
            'severity': 'Low',
            'description': 'Cross-Origin-Opener-Policy no está presente',
            'recommendation': 'Considerar agregar COOP para aislar el contexto de navegación'
        },
        'Cross-Origin-Embedder-Policy': {
            'name': 'COEP',
            'severity': 'Info',
            'description': 'Cross-Origin-Embedder-Policy no está presente',
            'recommendation': 'Considerar COEP si se requiere aislamiento estricto de recursos'
        },
        'Cross-Origin-Resource-Policy': {
            'name': 'CORP',
            'severity': 'Info',
            'description': 'Cross-Origin-Resource-Policy no está presente',
            'recommendation': 'Considerar CORP para controlar cómo otros sitios pueden cargar recursos'
        }
    }
    
    # Verificar en home y primeras 5 páginas
    pages_to_check = responses[:6] if len(responses) > 6 else responses
    
    for response in pages_to_check:
        url = response.get('url', '')
        headers = response.get('headers', {})
        
        # Verificar cada header
        for header_name, config in security_headers.items():
            header_value = headers.get(header_name, '')
            
            if not header_value:
                findings.append({
                    'type': 'missing_security_header',
                    'severity': config['severity'],
                    'title': f"Falta header de seguridad: {config['name']}",
                    'description': f"{config['description']} en {url}",
                    'recommendation': config['recommendation'],
                    'evidence': {
                        'url': url,
                        'missing_header': header_name,
                        'all_headers': list(headers.keys())
                    }
                })
            else:
                # Validar configuración específica
                if header_name == 'Strict-Transport-Security':
                    if 'max-age' not in header_value.lower():
                        findings.append({
                            'type': 'misconfigured_hsts',
                            'severity': 'Medium',
                            'title': 'HSTS sin max-age configurado',
                            'description': f'HSTS presente pero sin max-age en {url}',
                            'recommendation': 'Asegurar que HSTS incluya max-age>=31536000',
                            'evidence': {
                                'url': url,
                                'header_value': header_value
                            }
                        })
                
                elif header_name == 'X-Frame-Options':
                    value_upper = header_value.upper()
                    if value_upper not in ['DENY', 'SAMEORIGIN']:
                        findings.append({
                            'type': 'misconfigured_xfo',
                            'severity': 'Low',
                            'title': 'X-Frame-Options con valor no recomendado',
                            'description': f'X-Frame-Options tiene valor no estándar en {url}',
                            'recommendation': 'Usar DENY o SAMEORIGIN',
                            'evidence': {
                                'url': url,
                                'header_value': header_value
                            }
                        })
        
        # Verificar Cache-Control en páginas sensibles
        url_lower = url.lower()
        if '/login' in url_lower or '/admin' in url_lower or '/auth' in url_lower:
            cache_control = headers.get('Cache-Control', '')
            if not cache_control or 'no-store' not in cache_control.lower():
                findings.append({
                    'type': 'missing_cache_control',
                    'severity': 'Medium',
                    'title': 'Página sensible sin Cache-Control apropiado',
                    'description': f'Página sensible ({url}) sin Cache-Control: no-store',
                    'recommendation': 'Agregar Cache-Control: no-store, no-cache, must-revalidate en páginas sensibles',
                    'evidence': {
                        'url': url,
                        'cache_control': cache_control or 'No presente'
                    }
                })
        
        # Verificar CSP en frame-ancestors (alternativa a X-Frame-Options)
        csp = headers.get('Content-Security-Policy', '')
        if csp and 'frame-ancestors' not in csp.lower():
            # No es un hallazgo crítico si X-Frame-Options está presente
            xfo = headers.get('X-Frame-Options', '')
            if not xfo:
                findings.append({
                    'type': 'csp_no_frame_ancestors',
                    'severity': 'Info',
                    'title': 'CSP sin frame-ancestors',
                    'description': f'CSP presente pero sin frame-ancestors en {url}',
                    'recommendation': 'Agregar frame-ancestors a CSP o mantener X-Frame-Options',
                    'evidence': {
                        'url': url,
                        'csp_value': csp
                    }
                })
    
    return findings

