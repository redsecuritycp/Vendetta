"""
Verificación de configuración CORS
"""

from typing import Dict, List
import re


def check_cors(responses: List[Dict]) -> List[Dict]:
    """
    Verifica la configuración CORS.
    
    Args:
        responses: Lista de respuestas HTTP obtenidas
        
    Returns:
        Lista de hallazgos
    """
    findings = []
    
    for response in responses:
        url = response.get('url', '')
        headers = response.get('headers', {})
        
        # Verificar headers CORS
        acao = headers.get('Access-Control-Allow-Origin', '')
        acac = headers.get('Access-Control-Allow-Credentials', '')
        acam = headers.get('Access-Control-Allow-Methods', '')
        acah = headers.get('Access-Control-Allow-Headers', '')
        
        if not acao:
            # No hay CORS configurado, no es necesariamente un problema
            continue
        
        # Verificar si Allow-Origin es "*"
        if acao == '*':
            # Si también permite credenciales, es inseguro
            if acac and acac.lower() == 'true':
                findings.append({
                    'type': 'cors_wildcard_with_credentials',
                    'severity': 'High',
                    'title': 'CORS con wildcard y credenciales',
                    'description': f'CORS configurado con Access-Control-Allow-Origin: * y Access-Control-Allow-Credentials: true en {url}',
                    'recommendation': 'No usar wildcard (*) cuando se permiten credenciales. Especificar dominios permitidos explícitamente',
                    'evidence': {
                        'url': url,
                        'access_control_allow_origin': acao,
                        'access_control_allow_credentials': acac
                    }
                })
            else:
                findings.append({
                    'type': 'cors_wildcard',
                    'severity': 'Medium',
                    'title': 'CORS con wildcard (*)',
                    'description': f'CORS configurado con Access-Control-Allow-Origin: * en {url}',
                    'recommendation': 'Considerar especificar dominios permitidos explícitamente en lugar de usar wildcard',
                    'evidence': {
                        'url': url,
                        'access_control_allow_origin': acao
                    }
                })
        
        # Verificar métodos permitidos
        if acam:
            methods = [m.strip().upper() for m in acam.split(',')]
            if 'DELETE' in methods or 'PUT' in methods or 'PATCH' in methods:
                findings.append({
                    'type': 'cors_dangerous_methods',
                    'severity': 'Medium',
                    'title': 'CORS permite métodos peligrosos',
                    'description': f'CORS permite métodos peligrosos (DELETE/PUT/PATCH) en {url}',
                    'recommendation': 'Revisar si es necesario permitir métodos DELETE/PUT/PATCH vía CORS',
                    'evidence': {
                        'url': url,
                        'access_control_allow_methods': acam,
                        'dangerous_methods': [m for m in methods if m in ['DELETE', 'PUT', 'PATCH']]
                    }
                })
        
        # Verificar si hay CORS pero no se especifica origen específico (puede ser información)
        if acao and acao != '*':
            # Verificar si el origen permitido coincide con el origen de la request
            # Esto es solo informativo
            findings.append({
                'type': 'cors_configured',
                'severity': 'Info',
                'title': 'CORS configurado',
                'description': f'CORS está configurado en {url}',
                'recommendation': 'Verificar que los orígenes permitidos sean los correctos',
                'evidence': {
                    'url': url,
                    'access_control_allow_origin': acao,
                    'access_control_allow_methods': acam or 'No especificado',
                    'access_control_allow_headers': acah or 'No especificado',
                    'access_control_allow_credentials': acac or 'No especificado'
                }
            })
    
    return findings

