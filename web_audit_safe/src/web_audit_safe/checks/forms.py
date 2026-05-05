"""
Verificación de formularios y protección CSRF
"""

import re
from typing import Dict, List
from bs4 import BeautifulSoup


def check_forms(responses: List[Dict]) -> List[Dict]:
    """
    Verifica formularios y protección CSRF.
    
    Args:
        responses: Lista de respuestas HTTP obtenidas
        
    Returns:
        Lista de hallazgos
    """
    findings = []
    
    for response in responses:
        url = response.get('url', '')
        content = response.get('content', '')
        
        if not content:
            continue
        
        try:
            soup = BeautifulSoup(content, 'html.parser')
            forms = soup.find_all('form')
            
            if not forms:
                continue
            
            for form in forms:
                form_method = form.get('method', 'GET').upper()
                form_action = form.get('action', '')
                
                # Verificar método GET para datos sensibles
                if form_method == 'GET':
                    # Buscar campos sensibles
                    has_password = form.find('input', {'type': 'password'}) is not None
                    has_email = form.find('input', {'type': 'email'}) is not None
                    has_hidden_sensitive = False
                    
                    # Buscar inputs hidden que puedan contener datos sensibles
                    hidden_inputs = form.find_all('input', {'type': 'hidden'})
                    for hidden in hidden_inputs:
                        name = hidden.get('name', '').lower()
                        if any(keyword in name for keyword in ['token', 'secret', 'key', 'password']):
                            has_hidden_sensitive = True
                    
                    if has_password or (has_email and has_hidden_sensitive):
                        findings.append({
                            'type': 'form_get_sensitive',
                            'severity': 'High',
                            'title': 'Formulario con método GET para datos sensibles',
                            'description': f'Formulario en {url} usa GET para datos sensibles (passwords, emails)',
                            'recommendation': 'Cambiar método del formulario a POST para datos sensibles',
                            'evidence': {
                                'url': url,
                                'form_method': form_method,
                                'form_action': form_action,
                                'has_password': has_password
                            }
                        })
                
                # Verificar protección CSRF
                csrf_token_found = False
                
                # Buscar tokens CSRF en inputs hidden
                hidden_inputs = form.find_all('input', {'type': 'hidden'})
                for hidden in hidden_inputs:
                    name = hidden.get('name', '').lower()
                    if 'csrf' in name or 'token' in name or '_token' in name:
                        csrf_token_found = True
                        break
                
                # Buscar en meta tags
                if not csrf_token_found:
                    meta_tags = soup.find_all('meta', {'name': re.compile(r'csrf|token', re.I)})
                    if meta_tags:
                        csrf_token_found = True
                
                # Si no se encuentra token CSRF y el formulario es POST/PUT/DELETE
                if form_method in ['POST', 'PUT', 'DELETE'] and not csrf_token_found:
                    # Verificar si es un formulario de login/admin
                    url_lower = url.lower()
                    is_sensitive_form = (
                        '/login' in url_lower or
                        '/admin' in url_lower or
                        '/auth' in url_lower or
                        '/signin' in url_lower or
                        '/register' in url_lower or
                        form.find('input', {'type': 'password'}) is not None
                    )
                    
                    if is_sensitive_form:
                        findings.append({
                            'type': 'missing_csrf_token',
                            'severity': 'High',
                            'title': 'Formulario sensible sin token CSRF detectado',
                            'description': f'Formulario en {url} no parece tener protección CSRF',
                            'recommendation': 'Implementar tokens CSRF en todos los formularios que modifiquen estado',
                            'evidence': {
                                'url': url,
                                'form_method': form_method,
                                'form_action': form_action,
                                'is_sensitive': True
                            }
                        })
                    else:
                        findings.append({
                            'type': 'missing_csrf_token',
                            'severity': 'Medium',
                            'title': 'Formulario sin token CSRF detectado',
                            'description': f'Formulario en {url} no parece tener protección CSRF',
                            'recommendation': 'Considerar implementar tokens CSRF para protección adicional',
                            'evidence': {
                                'url': url,
                                'form_method': form_method,
                                'form_action': form_action
                            }
                        })
                
                # Verificar autocomplete en campos de contraseña
                password_inputs = form.find_all('input', {'type': 'password'})
                for pwd_input in password_inputs:
                    autocomplete = pwd_input.get('autocomplete', '')
                    if autocomplete and 'off' not in autocomplete.lower() and 'new-password' not in autocomplete.lower():
                        # No es crítico, pero puede ser información útil
                        findings.append({
                            'type': 'password_autocomplete',
                            'severity': 'Info',
                            'title': 'Campo de contraseña con autocomplete habilitado',
                            'description': f'Campo de contraseña en formulario de {url} tiene autocomplete',
                            'recommendation': 'Considerar deshabilitar autocomplete en campos de contraseña',
                            'evidence': {
                                'url': url,
                                'autocomplete_value': autocomplete
                            }
                        })
        
        except Exception as e:
            # Error al parsear HTML, continuar
            continue
    
    return findings

