"""
Verificación de archivos y paths comúnmente expuestos
"""

from typing import Dict, List
from urllib.parse import urlparse, urljoin


def check_file_exposure(responses: List[Dict], scope_url: str) -> List[Dict]:
    """
    Verifica la exposición de archivos y paths comunes.
    
    Args:
        responses: Lista de respuestas HTTP obtenidas
        scope_url: URL del scope
        
    Returns:
        Lista de hallazgos
    """
    findings = []
    
    parsed = urlparse(scope_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    
    # Archivos comunes a verificar
    common_files = [
        {
            'path': '/robots.txt',
            'name': 'robots.txt',
            'severity': 'Info',
            'description': 'robots.txt encontrado',
            'type': 'info'
        },
        {
            'path': '/sitemap.xml',
            'name': 'sitemap.xml',
            'severity': 'Info',
            'description': 'sitemap.xml encontrado',
            'type': 'info'
        },
        {
            'path': '/.well-known/security.txt',
            'name': 'security.txt',
            'severity': 'Info',
            'description': '.well-known/security.txt encontrado',
            'type': 'info'
        },
        {
            'path': '/humans.txt',
            'name': 'humans.txt',
            'severity': 'Info',
            'description': 'humans.txt encontrado',
            'type': 'info'
        },
        {
            'path': '/favicon.ico',
            'name': 'favicon.ico',
            'severity': 'Info',
            'description': 'favicon.ico encontrado',
            'type': 'info'
        },
        {
            'path': '/admin',
            'name': '/admin',
            'severity': 'Low',
            'description': 'Path /admin accesible',
            'type': 'exposed_path'
        },
        {
            'path': '/.git/HEAD',
            'name': '.git/HEAD',
            'severity': 'High',
            'description': 'Repositorio .git expuesto',
            'type': 'sensitive_file'
        },
        {
            'path': '/.env',
            'name': '.env',
            'severity': 'High',
            'description': 'Archivo .env expuesto',
            'type': 'sensitive_file'
        },
        {
            'path': '/backup.zip',
            'name': 'backup.zip',
            'severity': 'Medium',
            'description': 'Archivo backup.zip expuesto',
            'type': 'sensitive_file'
        },
        {
            'path': '/site.zip',
            'name': 'site.zip',
            'severity': 'Medium',
            'description': 'Archivo site.zip expuesto',
            'type': 'sensitive_file'
        },
        {
            'path': '/.git/config',
            'name': '.git/config',
            'severity': 'High',
            'description': 'Archivo .git/config expuesto',
            'type': 'sensitive_file'
        },
        {
            'path': '/.gitignore',
            'name': '.gitignore',
            'severity': 'Low',
            'description': '.gitignore expuesto (puede revelar estructura)',
            'type': 'info_file'
        },
        {
            'path': '/package.json',
            'name': 'package.json',
            'severity': 'Low',
            'description': 'package.json expuesto (puede revelar dependencias)',
            'type': 'info_file'
        },
        {
            'path': '/composer.json',
            'name': 'composer.json',
            'severity': 'Low',
            'description': 'composer.json expuesto (puede revelar dependencias)',
            'type': 'info_file'
        },
        {
            'path': '/.DS_Store',
            'name': '.DS_Store',
            'severity': 'Low',
            'description': '.DS_Store expuesto (archivo del sistema)',
            'type': 'system_file'
        }
    ]
    
    # Verificar archivos encontrados en las respuestas
    found_urls = {response.get('url', '') for response in responses}
    
    for file_info in common_files:
        file_url = urljoin(base_url, file_info['path'])
        
        # Verificar si el archivo fue encontrado en las respuestas
        found = False
        matching_response = None
        
        for response in responses:
            response_url = response.get('url', '').rstrip('/')
            file_url_normalized = file_url.rstrip('/')
            
            if response_url == file_url_normalized or response_url.startswith(file_url_normalized + '/'):
                found = True
                matching_response = response
                break
        
        if found and matching_response:
            status_code = matching_response.get('status_code')
            
            # Solo reportar si es accesible (200, 30x, o 403 puede indicar existencia)
            if status_code in [200, 301, 302, 303, 307, 308, 403]:
                if file_info['type'] == 'sensitive_file' and status_code == 200:
                    findings.append({
                        'type': file_info['type'],
                        'severity': file_info['severity'],
                        'title': f"Archivo sensible expuesto: {file_info['name']}",
                        'description': f"{file_info['description']} en {file_url} (Status: {status_code})",
                        'recommendation': f"Remover o restringir acceso a {file_info['name']}",
                        'evidence': {
                            'url': file_url,
                            'status_code': status_code,
                            'content_type': matching_response.get('content_type', ''),
                            'size': matching_response.get('size', 0)
                        }
                    })
                elif file_info['type'] in ['exposed_path', 'info_file', 'system_file'] and status_code == 200:
                    findings.append({
                        'type': file_info['type'],
                        'severity': file_info['severity'],
                        'title': f"Path expuesto: {file_info['name']}",
                        'description': f"{file_info['description']} en {file_url} (Status: {status_code})",
                        'recommendation': f"Evaluar si {file_info['name']} debe ser accesible públicamente",
                        'evidence': {
                            'url': file_url,
                            'status_code': status_code,
                            'content_type': matching_response.get('content_type', '')
                        }
                    })
                elif file_info['type'] == 'info' and status_code == 200:
                    # Solo información, no un hallazgo de seguridad
                    findings.append({
                        'type': 'info',
                        'severity': 'Info',
                        'title': f"Archivo encontrado: {file_info['name']}",
                        'description': f"{file_info['description']} en {file_url}",
                        'recommendation': 'N/A',
                        'evidence': {
                            'url': file_url,
                            'status_code': status_code
                        }
                    })
    
    return findings

