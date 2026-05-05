"""
Verificación de TLS/SSL y certificados
"""

import ssl
import socket
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urlparse


def check_tls(scope_url: str) -> List[Dict]:
    """
    Verifica la configuración TLS/SSL del sitio.
    
    Args:
        scope_url: URL del sitio a verificar
        
    Returns:
        Lista de hallazgos
    """
    findings = []
    
    parsed = urlparse(scope_url)
    
    # Solo verificar si es HTTPS
    if parsed.scheme != 'https':
        findings.append({
            'type': 'no_https',
            'severity': 'High',
            'title': 'Sitio no utiliza HTTPS',
            'description': f'El sitio {scope_url} no utiliza HTTPS',
            'recommendation': 'Implementar HTTPS para proteger datos en tránsito',
            'evidence': {
                'url': scope_url,
                'scheme': parsed.scheme
            }
        })
        return findings
    
    hostname = parsed.netloc.split(':')[0]
    port = parsed.port or 443
    
    try:
        # Crear contexto SSL
        context = ssl.create_default_context()
        
        # Conectar y obtener información del certificado
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Versión TLS
                tls_version = ssock.version()
                
                # Información del certificado
                cert = ssock.getpeercert()
                
                # Información del certificado binario
                cert_binary = ssock.getpeercert(binary_form=True)
                
                # Parsear certificado con cryptography si está disponible
                issuer = {}
                subject = {}
                san_list = []
                not_before = None
                not_after = None
                days_until_expiry = None
                
                try:
                    from cryptography import x509
                    from cryptography.hazmat.backends import default_backend
                    
                    cert_obj = x509.load_der_x509_certificate(cert_binary, default_backend())
                    
                    # Información del certificado
                    issuer = dict(x509_name_to_dict(cert_obj.issuer))
                    subject = dict(x509_name_to_dict(cert_obj.subject))
                    
                    # SAN (Subject Alternative Names)
                    try:
                        ext = cert_obj.extensions.get_extension_for_oid(
                            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                        )
                        san_list = ext.value.get_values_for_type(x509.DNSName)
                    except x509.ExtensionNotFound:
                        pass
                    
                    # Fechas
                    not_before = cert_obj.not_valid_before
                    not_after = cert_obj.not_valid_after
                    now = datetime.now(not_after.tzinfo) if not_after.tzinfo else datetime.now()
                    days_until_expiry = (not_after - now).days
                    
                except ImportError:
                    # Si cryptography no está disponible, usar información básica del certificado
                    if cert:
                        issuer = cert.get('issuer', [])
                        subject = cert.get('subject', [])
                        # Convertir a formato similar
                        if isinstance(issuer, tuple):
                            issuer = dict(issuer)
                        if isinstance(subject, tuple):
                            subject = dict(subject)
                        
                        # Intentar obtener fechas del certificado básico
                        if 'notBefore' in cert:
                            try:
                                not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                            except:
                                pass
                        if 'notAfter' in cert:
                            try:
                                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                                if not_after:
                                    now = datetime.now()
                                    days_until_expiry = (not_after - now).days
                            except:
                                pass
                except Exception as e:
                    # Si hay error al parsear, usar información básica
                    if cert:
                        issuer = cert.get('issuer', {})
                        subject = cert.get('subject', {})
                
                # Verificar versión TLS
                if tls_version in ['TLSv1', 'TLSv1.1']:
                    findings.append({
                        'type': 'weak_tls_version',
                        'severity': 'High',
                        'title': f'Versión TLS débil: {tls_version}',
                        'description': f'El sitio utiliza {tls_version} que es inseguro',
                        'recommendation': 'Actualizar a TLS 1.2 o superior',
                        'evidence': {
                            'url': scope_url,
                            'tls_version': tls_version
                        }
                    })
                elif tls_version == 'TLSv1.2':
                    findings.append({
                        'type': 'tls_1_2_only',
                        'severity': 'Info',
                        'title': 'Solo TLS 1.2 soportado',
                        'description': f'El sitio utiliza {tls_version}. Se recomienda TLS 1.3',
                        'recommendation': 'Considerar habilitar TLS 1.3 para mejor seguridad',
                        'evidence': {
                            'url': scope_url,
                            'tls_version': tls_version
                        }
                    })
                
                # Verificar expiración (solo si tenemos la información)
                if days_until_expiry is not None and days_until_expiry < 0:
                    findings.append({
                        'type': 'cert_expired',
                        'severity': 'High',
                        'title': 'Certificado expirado',
                        'description': f'El certificado expiró hace {abs(days_until_expiry)} días',
                        'recommendation': 'Renovar el certificado inmediatamente',
                        'evidence': {
                            'url': scope_url,
                            'expiry_date': not_after.isoformat(),
                            'days_until_expiry': days_until_expiry
                        }
                    })
                elif days_until_expiry is not None and days_until_expiry < 30:
                    findings.append({
                        'type': 'cert_expiring_soon',
                        'severity': 'Medium',
                        'title': 'Certificado próximo a expirar',
                        'description': f'El certificado expira en {days_until_expiry} días',
                        'recommendation': 'Renovar el certificado antes de que expire',
                        'evidence': {
                            'url': scope_url,
                            'expiry_date': not_after.isoformat(),
                            'days_until_expiry': days_until_expiry
                        }
                    })
                
                # Información del certificado (siempre reportar)
                evidence = {
                    'url': scope_url,
                    'tls_version': tls_version,
                    'issuer': issuer,
                    'subject': subject,
                    'san': san_list
                }
                
                if not_before:
                    evidence['valid_from'] = not_before.isoformat() if hasattr(not_before, 'isoformat') else str(not_before)
                if not_after:
                    evidence['valid_until'] = not_after.isoformat() if hasattr(not_after, 'isoformat') else str(not_after)
                if days_until_expiry is not None:
                    evidence['days_until_expiry'] = days_until_expiry
                
                findings.append({
                    'type': 'cert_info',
                    'severity': 'Info',
                    'title': 'Información del certificado TLS',
                    'description': 'Información del certificado obtenida',
                    'recommendation': 'N/A',
                    'evidence': evidence
                })
                
    except ssl.SSLError as e:
        findings.append({
            'type': 'ssl_error',
            'severity': 'High',
            'title': 'Error SSL/TLS',
            'description': f'Error al verificar SSL/TLS: {str(e)}',
            'recommendation': 'Verificar configuración SSL/TLS del servidor',
            'evidence': {
                'url': scope_url,
                'error': str(e)
            }
        })
    except socket.timeout:
        findings.append({
            'type': 'tls_timeout',
            'severity': 'Medium',
            'title': 'Timeout al verificar TLS',
            'description': 'No se pudo conectar para verificar TLS',
            'recommendation': 'Verificar conectividad y configuración del servidor',
            'evidence': {
                'url': scope_url,
                'error': 'Timeout'
            }
        })
    except Exception as e:
        findings.append({
            'type': 'tls_check_error',
            'severity': 'Info',
            'title': 'Error al verificar TLS',
            'description': f'Error inesperado: {str(e)}',
            'recommendation': 'Verificar manualmente la configuración TLS',
            'evidence': {
                'url': scope_url,
                'error': str(e)
            }
        })
    
    return findings


def x509_name_to_dict(name) -> Dict[str, str]:
    """
    Convierte un objeto x509.Name a diccionario.
    
    Args:
        name: Objeto x509.Name
        
    Returns:
        Diccionario con atributos
    """
    result = {}
    for attribute in name:
        oid_name = attribute.oid._name
        result[oid_name] = attribute.value
    return result

