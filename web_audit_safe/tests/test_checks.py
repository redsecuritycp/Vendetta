"""
Tests para los módulos de checks
"""

import unittest
from web_audit_safe.checks.headers import check_security_headers
from web_audit_safe.checks.cookies import check_cookies, parse_cookie_attributes


class TestChecks(unittest.TestCase):
    """Tests para módulos de verificación"""
    
    def test_check_security_headers_missing(self):
        """Test de verificación de headers faltantes"""
        responses = [
            {
                'url': 'https://example.com',
                'headers': {},
                'content': None,
                'content_type': 'text/html'
            }
        ]
        
        findings = check_security_headers(responses)
        
        # Debe encontrar varios headers faltantes
        self.assertGreater(len(findings), 0)
        
        # Verificar que hay hallazgos de headers faltantes
        missing_header_findings = [
            f for f in findings if f.get('type') == 'missing_security_header'
        ]
        self.assertGreater(len(missing_header_findings), 0)
    
    def test_check_security_headers_present(self):
        """Test cuando los headers están presentes"""
        responses = [
            {
                'url': 'https://example.com',
                'headers': {
                    'Strict-Transport-Security': 'max-age=31536000',
                    'Content-Security-Policy': "default-src 'self'",
                    'X-Frame-Options': 'DENY',
                    'X-Content-Type-Options': 'nosniff'
                },
                'content': None,
                'content_type': 'text/html'
            }
        ]
        
        findings = check_security_headers(responses)
        
        # Debe tener menos hallazgos que cuando faltan todos
        # (aún puede haber algunos headers faltantes)
        missing_hsts = [
            f for f in findings 
            if f.get('type') == 'missing_security_header' and 
            'HSTS' in f.get('title', '')
        ]
        self.assertEqual(len(missing_hsts), 0)
    
    def test_check_cookies_insecure(self):
        """Test de verificación de cookies inseguras"""
        responses = [
            {
                'url': 'https://example.com',
                'headers': {
                    'Set-Cookie': 'sessionid=abc123; Path=/'
                },
                'content': None
            }
        ]
        
        findings = check_cookies(responses)
        
        # Debe encontrar cookies sin Secure y HttpOnly
        insecure_findings = [
            f for f in findings 
            if 'cookie' in f.get('type', '').lower() and 
            ('secure' in f.get('type', '').lower() or 'httponly' in f.get('type', '').lower())
        ]
        self.assertGreater(len(insecure_findings), 0)
    
    def test_check_cookies_secure(self):
        """Test cuando las cookies están bien configuradas"""
        responses = [
            {
                'url': 'https://example.com',
                'headers': {
                    'Set-Cookie': 'sessionid=abc123; Secure; HttpOnly; SameSite=Strict; Path=/'
                },
                'content': None
            }
        ]
        
        findings = check_cookies(responses)
        
        # No debe haber hallazgos de cookies sin Secure/HttpOnly
        insecure_findings = [
            f for f in findings 
            if f.get('type') in ['cookie_without_secure', 'cookie_without_httponly']
        ]
        self.assertEqual(len(insecure_findings), 0)
    
    def test_parse_cookie_attributes(self):
        """Test de parsing de atributos de cookies"""
        cookie_header = 'sessionid=abc123; Secure; HttpOnly; SameSite=Strict; Path=/; Domain=example.com'
        
        attrs = parse_cookie_attributes(cookie_header)
        
        self.assertTrue(attrs.get('Secure'))
        self.assertTrue(attrs.get('HttpOnly'))
        self.assertEqual(attrs.get('SameSite'), 'Strict')
        self.assertEqual(attrs.get('Path'), '/')
        self.assertEqual(attrs.get('Domain'), 'example.com')


if __name__ == '__main__':
    unittest.main()

