"""
Tests para el módulo utils
"""

import unittest
from web_audit_safe.utils import (
    normalize_url,
    get_host_from_url,
    is_same_host,
    is_in_scope,
    sanitize_content
)


class TestUtils(unittest.TestCase):
    """Tests para funciones de utilidad"""
    
    def test_normalize_url(self):
        """Test de normalización de URLs"""
        # URL básica
        self.assertEqual(
            normalize_url("https://example.com"),
            "https://example.com"
        )
        
        # URL con puerto por defecto
        self.assertEqual(
            normalize_url("https://example.com:443/path"),
            "https://example.com/path"
        )
        
        # URL sin scheme
        result = normalize_url("example.com")
        self.assertIsNotNone(result)
        self.assertTrue(result.startswith("https://"))
        
        # URL con fragmento (debe removerlo)
        result = normalize_url("https://example.com/path#fragment")
        self.assertNotIn("#", result)
    
    def test_get_host_from_url(self):
        """Test de extracción de host"""
        self.assertEqual(
            get_host_from_url("https://example.com/path"),
            "example.com"
        )
        
        self.assertEqual(
            get_host_from_url("http://subdomain.example.com:8080/path"),
            "subdomain.example.com:8080"
        )
    
    def test_is_same_host(self):
        """Test de comparación de hosts"""
        self.assertTrue(
            is_same_host("https://example.com/path1", "https://example.com/path2")
        )
        
        self.assertFalse(
            is_same_host("https://example.com", "https://other.com")
        )
        
        # Mismo host con diferentes puertos (debe ser True después de normalizar)
        self.assertTrue(
            is_same_host("https://example.com:443", "https://example.com")
        )
    
    def test_is_in_scope(self):
        """Test de verificación de scope"""
        scope = "https://example.com"
        
        self.assertTrue(
            is_in_scope("https://example.com/page", scope)
        )
        
        self.assertTrue(
            is_in_scope("https://example.com/subdir/page", scope)
        )
        
        self.assertFalse(
            is_in_scope("https://other.com/page", scope)
        )
        
        # Scope con path específico
        scope_with_path = "https://example.com/app"
        self.assertTrue(
            is_in_scope("https://example.com/app/page", scope_with_path)
        )
        
        self.assertFalse(
            is_in_scope("https://example.com/other/page", scope_with_path)
        )
    
    def test_sanitize_content(self):
        """Test de sanitización de contenido"""
        # Contenido normal
        content = "Hello World"
        self.assertEqual(sanitize_content(content), "Hello World")
        
        # Contenido muy largo
        long_content = "A" * 5000
        result = sanitize_content(long_content, max_length=100)
        self.assertLessEqual(len(result), 120)  # 100 + "[truncado]"
        self.assertIn("truncado", result)
        
        # Contenido None
        self.assertEqual(sanitize_content(None), "")
        
        # Contenido vacío
        self.assertEqual(sanitize_content(""), "")


if __name__ == '__main__':
    unittest.main()

