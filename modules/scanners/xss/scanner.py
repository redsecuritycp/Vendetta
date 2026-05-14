"""
Detector de vulnerabilidades XSS (Cross-Site Scripting)
Analiza parámetros de URL para detectar posibles puntos de inyección
"""

import requests
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from html.parser import HTMLParser


@dataclass
class XSSResult:
    """Resultado del análisis XSS"""
    url: str
    vulnerable_params: List[Dict]
    reflected_params: List[str]
    risk_level: str
    details: List[str]
    recommendations: List[str]


class ReflectionChecker(HTMLParser):
    """Parser para detectar reflexiones en HTML"""
    
    def __init__(self, payload: str):
        super().__init__()
        self.payload = payload
        self.found_in_tag = False
        self.found_in_attr = False
        self.found_in_script = False
        self.in_script = False
    
    def handle_starttag(self, tag, attrs):
        if tag == 'script':
            self.in_script = True
        for attr_name, attr_value in attrs:
            if attr_value and self.payload in attr_value:
                self.found_in_attr = True
    
    def handle_endtag(self, tag):
        if tag == 'script':
            self.in_script = False
    
    def handle_data(self, data):
        if self.payload in data:
            if self.in_script:
                self.found_in_script = True
            else:
                self.found_in_tag = True


class XSSAnalyzer:
    """Analizador de vulnerabilidades XSS"""
    
    # Payloads de prueba seguros (no ejecutan código)
    TEST_PAYLOADS = [
        "XSS_TEST_123",
        "<xss>test</xss>",
        "';alert('xss')//",
        '"><img src=x>',
        "javascript:test",
        "<script>xss</script>",
        "'-alert(1)-'",
        "<img src=x onerror=alert(1)>",
    ]
    
    # Patrones que indican posible vulnerabilidad
    DANGEROUS_PATTERNS = [
        (r'<script[^>]*>.*?</script>', "Script tag reflejado"),
        (r'on\w+\s*=', "Event handler reflejado"),
        (r'javascript:', "JavaScript URI reflejado"),
        (r'<img[^>]+onerror', "IMG con onerror reflejado"),
        (r'<svg[^>]+onload', "SVG con onload reflejado"),
    ]
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SecurityAudit/1.0 (Authorized XSS Test)'
        })
    
    def analyze(self, url: str) -> XSSResult:
        """
        Analiza una URL para detectar vulnerabilidades XSS
        
        Args:
            url: URL con parámetros a analizar
            
        Returns:
            XSSResult con los hallazgos
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        vulnerable_params = []
        reflected_params = []
        details = []
        recommendations = []
        
        if not params:
            details.append("No se encontraron parámetros en la URL para analizar")
            return XSSResult(
                url=url,
                vulnerable_params=[],
                reflected_params=[],
                risk_level="info",
                details=details,
                recommendations=["Proporcionar URL con parámetros (ej: ?search=test)"]
            )
        
        # Probar cada parámetro
        for param_name, param_values in params.items():
            original_value = param_values[0] if param_values else ""
            
            param_is_vulnerable = False
            for payload in self.TEST_PAYLOADS:
                result = self._test_payload(url, param_name, payload, parsed)
                
                if result['reflected']:
                    if param_name not in reflected_params:
                        reflected_params.append(param_name)
                    
                    if result['vulnerable']:
                        vulnerable_params.append({
                            'param': param_name,
                            'payload': payload,
                            'context': result['context'],
                            'severity': result['severity']
                        })
                        details.append(
                            f"Parámetro '{param_name}' refleja payload en contexto: {result['context']}"
                        )
                        param_is_vulnerable = True
                        break  # Solo break si confirmado vulnerable
        
        # Eliminar duplicados
        reflected_params = list(set(reflected_params))
        
        # Generar recomendaciones
        if vulnerable_params:
            recommendations.extend([
                "Implementar sanitización de entrada (input validation)",
                "Usar encoding de salida apropiado (HTML entities, URL encoding)",
                "Implementar Content-Security-Policy (CSP)",
                "Usar frameworks que escapen automáticamente (React, Vue, Angular)",
                "Validar y sanitizar en servidor, no solo en cliente"
            ])
        
        # Calcular nivel de riesgo
        risk_level = self._calculate_risk(vulnerable_params, reflected_params)
        
        return XSSResult(
            url=url,
            vulnerable_params=vulnerable_params,
            reflected_params=reflected_params,
            risk_level=risk_level,
            details=details,
            recommendations=recommendations
        )
    
    def _test_payload(self, url: str, param: str, payload: str, parsed) -> Dict:
        """Prueba un payload específico en un parámetro"""
        result = {
            'reflected': False,
            'vulnerable': False,
            'context': None,
            'severity': 'bajo'
        }
        
        try:
            # Construir URL con payload
            params = parse_qs(parsed.query)
            params[param] = [payload]
            new_query = urlencode(params, doseq=True)
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))
            
            response = self.session.get(test_url, timeout=10)
            content = response.text
            
            # Verificar si el payload se refleja
            if payload in content:
                result['reflected'] = True
                
                # Analizar contexto de reflexión
                checker = ReflectionChecker(payload)
                try:
                    checker.feed(content)
                except:
                    pass
                
                if checker.found_in_script:
                    result['vulnerable'] = True
                    result['context'] = "Dentro de <script>"
                    result['severity'] = "critico"
                elif checker.found_in_attr:
                    result['vulnerable'] = True
                    result['context'] = "Atributo HTML"
                    result['severity'] = "alto"
                elif checker.found_in_tag:
                    result['context'] = "Contenido HTML"
                    # Verificar si se renderiza como HTML
                    if '<' in payload and payload in content:
                        result['vulnerable'] = True
                        result['severity'] = "alto"
                
                # Verificar patrones peligrosos
                for pattern, desc in self.DANGEROUS_PATTERNS:
                    if re.search(pattern, content, re.IGNORECASE):
                        result['vulnerable'] = True
                        result['context'] = desc
                        result['severity'] = "critico"
                        break
                        
        except Exception as e:
            result['error'] = str(e)[:100]
        
        return result
    
    def _calculate_risk(self, vulnerable: List, reflected: List) -> str:
        """Calcula el nivel de riesgo"""
        if any(v.get('severity') == 'critico' for v in vulnerable):
            return "critico"
        elif any(v.get('severity') == 'alto' for v in vulnerable):
            return "alto"
        elif vulnerable:
            return "medio"
        elif reflected:
            return "bajo"
        return "ninguno"


def main():
    """Función principal para uso CLI"""
    import sys
    
    print("=" * 60)
    print("DETECTOR DE VULNERABILIDADES XSS")
    print("=" * 60)
    print("\nADVERTENCIA LEGAL:")
    print("Esta herramienta es solo para uso en sistemas propios o")
    print("con autorización explícita del propietario.")
    print("El uso no autorizado puede ser ilegal.")
    print("=" * 60)
    
    if len(sys.argv) < 2:
        print("\nUso: python xss_test.py <url_con_parametros>")
        print("Ejemplo: python xss_test.py 'https://ejemplo.com/buscar?q=test'")
        sys.exit(1)
    
    url = sys.argv[1]
    analyzer = XSSAnalyzer()
    result = analyzer.analyze(url)
    
    print(f"\nResultados para: {result.url}")
    print("-" * 40)
    print(f"Nivel de Riesgo: {result.risk_level.upper()}")
    print(f"Parámetros Reflejados: {len(result.reflected_params)}")
    print(f"Parámetros Vulnerables: {len(result.vulnerable_params)}")
    
    if result.reflected_params:
        print(f"\nParámetros que reflejan entrada: {', '.join(result.reflected_params)}")
    
    if result.vulnerable_params:
        print("\nVULNERABILIDADES ENCONTRADAS:")
        for v in result.vulnerable_params:
            print(f"  - {v['param']}: {v['context']} (Severidad: {v['severity']})")
    
    if result.details:
        print("\nDETALLES:")
        for d in result.details:
            print(f"  - {d}")
    
    if result.recommendations:
        print("\nRECOMENDACIONES:")
        for r in result.recommendations:
            print(f"  - {r}")


if __name__ == "__main__":
    main()
