"""
Detector de vulnerabilidad a Clickjacking
Verifica si un sitio puede ser embebido en iframes
"""

import requests
from urllib.parse import urlparse
from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class ClickjackingResult:
    """Resultado del análisis de clickjacking"""
    url: str
    vulnerable: bool
    x_frame_options: Optional[str]
    csp_frame_ancestors: Optional[str]
    can_be_framed: bool
    risk_level: str
    details: List[str]
    recommendations: List[str]
    test_html: str


class ClickjackingAnalyzer:
    """Analizador de vulnerabilidad a Clickjacking"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SecurityAudit/1.0 (Clickjacking Test)'
        })
    
    def analyze(self, url: str) -> ClickjackingResult:
        """
        Analiza un sitio para detectar vulnerabilidad a clickjacking
        
        Args:
            url: URL del sitio a analizar
            
        Returns:
            ClickjackingResult con los hallazgos
        """
        parsed = urlparse(url)
        if not parsed.scheme:
            url = f"https://{url}"
        
        details = []
        recommendations = []
        vulnerable = False
        can_be_framed = True
        
        # Obtener headers
        x_frame_options = None
        csp_frame_ancestors = None
        
        try:
            response = self.session.get(url, timeout=10)
            headers = response.headers
            
            # Verificar X-Frame-Options
            x_frame_options = headers.get('X-Frame-Options')
            if x_frame_options:
                xfo_lower = x_frame_options.lower()
                if xfo_lower in ['deny', 'sameorigin']:
                    can_be_framed = False
                    details.append(f"X-Frame-Options: {x_frame_options} - Protegido")
                else:
                    details.append(f"X-Frame-Options: {x_frame_options} - Valor no estándar")
            else:
                details.append("X-Frame-Options: No presente")
                vulnerable = True
            
            # Verificar CSP frame-ancestors
            csp = headers.get('Content-Security-Policy', '')
            if 'frame-ancestors' in csp.lower():
                # Extraer directiva frame-ancestors
                for directive in csp.split(';'):
                    if 'frame-ancestors' in directive.lower():
                        csp_frame_ancestors = directive.strip()
                        if "'none'" in directive or "'self'" in directive:
                            can_be_framed = False
                            details.append(f"CSP frame-ancestors: Protegido")
                        else:
                            details.append(f"CSP frame-ancestors: {directive.strip()}")
                        break
            else:
                details.append("CSP frame-ancestors: No presente")
            
            # Determinar si es vulnerable
            if x_frame_options is None and csp_frame_ancestors is None:
                vulnerable = True
                can_be_framed = True
                details.append("Sin protección contra clickjacking")
            elif can_be_framed:
                vulnerable = True
            else:
                vulnerable = False
                
        except Exception as e:
            details.append(f"Error al analizar: {str(e)[:100]}")
            vulnerable = True  # Asumir vulnerable si hay error
        
        # Generar recomendaciones
        if vulnerable:
            recommendations.extend([
                "Agregar header X-Frame-Options: DENY o SAMEORIGIN",
                "Implementar CSP con frame-ancestors 'none' o 'self'",
                "Considerar usar JavaScript frame-busting como respaldo"
            ])
        
        # Calcular nivel de riesgo
        if vulnerable and can_be_framed:
            risk_level = "alto"
        elif vulnerable:
            risk_level = "medio"
        else:
            risk_level = "bajo"
        
        # Generar HTML de prueba
        test_html = self._generate_test_html(url)
        
        return ClickjackingResult(
            url=url,
            vulnerable=vulnerable,
            x_frame_options=x_frame_options,
            csp_frame_ancestors=csp_frame_ancestors,
            can_be_framed=can_be_framed,
            risk_level=risk_level,
            details=details,
            recommendations=recommendations,
            test_html=test_html
        )
    
    def _generate_test_html(self, url: str) -> str:
        """Genera HTML para probar clickjacking visualmente"""
        return f'''<!DOCTYPE html>
<html>
<head>
    <title>Prueba de Clickjacking - {url}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background: #f0f0f0;
        }}
        .warning {{
            background: #fff3cd;
            border: 1px solid #ffc107;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
        .container {{
            position: relative;
            width: 100%;
            max-width: 1000px;
            margin: 0 auto;
        }}
        .overlay {{
            position: absolute;
            top: 100px;
            left: 50px;
            background: rgba(255,0,0,0.3);
            padding: 20px;
            border-radius: 5px;
            pointer-events: none;
        }}
        iframe {{
            width: 100%;
            height: 600px;
            border: 2px solid #333;
        }}
        .result {{
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
        }}
        .vulnerable {{
            background: #f8d7da;
            border: 1px solid #f5c6cb;
        }}
        .protected {{
            background: #d4edda;
            border: 1px solid #c3e6cb;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Prueba de Clickjacking</h1>
        
        <div class="warning">
            <strong>ADVERTENCIA LEGAL:</strong> Esta prueba es solo para sitios propios 
            o con autorización explícita. El uso no autorizado puede ser ilegal.
        </div>
        
        <h2>URL objetivo: {url}</h2>
        
        <div id="result" class="result">
            Cargando iframe... Si el sitio aparece abajo, es vulnerable a clickjacking.
        </div>
        
        <h3>Iframe de prueba:</h3>
        <iframe 
            id="testFrame"
            src="{url}" 
            sandbox="allow-scripts allow-same-origin"
            onload="checkFrame()"
            onerror="frameError()">
        </iframe>
        
        <div class="overlay">
            <p>Este overlay simula un botón malicioso</p>
            <button>Botón falso (no funciona)</button>
        </div>
    </div>
    
    <script>
        function checkFrame() {{
            var result = document.getElementById('result');
            var frame = document.getElementById('testFrame');
            
            try {{
                // Intentar acceder al contenido (fallará por CORS si está cargado)
                var doc = frame.contentDocument || frame.contentWindow.document;
                result.className = 'result vulnerable';
                result.innerHTML = '<strong>VULNERABLE:</strong> El sitio puede ser embebido en un iframe.';
            }} catch(e) {{
                // Si hay contenido visible pero no podemos acceder, sigue siendo vulnerable
                result.className = 'result vulnerable';
                result.innerHTML = '<strong>POSIBLEMENTE VULNERABLE:</strong> El iframe cargó contenido (verificar visualmente).';
            }}
        }}
        
        function frameError() {{
            var result = document.getElementById('result');
            result.className = 'result protected';
            result.innerHTML = '<strong>PROTEGIDO:</strong> El sitio rechazó ser embebido en un iframe.';
        }}
        
        // Timeout para detectar si el frame no carga
        setTimeout(function() {{
            var result = document.getElementById('result');
            if (result.innerHTML.includes('Cargando')) {{
                result.className = 'result protected';
                result.innerHTML = '<strong>PROTEGIDO o BLOQUEADO:</strong> El iframe no cargó contenido.';
            }}
        }}, 5000);
    </script>
</body>
</html>'''


def main():
    """Función principal para uso CLI"""
    import sys
    
    print("=" * 60)
    print("DETECTOR DE CLICKJACKING")
    print("=" * 60)
    print("\nADVERTENCIA LEGAL:")
    print("Esta herramienta es solo para uso en sistemas propios o")
    print("con autorización explícita del propietario.")
    print("El uso no autorizado puede ser ilegal.")
    print("=" * 60)
    
    if len(sys.argv) < 2:
        print("\nUso: python clickjacking_test.py <url>")
        print("Ejemplo: python clickjacking_test.py https://ejemplo.com")
        sys.exit(1)
    
    url = sys.argv[1]
    analyzer = ClickjackingAnalyzer()
    result = analyzer.analyze(url)
    
    print(f"\nResultados para: {result.url}")
    print("-" * 40)
    print(f"Vulnerable: {'Sí' if result.vulnerable else 'No'}")
    print(f"Puede ser enmarcado: {'Sí' if result.can_be_framed else 'No'}")
    print(f"Nivel de Riesgo: {result.risk_level.upper()}")
    
    if result.x_frame_options:
        print(f"X-Frame-Options: {result.x_frame_options}")
    else:
        print("X-Frame-Options: No presente")
    
    if result.csp_frame_ancestors:
        print(f"CSP frame-ancestors: {result.csp_frame_ancestors}")
    else:
        print("CSP frame-ancestors: No presente")
    
    if result.details:
        print("\nDETALLES:")
        for d in result.details:
            print(f"  - {d}")
    
    if result.recommendations:
        print("\nRECOMENDACIONES:")
        for r in result.recommendations:
            print(f"  - {r}")
    
    # Guardar HTML de prueba
    html_file = "clickjacking_test.html"
    with open(html_file, 'w') as f:
        f.write(result.test_html)
    print(f"\nArchivo de prueba guardado: {html_file}")
    print("Abre este archivo en un navegador para verificar visualmente.")


if __name__ == "__main__":
    main()
