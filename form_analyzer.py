"""
Form Analyzer - Analiza formularios para detectar vulnerabilidades
Solo para uso en sistemas propios o con autorización explícita
"""

import requests
from bs4 import BeautifulSoup
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from urllib.parse import urljoin, urlparse
import re


@dataclass
class FormInfo:
    action: str
    method: str
    inputs: List[Dict]
    has_csrf: bool
    csrf_token_name: Optional[str]
    issues: List[str]
    risk_level: str


@dataclass
class FormAnalyzerResult:
    target: str
    forms_found: int
    forms: List[FormInfo]
    overall_risk: str
    details: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


class FormAnalyzer:
    """
    Analiza formularios HTML para detectar problemas de seguridad
    """
    
    CSRF_TOKEN_NAMES = [
        "csrf", "csrf_token", "csrftoken", "csrfmiddlewaretoken",
        "_csrf", "_token", "token", "authenticity_token",
        "xsrf", "xsrf_token", "_xsrf", "__requestverificationtoken",
        "anticsrf", "anti_csrf", "nonce"
    ]
    
    SENSITIVE_INPUT_NAMES = [
        "password", "passwd", "pass", "pwd", "secret",
        "credit_card", "cc_number", "cvv", "ssn",
        "api_key", "apikey", "token", "auth"
    ]
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        self.session.verify = False
        requests.packages.urllib3.disable_warnings()
    
    def _has_csrf_token(self, form: BeautifulSoup, inputs: List[Dict]) -> tuple:
        """Verifica si el formulario tiene token CSRF"""
        for inp in inputs:
            name = inp.get("name", "").lower()
            for csrf_name in self.CSRF_TOKEN_NAMES:
                if csrf_name in name:
                    return True, inp.get("name")
        
        for meta in form.find_all("meta"):
            name = meta.get("name", "").lower()
            if "csrf" in name:
                return True, meta.get("name")
        
        return False, None
    
    def _analyze_inputs(self, inputs: List[Dict]) -> List[str]:
        """Analiza los inputs del formulario en busca de problemas"""
        issues = []
        
        password_inputs = [i for i in inputs if i.get("type") == "password"]
        for pwd_input in password_inputs:
            if not pwd_input.get("autocomplete") or pwd_input.get("autocomplete") != "off":
                issues.append(f"Campo de contraseña '{pwd_input.get('name', 'unknown')}' permite autocompletado")
        
        for inp in inputs:
            name = inp.get("name", "").lower()
            inp_type = inp.get("type", "text")
            
            for sensitive in self.SENSITIVE_INPUT_NAMES:
                if sensitive in name:
                    if inp_type != "password" and inp_type != "hidden":
                        issues.append(f"Campo sensible '{inp.get('name')}' no es tipo password/hidden")
        
        email_inputs = [i for i in inputs if i.get("type") == "email" or "email" in i.get("name", "").lower()]
        for email in email_inputs:
            if not email.get("pattern") and not email.get("required"):
                issues.append(f"Campo de email '{email.get('name', 'unknown')}' sin validación HTML5")
        
        return issues
    
    def _analyze_form(self, form: BeautifulSoup, base_url: str) -> FormInfo:
        """Analiza un formulario individual"""
        action_attr = form.get("action", "")
        if action_attr and isinstance(action_attr, str):
            action = urljoin(base_url, action_attr)
        else:
            action = base_url
        
        method_attr = form.get("method", "GET")
        method = method_attr.upper() if isinstance(method_attr, str) else "GET"
        
        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            input_info = {
                "name": inp.get("name"),
                "type": inp.get("type", "text"),
                "id": inp.get("id"),
                "required": inp.has_attr("required"),
                "pattern": inp.get("pattern"),
                "autocomplete": inp.get("autocomplete"),
                "value": inp.get("value", "")[:50] if inp.get("value") else None
            }
            inputs.append(input_info)
        
        has_csrf, csrf_name = self._has_csrf_token(form, inputs)
        
        issues = []
        
        if method == "POST" and not has_csrf:
            issues.append("Formulario POST sin token CSRF visible")
        
        if method == "GET":
            has_password = any(i.get("type") == "password" for i in inputs)
            if has_password:
                issues.append("Formulario con contraseña usa método GET (datos visibles en URL)")
        
        parsed_action = urlparse(action)
        if parsed_action.scheme == "http" and any(i.get("type") == "password" for i in inputs):
            issues.append("Formulario de login envía a HTTP (sin cifrado)")
        
        issues.extend(self._analyze_inputs(inputs))
        
        if not issues:
            risk_level = "bajo"
        elif any("CSRF" in i for i in issues):
            risk_level = "alto"
        elif any("contraseña" in i.lower() or "password" in i.lower() for i in issues):
            risk_level = "medio"
        else:
            risk_level = "bajo"
        
        return FormInfo(
            action=action,
            method=method,
            inputs=inputs,
            has_csrf=has_csrf,
            csrf_token_name=csrf_name,
            issues=issues,
            risk_level=risk_level
        )
    
    def analyze(self, url: str) -> FormAnalyzerResult:
        """
        Analiza todos los formularios en una página
        
        Args:
            url: URL de la página a analizar
        """
        try:
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
        except Exception as e:
            return FormAnalyzerResult(
                target=url,
                forms_found=0,
                forms=[],
                overall_risk="error",
                details=[f"Error al obtener la página: {str(e)}"],
                recommendations=["Verificar que la URL sea accesible"]
            )
        
        soup = BeautifulSoup(response.text, "html.parser")
        html_forms = soup.find_all("form")
        
        forms = []
        for form in html_forms:
            form_info = self._analyze_form(form, url)
            forms.append(form_info)
        
        if any(f.risk_level == "alto" for f in forms):
            overall_risk = "alto"
        elif any(f.risk_level == "medio" for f in forms):
            overall_risk = "medio"
        elif forms:
            overall_risk = "bajo"
        else:
            overall_risk = "info"
        
        details = [
            f"URL analizada: {url}",
            f"Formularios encontrados: {len(forms)}"
        ]
        
        for i, form in enumerate(forms, 1):
            details.append(f"Form {i}: {form.method} -> {form.action[:50]}... ({len(form.inputs)} campos)")
        
        recommendations = []
        
        csrf_issues = sum(1 for f in forms if not f.has_csrf and f.method == "POST")
        if csrf_issues > 0:
            recommendations.append(f"Agregar tokens CSRF a {csrf_issues} formulario(s) POST")
            recommendations.append("Implementar protección CSRF en el framework backend")
        
        password_issues = sum(1 for f in forms for i in f.issues if "contraseña" in i.lower())
        if password_issues > 0:
            recommendations.append("Revisar configuración de campos de contraseña")
            recommendations.append("Deshabilitar autocompletado en campos sensibles")
        
        http_issues = sum(1 for f in forms for i in f.issues if "HTTP" in i)
        if http_issues > 0:
            recommendations.append("Migrar formularios de login a HTTPS")
        
        if not recommendations:
            recommendations.append("Los formularios parecen tener buenas prácticas de seguridad")
        
        return FormAnalyzerResult(
            target=url,
            forms_found=len(forms),
            forms=forms,
            overall_risk=overall_risk,
            details=details,
            recommendations=recommendations
        )


def main():
    import sys
    
    print("=" * 60)
    print("FORM ANALYZER - Análisis de Seguridad de Formularios")
    print("=" * 60)
    print("\nADVERTENCIA: Solo para sistemas propios o autorizados")
    print("=" * 60)
    
    if len(sys.argv) < 2:
        print("\nUso: python form_analyzer.py <url>")
        print("Ejemplo: python form_analyzer.py https://mi-sitio.com/login")
        sys.exit(1)
    
    url = sys.argv[1]
    
    analyzer = FormAnalyzer()
    result = analyzer.analyze(url)
    
    print(f"\nRiesgo: {result.overall_risk.upper()}")
    print(f"Formularios: {result.forms_found}")
    
    for i, form in enumerate(result.forms, 1):
        print(f"\n  Form {i}: {form.method} -> {form.action[:40]}...")
        print(f"    CSRF: {'Sí' if form.has_csrf else 'No'}")
        if form.issues:
            for issue in form.issues:
                print(f"    [!] {issue}")


if __name__ == "__main__":
    main()
