"""
Pipeline de escaneo completo - Ejecuta todas las herramientas en secuencia
y consolida resultados en un reporte unificado
"""

import time
from typing import Dict, List, Optional, Callable
from urllib.parse import urlparse
from dataclasses import dataclass, field

from report_generator import ScanReport, Finding
from recon import PassiveRecon
from sslstrip_sim import SSLStripAnalyzer
from xss_test import XSSAnalyzer
from clickjacking_test import ClickjackingAnalyzer
from dir_fuzzer import DirectoryFuzzer
from form_analyzer import FormAnalyzer
from subdomain_enum import SubdomainEnumerator
from bypass_403 import Bypass403


@dataclass
class ScanProgress:
    """Estado del escaneo"""
    current_tool: str = ""
    current_step: int = 0
    total_steps: int = 8
    percent: float = 0.0
    findings_so_far: int = 0
    log: List[str] = field(default_factory=list)
    done: bool = False
    error: Optional[str] = None


class FullScanner:
    """Ejecuta un scan completo contra un objetivo"""

    TOOLS = [
        ("Reconocimiento Pasivo", "recon"),
        ("Analisis HSTS/SSL", "hsts"),
        ("Analisis XSS", "xss"),
        ("Clickjacking", "clickjack"),
        ("Fuzzing de Directorios", "dirs"),
        ("Analisis de Formularios", "forms"),
        ("Enumeracion de Subdominios", "subs"),
        ("Bypass 403", "bypass"),
    ]

    def __init__(self, auth_config: Optional[Dict] = None):
        self.auth_config = auth_config or {}
        self.progress = ScanProgress(total_steps=len(self.TOOLS))

    def _log(self, msg: str):
        self.progress.log.append(msg)

    def _update_progress(self, tool_name: str, step: int):
        self.progress.current_tool = tool_name
        self.progress.current_step = step
        self.progress.percent = (step / self.progress.total_steps) * 100

    def scan(self, url: str,
             skip_tools: Optional[List[str]] = None,
             xss_test_url: str = "",
             bypass_paths: Optional[List[str]] = None,
             on_progress: Optional[Callable] = None) -> ScanReport:
        """
        Ejecuta scan completo

        Args:
            url: URL objetivo
            skip_tools: Lista de tool IDs a saltear
            xss_test_url: URL con parametros para test XSS
            bypass_paths: Paths para probar bypass 403
            on_progress: Callback para reportar progreso
        """
        skip = set(skip_tools or [])
        report = ScanReport(target=url)
        start_time = time.time()

        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path

        step = 0

        # 1. Reconocimiento
        if "recon" not in skip:
            step += 1
            self._update_progress("Reconocimiento Pasivo", step)
            self._log(f"[{step}/{self.progress.total_steps}] Reconocimiento pasivo de {domain}...")
            if on_progress:
                on_progress(self.progress)
            try:
                recon = PassiveRecon()
                result = recon.analyze(url)
                report.tools_used.append("Recon")
                report.raw_results["recon"] = {
                    "ips": result.ip_addresses,
                    "technologies": result.technologies,
                    "security_headers": result.security_headers,
                }
                missing = [h for h in PassiveRecon.SECURITY_HEADERS if h not in result.security_headers]
                for h in missing:
                    report.add_finding(Finding(
                        tool="Recon",
                        title=f"Header de seguridad faltante: {h}",
                        severity="medio" if h in ["Content-Security-Policy", "Strict-Transport-Security"] else "bajo",
                        description=f"El header {h} no esta presente en la respuesta del servidor.",
                        recommendation=f"Implementar el header {h} en la configuracion del servidor web."
                    ))
                if result.server_info.get("server"):
                    report.add_finding(Finding(
                        tool="Recon",
                        title="Version del servidor expuesta",
                        severity="bajo",
                        description=f"El servidor expone su version: {result.server_info['server']}",
                        evidence=f"Server: {result.server_info['server']}",
                        recommendation="Ocultar la version del servidor en los headers HTTP."
                    ))
                if result.server_info.get("powered_by"):
                    report.add_finding(Finding(
                        tool="Recon",
                        title="Tecnologia expuesta via X-Powered-By",
                        severity="bajo",
                        description=f"Header X-Powered-By revela: {result.server_info['powered_by']}",
                        recommendation="Remover el header X-Powered-By."
                    ))
                self._log(f"  > {len(result.ip_addresses)} IPs, {len(result.technologies)} tecnologias, {len(result.security_headers)}/{len(PassiveRecon.SECURITY_HEADERS)} headers")
            except Exception as e:
                self._log(f"  > Error: {str(e)[:100]}")

        # 2. HSTS/SSL
        if "hsts" not in skip:
            step += 1
            self._update_progress("Analisis HSTS/SSL", step)
            self._log(f"[{step}/{self.progress.total_steps}] Analisis HSTS/SSL...")
            if on_progress:
                on_progress(self.progress)
            try:
                analyzer = SSLStripAnalyzer()
                result = analyzer.analyze(url)
                report.tools_used.append("HSTS")
                if not result.has_hsts:
                    report.add_finding(Finding(
                        tool="HSTS",
                        title="Sin proteccion HSTS",
                        severity="alto",
                        description="El sitio no implementa HTTP Strict Transport Security, vulnerable a ataques SSLStrip.",
                        recommendation="Agregar header Strict-Transport-Security con max-age minimo de 1 anio."
                    ))
                if not result.redirects_to_https:
                    report.add_finding(Finding(
                        tool="HSTS",
                        title="HTTP no redirige a HTTPS",
                        severity="alto",
                        description="Las conexiones HTTP no son redirigidas automaticamente a HTTPS.",
                        recommendation="Configurar redireccion 301 de HTTP a HTTPS."
                    ))
                for v in result.vulnerabilities:
                    if "max-age" in v.lower():
                        report.add_finding(Finding(
                            tool="HSTS",
                            title="HSTS max-age insuficiente",
                            severity="medio",
                            description=v,
                            recommendation="Aumentar max-age a 31536000 (1 anio) o mas."
                        ))
                self._log(f"  > HSTS: {'Si' if result.has_hsts else 'No'}, Riesgo: {result.risk_level}")
            except Exception as e:
                self._log(f"  > Error: {str(e)[:100]}")

        # 3. XSS
        if "xss" not in skip:
            step += 1
            self._update_progress("Analisis XSS", step)
            test_url = xss_test_url or url
            self._log(f"[{step}/{self.progress.total_steps}] Analisis XSS en {test_url}...")
            if on_progress:
                on_progress(self.progress)
            try:
                analyzer = XSSAnalyzer()
                result = analyzer.analyze(test_url)
                report.tools_used.append("XSS")
                for v in result.vulnerable_params:
                    report.add_finding(Finding(
                        tool="XSS",
                        title=f"XSS en parametro '{v['param']}'",
                        severity="critico" if v.get("severity") == "critico" else "alto",
                        description=f"Parametro '{v['param']}' vulnerable a XSS. Contexto: {v.get('context', 'N/A')}",
                        evidence=f"Payload reflejado: {v.get('payload', 'N/A')}",
                        recommendation="Sanitizar entrada y aplicar encoding de salida. Implementar CSP."
                    ))
                self._log(f"  > Params reflejados: {len(result.reflected_params)}, Vulnerables: {len(result.vulnerable_params)}")
            except Exception as e:
                self._log(f"  > Error: {str(e)[:100]}")

        # 4. Clickjacking
        if "clickjack" not in skip:
            step += 1
            self._update_progress("Clickjacking", step)
            self._log(f"[{step}/{self.progress.total_steps}] Test de clickjacking...")
            if on_progress:
                on_progress(self.progress)
            try:
                analyzer = ClickjackingAnalyzer()
                result = analyzer.analyze(url)
                report.tools_used.append("Clickjacking")
                if result.vulnerable:
                    report.add_finding(Finding(
                        tool="Clickjacking",
                        title="Vulnerable a Clickjacking",
                        severity="alto" if result.can_be_framed else "medio",
                        description=f"El sitio puede ser embebido en iframes. X-Frame-Options: {result.x_frame_options or 'No presente'}. CSP frame-ancestors: {result.csp_frame_ancestors or 'No presente'}.",
                        recommendation="Agregar X-Frame-Options: DENY y CSP frame-ancestors 'none'."
                    ))
                self._log(f"  > Vulnerable: {'Si' if result.vulnerable else 'No'}")
            except Exception as e:
                self._log(f"  > Error: {str(e)[:100]}")

        # 5. Directories
        if "dirs" not in skip:
            step += 1
            self._update_progress("Fuzzing de Directorios", step)
            self._log(f"[{step}/{self.progress.total_steps}] Fuzzing de directorios...")
            if on_progress:
                on_progress(self.progress)
            try:
                fuzzer = DirectoryFuzzer()
                result = fuzzer.analyze(url, threads=15)
                report.tools_used.append("DirFuzzer")
                for p in result.found_paths:
                    if p["risk"] in ["critico", "alto"]:
                        report.add_finding(Finding(
                            tool="DirFuzzer",
                            title=f"Archivo sensible expuesto: {p['path']}",
                            severity=p["risk"],
                            description=f"Se encontro {p['path']} accesible (HTTP {p['status']}, {p['size']} bytes).",
                            evidence=f"URL: {p.get('url', '')}\nContent-Type: {p.get('content_type', 'N/A')}",
                            recommendation="Bloquear acceso a archivos sensibles via configuracion del servidor."
                        ))
                    elif p["risk"] == "medio":
                        report.add_finding(Finding(
                            tool="DirFuzzer",
                            title=f"Ruta administrativa encontrada: {p['path']}",
                            severity="medio",
                            description=f"Ruta {p['path']} accesible (HTTP {p['status']}).",
                            recommendation="Restringir acceso por IP o autenticacion fuerte."
                        ))
                self._log(f"  > {result.total_checked} paths probados, {len(result.found_paths)} encontrados")
            except Exception as e:
                self._log(f"  > Error: {str(e)[:100]}")

        # 6. Forms
        if "forms" not in skip:
            step += 1
            self._update_progress("Analisis de Formularios", step)
            self._log(f"[{step}/{self.progress.total_steps}] Analizando formularios...")
            if on_progress:
                on_progress(self.progress)
            try:
                analyzer = FormAnalyzer()
                result = analyzer.analyze(url)
                report.tools_used.append("Forms")
                for form in result.forms:
                    if not form.has_csrf and form.method == "POST":
                        report.add_finding(Finding(
                            tool="Forms",
                            title=f"Formulario POST sin CSRF: {form.action[:60]}",
                            severity="alto",
                            description=f"Formulario {form.method} hacia {form.action} no tiene token CSRF.",
                            recommendation="Implementar tokens CSRF en todos los formularios POST."
                        ))
                    for issue in form.issues:
                        if "HTTP" in issue and "cifrado" in issue.lower():
                            report.add_finding(Finding(
                                tool="Forms",
                                title="Login sobre HTTP sin cifrado",
                                severity="critico",
                                description=issue,
                                recommendation="Migrar todos los formularios de login a HTTPS."
                            ))
                self._log(f"  > {result.forms_found} formularios encontrados")
            except Exception as e:
                self._log(f"  > Error: {str(e)[:100]}")

        # 7. Subdomains
        if "subs" not in skip:
            step += 1
            self._update_progress("Enumeracion de Subdominios", step)
            self._log(f"[{step}/{self.progress.total_steps}] Enumerando subdominios de {domain}...")
            if on_progress:
                on_progress(self.progress)
            try:
                enumerator = SubdomainEnumerator()
                result = enumerator.analyze(domain, threads=20, timeout=60)
                report.tools_used.append("Subdominios")
                sensitive_subs = ["admin", "dev", "staging", "test", "backup", "internal", "vpn"]
                for sub in result.subdomains_found:
                    if sub.subdomain in sensitive_subs:
                        report.add_finding(Finding(
                            tool="Subdominios",
                            title=f"Subdominio sensible: {sub.full_domain}",
                            severity="medio",
                            description=f"Subdominio {sub.full_domain} encontrado ({', '.join(sub.ip_addresses)}). HTTP: {sub.http_status}, HTTPS: {sub.https_status}.",
                            recommendation="Verificar que subdominios de desarrollo no expongan informacion sensible."
                        ))
                http_only = [s for s in result.subdomains_found if s.http_status and not s.https_status]
                if http_only:
                    report.add_finding(Finding(
                        tool="Subdominios",
                        title=f"{len(http_only)} subdominios sin HTTPS",
                        severity="medio",
                        description=f"Los siguientes subdominios solo tienen HTTP: {', '.join(s.full_domain for s in http_only[:5])}",
                        recommendation="Implementar HTTPS en todos los subdominios."
                    ))
                self._log(f"  > {len(result.subdomains_found)} subdominios encontrados de {result.total_checked} probados")
            except Exception as e:
                self._log(f"  > Error: {str(e)[:100]}")

        # 8. Bypass 403
        if "bypass" not in skip and bypass_paths:
            step += 1
            self._update_progress("Bypass 403", step)
            self._log(f"[{step}/{self.progress.total_steps}] Intentando bypass 403 en {len(bypass_paths)} paths...")
            if on_progress:
                on_progress(self.progress)
            try:
                bypasser = Bypass403()
                result = bypasser.analyze(url, bypass_paths)
                report.tools_used.append("Bypass403")
                for dl in result.downloadable_files:
                    report.add_finding(Finding(
                        tool="Bypass403",
                        title=f"Bypass 403 exitoso: {dl['original_path']}",
                        severity="critico",
                        description=f"Se logro acceder a {dl['original_path']} usando tecnica: {dl['technique']}.",
                        evidence=f"URL: {dl['bypass_url']}\nContenido ({dl['size']} bytes): {dl['content'][:200]}...",
                        recommendation="Revisar reglas de acceso y bloquear todas las variantes de la ruta."
                    ))
                self._log(f"  > {result.total_bypasses} bypasses encontrados")
            except Exception as e:
                self._log(f"  > Error: {str(e)[:100]}")

        report.duration = time.time() - start_time
        self.progress.done = True
        self.progress.findings_so_far = len(report.findings)
        self.progress.percent = 100
        self._log(f"\nScan completo en {report.duration:.1f}s - {len(report.findings)} hallazgos")
        if on_progress:
            on_progress(self.progress)

        return report
