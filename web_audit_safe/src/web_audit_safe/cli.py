"""
Interfaz de línea de comandos para web_audit_safe
"""

import argparse
import sys
from typing import Dict

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.panel import Panel

from .crawler import WebCrawler
from .report import ReportGenerator
from .utils import normalize_url, get_host_from_url, resolve_ip, get_port_from_url
from .checks import (
    check_security_headers,
    check_tls,
    check_cookies,
    check_file_exposure,
    check_forms,
    check_cors
)


def get_identity_info(scope_url: str) -> Dict:
    """
    Obtiene información de identidad del objetivo.
    
    Args:
        scope_url: URL del scope
        
    Returns:
        Diccionario con información de identidad
    """
    info = {
        'url': scope_url,
        'normalized_url': normalize_url(scope_url),
        'host': get_host_from_url(scope_url),
        'scheme': None,
        'port': None,
        'ip': None
    }
    
    from urllib.parse import urlparse
    parsed = urlparse(scope_url)
    info['scheme'] = parsed.scheme
    info['port'] = get_port_from_url(scope_url)
    
    # Resolver IP
    host = info['host']
    if host:
        hostname = host.split(':')[0]
        ip = resolve_ip(hostname)
        if ip:
            info['ip'] = ip
    
    return info


def main():
    """Función principal del CLI"""
    parser = argparse.ArgumentParser(
        description='Herramienta de auditoría de seguridad pasiva para aplicaciones web',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python -m web_audit_safe --url "https://example.com"
  python -m web_audit_safe --url "https://example.com" --out ./reports --max-pages 30

⚠️  ADVERTENCIA: Solo use esta herramienta en sistemas que posea o tenga autorización explícita.
        """
    )
    
    parser.add_argument(
        '--url',
        type=str,
        required=True,
        help='URL objetivo a auditar (requerido)'
    )
    
    parser.add_argument(
        '--out',
        type=str,
        default='./output',
        help='Directorio de salida para reportes (default: ./output)'
    )
    
    parser.add_argument(
        '--max-pages',
        type=int,
        default=20,
        help='Máximo de páginas a analizar (default: 20)'
    )
    
    parser.add_argument(
        '--max-requests',
        type=int,
        default=200,
        help='Máximo de requests totales (default: 200)'
    )
    
    parser.add_argument(
        '--delay',
        type=float,
        default=1.0,
        help='Delay entre requests en segundos (default: 1.0)'
    )
    
    args = parser.parse_args()
    
    console = Console()
    
    # Mostrar advertencia legal
    console.print(Panel(
        "[bold red]⚠️  ADVERTENCIA LEGAL[/bold red]\n\n"
        "Esta herramienta está diseñada para uso ético y legal únicamente.\n"
        "Solo utilice en sistemas que posea o tenga autorización explícita por escrito.\n"
        "El uso no autorizado puede violar leyes locales, estatales y federales.",
        title="Advertencia",
        border_style="red"
    ))
    
    # Normalizar URL
    scope_url = normalize_url(args.url)
    if not scope_url:
        console.print(f"[red]Error: URL inválida: {args.url}[/red]")
        sys.exit(1)
    
    console.print(f"\n[bold]Iniciando auditoría de:[/bold] {scope_url}\n")
    
    # Obtener información de identidad
    identity_info = get_identity_info(scope_url)
    
    # Crear crawler
    crawler = WebCrawler(
        scope_url=scope_url,
        max_pages=args.max_pages,
        max_requests=args.max_requests,
        delay=args.delay
    )
    
    # Ejecutar crawler
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Crawleando sitio...", total=None)
        responses = crawler.crawl()
        progress.update(task, completed=True)
    
    console.print(f"[green]✓[/green] Crawling completado: {len(responses)} páginas analizadas\n")
    
    # Ejecutar checks
    all_findings = []
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        # TLS
        task = progress.add_task("Verificando TLS/SSL...", total=None)
        tls_findings = check_tls(scope_url)
        all_findings.extend(tls_findings)
        progress.update(task, completed=True)
        
        # Headers
        task = progress.add_task("Verificando headers de seguridad...", total=None)
        headers_findings = check_security_headers(responses)
        all_findings.extend(headers_findings)
        progress.update(task, completed=True)
        
        # Cookies
        task = progress.add_task("Verificando cookies...", total=None)
        cookies_findings = check_cookies(responses)
        all_findings.extend(cookies_findings)
        progress.update(task, completed=True)
        
        # Formularios
        task = progress.add_task("Verificando formularios...", total=None)
        forms_findings = check_forms(responses)
        all_findings.extend(forms_findings)
        progress.update(task, completed=True)
        
        # Exposición de archivos
        task = progress.add_task("Verificando exposición de archivos...", total=None)
        exposure_findings = check_file_exposure(responses, scope_url)
        all_findings.extend(exposure_findings)
        progress.update(task, completed=True)
        
        # CORS
        task = progress.add_task("Verificando CORS...", total=None)
        cors_findings = check_cors(responses)
        all_findings.extend(cors_findings)
        progress.update(task, completed=True)
    
    console.print(f"[green]✓[/green] Verificaciones completadas: {len(all_findings)} hallazgos encontrados\n")
    
    # Obtener robots.txt
    robots_txt_content, robots_txt_url = crawler.get_robots_txt()
    
    # Generar reportes
    report_gen = ReportGenerator(args.out)
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        # Guardar evidencias
        task = progress.add_task("Guardando evidencias...", total=None)
        for i, response in enumerate(responses):
            report_gen.save_evidence(response, i)
        progress.update(task, completed=True)
        
        # Generar JSON
        task = progress.add_task("Generando reporte JSON...", total=None)
        json_path = report_gen.generate_json_report(
            scope_url=scope_url,
            responses=responses,
            findings=all_findings,
            identity_info=identity_info,
            robots_txt=robots_txt_content
        )
        progress.update(task, completed=True)
        
        # Generar Markdown
        task = progress.add_task("Generando reporte Markdown...", total=None)
        md_path = report_gen.generate_markdown_report(
            scope_url=scope_url,
            responses=responses,
            findings=all_findings,
            identity_info=identity_info,
            robots_txt=robots_txt_content
        )
        progress.update(task, completed=True)
    
    # Resumen en consola
    console.print("\n[bold]Resumen de Hallazgos:[/bold]\n")
    
    findings_by_severity = {
        'Critical': [],
        'High': [],
        'Medium': [],
        'Low': [],
        'Info': []
    }
    
    for finding in all_findings:
        severity = finding.get('severity', 'Info')
        findings_by_severity[severity].append(finding)
    
    table = Table(show_header=True, header_style="bold")
    table.add_column("Severidad", style="bold")
    table.add_column("Cantidad", justify="right")
    
    severity_order = ['Critical', 'High', 'Medium', 'Low', 'Info']
    severity_colors = {
        'Critical': 'red',
        'High': 'orange3',
        'Medium': 'yellow',
        'Low': 'blue',
        'Info': 'cyan'
    }
    
    for severity in severity_order:
        count = len(findings_by_severity[severity])
        color = severity_colors.get(severity, 'white')
        table.add_row(
            f"[{color}]{severity}[/{color}]",
            f"[{color}]{count}[/{color}]"
        )
    
    console.print(table)
    
    # Información de salida
    console.print(f"\n[bold green]✓ Auditoría completada[/bold green]\n")
    console.print(f"Reportes generados en: [cyan]{args.out}[/cyan]")
    console.print(f"  - [cyan]report.json[/cyan] - Reporte estructurado")
    console.print(f"  - [cyan]report.md[/cyan] - Reporte legible")
    console.print(f"  - [cyan]evidence/[/cyan] - Evidencias de requests\n")


if __name__ == '__main__':
    main()

