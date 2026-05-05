"""
Generación de reportes en JSON y Markdown
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path


class ReportGenerator:
    """Generador de reportes de auditoría"""
    
    def __init__(self, output_dir: str):
        """
        Args:
            output_dir: Directorio de salida para reportes
        """
        self.output_dir = Path(output_dir)
        self.evidence_dir = self.output_dir / 'evidence'
        
        # Crear directorios
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
    
    def save_evidence(self, response: Dict, index: int) -> str:
        """
        Guarda evidencia de una respuesta HTTP.
        
        Args:
            response: Datos de la respuesta
            index: Índice de la respuesta
            
        Returns:
            Ruta del archivo guardado
        """
        filename = f"response_{index:04d}.txt"
        filepath = self.evidence_dir / filename
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(f"URL: {response.get('url', 'N/A')}\n")
            f.write(f"Status Code: {response.get('status_code', 'N/A')}\n")
            f.write(f"Content-Type: {response.get('content_type', 'N/A')}\n")
            f.write(f"Size: {response.get('size', 0)} bytes\n")
            f.write(f"\n--- Headers ---\n")
            
            headers = response.get('headers', {})
            for key, value in sorted(headers.items()):
                # Limitar tamaño de valores de headers
                value_str = str(value)
                if len(value_str) > 500:
                    value_str = value_str[:500] + "... [truncado]"
                f.write(f"{key}: {value_str}\n")
            
            if response.get('content'):
                f.write(f"\n--- Content (snippet) ---\n")
                f.write(response['content'])
            
            if response.get('error'):
                f.write(f"\n--- Error ---\n")
                f.write(response['error'])
        
        return str(filepath)
    
    def generate_json_report(
        self,
        scope_url: str,
        responses: List[Dict],
        findings: List[Dict],
        identity_info: Dict,
        robots_txt: Optional[str]
    ) -> str:
        """
        Genera reporte en formato JSON.
        
        Args:
            scope_url: URL del scope auditado
            responses: Lista de respuestas HTTP
            findings: Lista de hallazgos
            identity_info: Información de identidad del objetivo
            robots_txt: Contenido de robots.txt si existe
            
        Returns:
            Ruta del archivo JSON generado
        """
        # Clasificar hallazgos por severidad
        findings_by_severity = {
            'Critical': [],
            'High': [],
            'Medium': [],
            'Low': [],
            'Info': []
        }
        
        for finding in findings:
            severity = finding.get('severity', 'Info')
            findings_by_severity[severity].append(finding)
        
        # Contar por tipo
        findings_by_type = {}
        for finding in findings:
            ftype = finding.get('type', 'unknown')
            findings_by_type[ftype] = findings_by_type.get(ftype, 0) + 1
        
        report = {
            'metadata': {
                'scope_url': scope_url,
                'scan_date': datetime.now().isoformat(),
                'tool_version': '1.0.0',
                'total_responses': len(responses),
                'total_findings': len(findings),
                'findings_summary': {
                    'critical': len(findings_by_severity['Critical']),
                    'high': len(findings_by_severity['High']),
                    'medium': len(findings_by_severity['Medium']),
                    'low': len(findings_by_severity['Low']),
                    'info': len(findings_by_severity['Info'])
                }
            },
            'identity': identity_info,
            'robots_txt': {
                'found': robots_txt is not None,
                'content': robots_txt if robots_txt else None
            },
            'responses': responses,
            'findings': findings,
            'findings_by_severity': findings_by_severity,
            'findings_by_type': findings_by_type
        }
        
        filepath = self.output_dir / 'report.json'
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return str(filepath)
    
    def generate_markdown_report(
        self,
        scope_url: str,
        responses: List[Dict],
        findings: List[Dict],
        identity_info: Dict,
        robots_txt: Optional[str]
    ) -> str:
        """
        Genera reporte en formato Markdown.
        
        Args:
            scope_url: URL del scope auditado
            responses: Lista de respuestas HTTP
            findings: Lista de hallazgos
            identity_info: Información de identidad del objetivo
            robots_txt: Contenido de robots.txt si existe
            
        Returns:
            Ruta del archivo Markdown generado
        """
        filepath = self.output_dir / 'report.md'
        
        with open(filepath, 'w', encoding='utf-8') as f:
            # Encabezado
            f.write("# Reporte de Auditoría de Seguridad\n\n")
            f.write(f"**Scope:** {scope_url}\n\n")
            f.write(f"**Fecha:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"**Herramienta:** web_audit_safe v1.0.0\n\n")
            f.write("---\n\n")
            
            # Resumen
            findings_by_severity = {
                'Critical': [],
                'High': [],
                'Medium': [],
                'Low': [],
                'Info': []
            }
            
            for finding in findings:
                severity = finding.get('severity', 'Info')
                findings_by_severity[severity].append(finding)
            
            f.write("## Resumen Ejecutivo\n\n")
            f.write(f"- **Total de páginas analizadas:** {len(responses)}\n")
            f.write(f"- **Total de hallazgos:** {len(findings)}\n")
            f.write(f"- **Críticos:** {len(findings_by_severity['Critical'])}\n")
            f.write(f"- **Altos:** {len(findings_by_severity['High'])}\n")
            f.write(f"- **Medios:** {len(findings_by_severity['Medium'])}\n")
            f.write(f"- **Bajos:** {len(findings_by_severity['Low'])}\n")
            f.write(f"- **Informativos:** {len(findings_by_severity['Info'])}\n\n")
            f.write("---\n\n")
            
            # Identidad del objetivo
            f.write("## Identidad del Objetivo\n\n")
            f.write(f"- **URL:** {scope_url}\n")
            if identity_info.get('ip'):
                f.write(f"- **IP:** {identity_info['ip']}\n")
            if identity_info.get('port'):
                f.write(f"- **Puerto:** {identity_info['port']}\n")
            if identity_info.get('scheme'):
                f.write(f"- **Scheme:** {identity_info['scheme']}\n")
            if identity_info.get('host'):
                f.write(f"- **Host:** {identity_info['host']}\n")
            f.write("\n---\n\n")
            
            # Robots.txt
            if robots_txt:
                f.write("## robots.txt\n\n")
                f.write("```\n")
                f.write(robots_txt[:2000])  # Limitar tamaño
                if len(robots_txt) > 2000:
                    f.write("\n... [truncado]")
                f.write("\n```\n\n")
                f.write("---\n\n")
            
            # Hallazgos por severidad
            severity_order = ['Critical', 'High', 'Medium', 'Low', 'Info']
            severity_emoji = {
                'Critical': '🔴',
                'High': '🟠',
                'Medium': '🟡',
                'Low': '🔵',
                'Info': 'ℹ️'
            }
            
            for severity in severity_order:
                severity_findings = findings_by_severity[severity]
                if not severity_findings:
                    continue
                
                emoji = severity_emoji.get(severity, '•')
                f.write(f"## {emoji} Hallazgos - Severidad {severity}\n\n")
                
                for i, finding in enumerate(severity_findings, 1):
                    f.write(f"### {i}. {finding.get('title', 'Sin título')}\n\n")
                    f.write(f"**Tipo:** `{finding.get('type', 'unknown')}`\n\n")
                    f.write(f"**Descripción:** {finding.get('description', 'N/A')}\n\n")
                    f.write(f"**Recomendación:** {finding.get('recommendation', 'N/A')}\n\n")
                    
                    # Evidencia
                    evidence = finding.get('evidence', {})
                    if evidence:
                        f.write("**Evidencia:**\n\n")
                        f.write("```json\n")
                        f.write(json.dumps(evidence, indent=2, ensure_ascii=False))
                        f.write("\n```\n\n")
                    
                    f.write("---\n\n")
            
            # Tabla de hallazgos
            f.write("## Tabla de Hallazgos\n\n")
            f.write("| Severidad | Tipo | Título | URL |\n")
            f.write("|-----------|------|--------|-----|\n")
            
            for finding in sorted(findings, key=lambda x: {
                'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4
            }.get(x.get('severity', 'Info'), 4)):
                severity = finding.get('severity', 'Info')
                ftype = finding.get('type', 'unknown')
                title = finding.get('title', 'Sin título').replace('|', '\\|')
                evidence = finding.get('evidence', {})
                url = evidence.get('url', 'N/A') if evidence else 'N/A'
                
                f.write(f"| {severity} | `{ftype}` | {title} | {url} |\n")
            
            f.write("\n---\n\n")
            
            # Páginas analizadas
            f.write("## Páginas Analizadas\n\n")
            f.write(f"Total: {len(responses)}\n\n")
            f.write("| URL | Status | Content-Type | Size |\n")
            f.write("|-----|--------|--------------|------|\n")
            
            for response in responses[:50]:  # Limitar a 50 para no hacer el reporte muy largo
                url = response.get('url', 'N/A')
                status = response.get('status_code', 'N/A')
                content_type = response.get('content_type', 'N/A')[:50]
                size = response.get('size', 0)
                
                f.write(f"| {url} | {status} | {content_type} | {size} bytes |\n")
            
            if len(responses) > 50:
                f.write(f"\n*... y {len(responses) - 50} páginas más*\n")
            
            f.write("\n---\n\n")
            f.write("## Notas\n\n")
            f.write("- Este reporte fue generado mediante auditoría **pasiva** (no intrusiva)\n")
            f.write("- No se enviaron payloads ofensivos ni se intentó explotar vulnerabilidades\n")
            f.write("- Los hallazgos se basan en análisis de headers, configuración y exposición de archivos\n")
            f.write("- Se recomienda revisar manualmente los hallazgos antes de tomar acciones correctivas\n\n")
        
        return str(filepath)

