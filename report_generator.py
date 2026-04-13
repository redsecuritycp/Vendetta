"""
Generador de reportes profesionales HTML para auditorias de seguridad
"""

import json
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict


@dataclass
class Finding:
    """Un hallazgo individual de seguridad"""
    tool: str
    title: str
    severity: str  # critico, alto, medio, bajo, info
    description: str
    evidence: str = ""
    recommendation: str = ""
    cvss_approx: float = 0.0


@dataclass
class ScanReport:
    """Reporte completo de un scan"""
    target: str
    scan_date: str = ""
    duration: float = 0.0
    findings: List[Finding] = field(default_factory=list)
    tools_used: List[str] = field(default_factory=list)
    summary: Dict[str, int] = field(default_factory=dict)
    raw_results: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.scan_date:
            self.scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def add_finding(self, finding: Finding):
        self.findings.append(finding)
        self._update_summary()

    def _update_summary(self):
        self.summary = {"critico": 0, "alto": 0, "medio": 0, "bajo": 0, "info": 0}
        for f in self.findings:
            if f.severity in self.summary:
                self.summary[f.severity] += 1

    def get_risk_score(self) -> int:
        """Score de 0-100 basado en hallazgos"""
        weights = {"critico": 25, "alto": 15, "medio": 8, "bajo": 3, "info": 0}
        score = 0
        for f in self.findings:
            score += weights.get(f.severity, 0)
        return min(score, 100)

    def to_json(self) -> str:
        self._update_summary()
        data = {
            "target": self.target,
            "scan_date": self.scan_date,
            "duration": self.duration,
            "risk_score": self.get_risk_score(),
            "summary": self.summary,
            "tools_used": self.tools_used,
            "findings": [asdict(f) for f in self.findings],
        }
        return json.dumps(data, indent=2, ensure_ascii=False)


class ReportGenerator:
    """Genera reportes HTML profesionales"""

    SEVERITY_COLORS = {
        "critico": "#dc2626",
        "alto": "#ea580c",
        "medio": "#d97706",
        "bajo": "#2563eb",
        "info": "#6b7280",
    }

    SEVERITY_LABELS = {
        "critico": "CRITICO",
        "alto": "ALTO",
        "medio": "MEDIO",
        "bajo": "BAJO",
        "info": "INFO",
    }

    def generate_html(self, report: ScanReport) -> str:
        """Genera reporte HTML profesional descargable"""
        report._update_summary()
        score = report.get_risk_score()

        if score >= 70:
            score_color = "#dc2626"
            score_label = "CRITICO"
        elif score >= 40:
            score_color = "#ea580c"
            score_label = "ALTO"
        elif score >= 20:
            score_color = "#d97706"
            score_label = "MEDIO"
        elif score > 0:
            score_color = "#2563eb"
            score_label = "BAJO"
        else:
            score_color = "#16a34a"
            score_label = "SEGURO"

        findings_html = ""
        for i, f in enumerate(report.findings, 1):
            color = self.SEVERITY_COLORS.get(f.severity, "#6b7280")
            label = self.SEVERITY_LABELS.get(f.severity, "INFO")
            evidence_html = f'<div class="evidence"><strong>Evidencia:</strong><pre>{self._escape(f.evidence)}</pre></div>' if f.evidence else ""
            findings_html += f'''
            <div class="finding" style="border-left: 4px solid {color};">
                <div class="finding-header">
                    <span class="severity-badge" style="background:{color};">{label}</span>
                    <span class="finding-title">#{i} {self._escape(f.title)}</span>
                    <span class="finding-tool">{self._escape(f.tool)}</span>
                </div>
                <div class="finding-body">
                    <p>{self._escape(f.description)}</p>
                    {evidence_html}
                    {f'<div class="recommendation"><strong>Recomendacion:</strong> {self._escape(f.recommendation)}</div>' if f.recommendation else ''}
                </div>
            </div>
            '''

        summary_bars = ""
        for sev in ["critico", "alto", "medio", "bajo", "info"]:
            count = report.summary.get(sev, 0)
            color = self.SEVERITY_COLORS[sev]
            label = self.SEVERITY_LABELS[sev]
            summary_bars += f'''
            <div class="summary-item">
                <span class="summary-label" style="color:{color};">{label}</span>
                <span class="summary-count" style="background:{color};">{count}</span>
            </div>
            '''

        tools_html = ", ".join(report.tools_used) if report.tools_used else "N/A"

        return f'''<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte de Seguridad - {self._escape(report.target)}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background: #f8fafc; color: #1e293b; line-height: 1.6; }}
        .header {{ background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%); color: white; padding: 40px; }}
        .header h1 {{ font-size: 28px; margin-bottom: 5px; }}
        .header .subtitle {{ color: #94a3b8; font-size: 14px; }}
        .header .meta {{ display: flex; gap: 30px; margin-top: 20px; font-size: 13px; color: #cbd5e1; }}
        .container {{ max-width: 1000px; margin: 0 auto; padding: 30px; }}
        .score-card {{ background: white; border-radius: 12px; padding: 30px; margin: -30px auto 30px; max-width: 1000px; box-shadow: 0 4px 24px rgba(0,0,0,0.08); display: flex; align-items: center; gap: 30px; }}
        .score-circle {{ width: 100px; height: 100px; border-radius: 50%; display: flex; flex-direction: column; align-items: center; justify-content: center; color: white; font-weight: bold; flex-shrink: 0; }}
        .score-number {{ font-size: 32px; line-height: 1; }}
        .score-label {{ font-size: 11px; margin-top: 4px; }}
        .summary-items {{ display: flex; gap: 15px; flex-wrap: wrap; }}
        .summary-item {{ display: flex; align-items: center; gap: 8px; }}
        .summary-label {{ font-weight: 600; font-size: 13px; min-width: 65px; }}
        .summary-count {{ color: white; padding: 2px 12px; border-radius: 12px; font-weight: bold; font-size: 14px; min-width: 30px; text-align: center; }}
        .section {{ margin-bottom: 30px; }}
        .section h2 {{ font-size: 20px; margin-bottom: 15px; padding-bottom: 8px; border-bottom: 2px solid #e2e8f0; }}
        .finding {{ background: white; border-radius: 8px; margin-bottom: 15px; box-shadow: 0 1px 3px rgba(0,0,0,0.06); overflow: hidden; }}
        .finding-header {{ padding: 15px 20px; display: flex; align-items: center; gap: 12px; background: #f8fafc; }}
        .severity-badge {{ color: white; padding: 3px 10px; border-radius: 4px; font-size: 11px; font-weight: bold; letter-spacing: 0.5px; }}
        .finding-title {{ font-weight: 600; flex: 1; }}
        .finding-tool {{ color: #64748b; font-size: 12px; background: #e2e8f0; padding: 2px 8px; border-radius: 4px; }}
        .finding-body {{ padding: 15px 20px; }}
        .finding-body p {{ margin-bottom: 10px; }}
        .evidence {{ background: #f1f5f9; border-radius: 6px; padding: 12px; margin: 10px 0; }}
        .evidence pre {{ white-space: pre-wrap; word-break: break-all; font-size: 12px; margin-top: 8px; color: #334155; }}
        .recommendation {{ background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 6px; padding: 12px; margin-top: 10px; color: #166534; }}
        .footer {{ text-align: center; padding: 30px; color: #94a3b8; font-size: 12px; border-top: 1px solid #e2e8f0; }}
        @media print {{
            body {{ background: white; }}
            .header {{ padding: 20px; }}
            .finding {{ break-inside: avoid; }}
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Reporte de Auditoria de Seguridad</h1>
        <div class="subtitle">Generado por Vendetta Security Suite</div>
        <div class="meta">
            <span>Objetivo: {self._escape(report.target)}</span>
            <span>Fecha: {report.scan_date}</span>
            <span>Duracion: {report.duration:.1f}s</span>
            <span>Herramientas: {self._escape(tools_html)}</span>
        </div>
    </div>
    <div class="container">
        <div class="score-card">
            <div class="score-circle" style="background:{score_color};">
                <div class="score-number">{score}</div>
                <div class="score-label">{score_label}</div>
            </div>
            <div>
                <h3 style="margin-bottom:10px;">Resumen de Hallazgos</h3>
                <div class="summary-items">{summary_bars}</div>
            </div>
        </div>

        <div class="section">
            <h2>Hallazgos Detallados ({len(report.findings)})</h2>
            {findings_html if findings_html else '<p style="color:#64748b;">No se encontraron hallazgos.</p>'}
        </div>
    </div>
    <div class="footer">
        Vendetta Security Suite &mdash; Reporte generado el {report.scan_date}<br>
        Solo para uso autorizado. Distribucion restringida.
    </div>
</body>
</html>'''

    def _escape(self, text: str) -> str:
        if not text:
            return ""
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
