"""
API REST para lanzar scans programaticamente
Corre en paralelo con Streamlit
"""

from flask import Flask, jsonify, request
from typing import Dict
import threading
import json

from full_scan import FullScanner
from report_generator import ReportGenerator
from db_manager import DBManager

from modules.templates.routes import bp as templates_bp

app = Flask(__name__)
db = DBManager()

# Blueprints modulares (Fase 12+)
app.register_blueprint(templates_bp)


@app.route("/", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "vendetta-api"}), 200


@app.route("/api/scan", methods=["POST"])
def start_scan():
    """Lanza un full scan"""
    data = request.get_json() or {}
    url = data.get("url", "")
    if not url:
        return jsonify({"error": "Falta parametro 'url'"}), 400

    skip = data.get("skip_tools", [])
    xss_url = data.get("xss_test_url", "")
    bypass_paths = data.get("bypass_paths", [])

    scanner = FullScanner()
    report = scanner.scan(url, skip_tools=skip, xss_test_url=xss_url, bypass_paths=bypass_paths)

    gen = ReportGenerator()
    html = gen.generate_html(report)

    report._update_summary()
    scan_id = db.save_scan(
        target=url,
        risk_score=report.get_risk_score(),
        summary=report.summary,
        tools_used=report.tools_used,
        duration=report.duration,
        report_json=report.to_json(),
        report_html=html,
    )

    return jsonify({
        "scan_id": scan_id,
        "target": url,
        "risk_score": report.get_risk_score(),
        "summary": report.summary,
        "findings_count": len(report.findings),
        "duration": report.duration,
    }), 200


@app.route("/api/scans", methods=["GET"])
def list_scans():
    """Lista scans guardados"""
    target = request.args.get("target", None)
    limit = int(request.args.get("limit", 50))
    scans = db.get_scans(target=target, limit=limit)
    return jsonify({"scans": scans}), 200


@app.route("/api/scans/<int:scan_id>", methods=["GET"])
def get_scan(scan_id: int):
    """Obtiene detalle de un scan"""
    scan = db.get_scan_report(scan_id)
    if not scan:
        return jsonify({"error": "Scan no encontrado"}), 404
    # No enviar HTML completo por API, solo JSON
    result = {k: v for k, v in scan.items() if k != "report_html"}
    return jsonify(result), 200


@app.route("/api/scans/<int:scan_id>/report", methods=["GET"])
def get_report_html(scan_id: int):
    """Obtiene reporte HTML de un scan"""
    scan = db.get_scan_report(scan_id)
    if not scan:
        return jsonify({"error": "Scan no encontrado"}), 404
    return scan.get("report_html", ""), 200, {"Content-Type": "text/html"}


@app.route("/api/targets", methods=["GET"])
def list_targets():
    """Lista targets escaneados"""
    targets = db.get_targets()
    return jsonify({"targets": targets}), 200


def run_api(port: int = 8080):
    """Corre la API en un thread separado"""
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)


def start_api_thread(port: int = 8080):
    """Inicia la API en background"""
    thread = threading.Thread(target=run_api, args=(port,), daemon=True)
    thread.start()
    return thread


if __name__ == "__main__":
    import os
    port = int(os.environ.get("VENDETTA_API_PORT", "3004"))
    host = os.environ.get("VENDETTA_API_HOST", "0.0.0.0")
    print(f"[vendetta-api] arrancando en {host}:{port}", flush=True)
    app.run(host=host, port=port, debug=False, use_reloader=False)
