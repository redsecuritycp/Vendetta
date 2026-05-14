"""
Blueprint Flask para el módulo templates.

Endpoint:
    POST /api/templates — ejecuta builtin + custom templates contra una URL.

Movido desde `api_server.py` en Fase 12 del MODULAR_PLAN.md (2026-05-14).
"""

from flask import Blueprint, jsonify, request

from .engine import TemplateEngine


bp = Blueprint("templates", __name__)


@bp.route("/api/templates", methods=["POST"])
def run_templates():
    """Ejecuta templates contra un objetivo"""
    data = request.get_json() or {}
    url = data.get("url", "")
    if not url:
        return jsonify({"error": "Falta parametro 'url'"}), 400

    custom = data.get("custom_templates", [])
    ids = data.get("template_ids", None)

    engine = TemplateEngine()
    matches = engine.scan(url, custom_templates=custom, template_ids=ids)

    return jsonify({
        "target": url,
        "matches": [
            {
                "id": m.template_id,
                "name": m.template_name,
                "severity": m.severity,
                "url": m.matched_at,
                "description": m.description,
            }
            for m in matches
        ],
        "total": len(matches),
    }), 200
