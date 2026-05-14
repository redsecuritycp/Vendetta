# modules/templates

Motor de **templates declarativos** (estilo Nuclei) para checks de seguridad custom contra una URL.

## Qué hace

Carga un set de **templates builtin** (12 checks: `exposed-phpinfo`, `exposed-env`, `git-config`, `wp-config-backup`, `directory-listing`, `server-status`, `swagger-ui`, `graphql-introspection`, `cors-wildcard`, `x-powered-by`, `admin-panel-open`, `debug-mode`) más cualquier template custom que pase el cliente. Cada template define `method` + `path` + `headers` + `body` + `matchers`. El engine hace el request y devuelve un match si **todos** los matchers (AND logic) son verdaderos.

Tipos de matcher soportados: `status`, `word` (en body o headers), `regex` (en body o headers), `header` (por key específica).

## Interfaz pública

### Como librería

```python
from modules.templates import TemplateEngine, TemplateMatch

engine = TemplateEngine()
matches = engine.scan(
    "https://example.com",
    custom_templates=[{...}],     # opcional
    template_ids=["exposed-env"], # opcional, filtra por id
)
for m in matches:
    print(m.template_id, m.severity, m.matched_at)
```

### Como blueprint Flask

```python
from modules.templates.routes import bp as templates_bp
app.register_blueprint(templates_bp)
```

Endpoint registrado: `POST /api/templates`

```bash
curl -X POST https://vendetta-arm.duckdns.org/api/templates \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com","template_ids":["exposed-env"]}'
```

Respuesta: `{ "target": "...", "matches": [...], "total": N }`

## Estructura del módulo

```
modules/templates/
├── __init__.py       ← exporta TemplateEngine, Template, TemplateMatch, BUILTIN_TEMPLATES
├── engine.py         ← lógica del motor (movida de template_engine.py)
├── routes.py         ← blueprint Flask con POST /api/templates
└── README.md
```

## Retro-compatibilidad

`template_engine.py` en la raíz queda como **wrapper deprecated** que reexporta `TemplateEngine`, `Template`, `TemplateMatch`, `BUILTIN_TEMPLATES` desde este módulo. Existe para no romper imports legacy (`from template_engine import TemplateEngine`). Se borra en 2-4 semanas.

## Cómo desinstalar

1. Quitar `app.register_blueprint(templates_bp)` de `api_server.py`.
2. Borrar `modules/templates/`.
3. (Opcional) borrar `template_engine.py` wrapper si ningún otro caller lo usa.

## Dependencias

- `requests` (HTTP client)
- `flask` (sólo `routes.py`)

Sin dependencias internas de otros módulos.
