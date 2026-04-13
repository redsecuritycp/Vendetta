"""
Motor de templates YAML estilo Nuclei para checks de seguridad custom
"""

import re
import requests
from typing import Dict, List, Optional
from dataclasses import dataclass, field


@dataclass
class TemplateMatch:
    """Un match de template"""
    template_id: str
    template_name: str
    severity: str
    matched_at: str
    evidence: str
    description: str


@dataclass
class Template:
    """Template de check de seguridad"""
    id: str
    name: str
    severity: str  # critico, alto, medio, bajo, info
    description: str
    method: str = "GET"
    path: str = "/"
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    matchers: List[Dict] = field(default_factory=list)
    # matcher types: status, word, regex, header
    # matcher example: {"type": "status", "values": [200]}
    # matcher example: {"type": "word", "values": ["phpinfo"], "part": "body"}
    # matcher example: {"type": "regex", "values": ["version.*[0-9]"], "part": "body"}
    # matcher example: {"type": "header", "key": "X-Powered-By", "values": ["PHP"]}

    @classmethod
    def from_dict(cls, data: Dict) -> 'Template':
        return cls(
            id=data.get("id", "unknown"),
            name=data.get("name", "Unknown Check"),
            severity=data.get("severity", "info"),
            description=data.get("description", ""),
            method=data.get("method", "GET"),
            path=data.get("path", "/"),
            headers=data.get("headers", {}),
            body=data.get("body", ""),
            matchers=data.get("matchers", []),
        )


# Templates predefinidos
BUILTIN_TEMPLATES = [
    {
        "id": "exposed-phpinfo",
        "name": "phpinfo() expuesto",
        "severity": "alto",
        "description": "El archivo phpinfo.php esta accesible y expone informacion sensible del servidor.",
        "path": "/phpinfo.php",
        "matchers": [
            {"type": "status", "values": [200]},
            {"type": "word", "values": ["phpinfo()"], "part": "body"},
        ],
    },
    {
        "id": "exposed-env",
        "name": "Archivo .env expuesto",
        "severity": "critico",
        "description": "El archivo .env esta accesible y puede contener credenciales.",
        "path": "/.env",
        "matchers": [
            {"type": "status", "values": [200]},
            {"type": "word", "values": ["DB_PASSWORD", "APP_KEY", "SECRET"], "part": "body"},
        ],
    },
    {
        "id": "git-config",
        "name": "Repositorio .git expuesto",
        "severity": "critico",
        "description": "El directorio .git esta accesible, permitiendo descargar codigo fuente.",
        "path": "/.git/config",
        "matchers": [
            {"type": "status", "values": [200]},
            {"type": "word", "values": ["[core]", "[remote"], "part": "body"},
        ],
    },
    {
        "id": "wp-config-backup",
        "name": "Backup de wp-config.php",
        "severity": "critico",
        "description": "Un backup del archivo de configuracion de WordPress es accesible.",
        "path": "/wp-config.php.bak",
        "matchers": [
            {"type": "status", "values": [200]},
            {"type": "word", "values": ["DB_NAME", "DB_PASSWORD"], "part": "body"},
        ],
    },
    {
        "id": "directory-listing",
        "name": "Directory listing habilitado",
        "severity": "medio",
        "description": "El servidor permite listar el contenido de directorios.",
        "path": "/",
        "matchers": [
            {"type": "status", "values": [200]},
            {"type": "word", "values": ["Index of /", "Directory listing"], "part": "body"},
        ],
    },
    {
        "id": "server-status",
        "name": "Apache server-status expuesto",
        "severity": "alto",
        "description": "La pagina server-status de Apache esta accesible publicamente.",
        "path": "/server-status",
        "matchers": [
            {"type": "status", "values": [200]},
            {"type": "word", "values": ["Apache Server Status", "Server Version"], "part": "body"},
        ],
    },
    {
        "id": "swagger-ui",
        "name": "Swagger UI accesible",
        "severity": "medio",
        "description": "La documentacion de la API (Swagger) esta accesible publicamente.",
        "path": "/swagger/",
        "matchers": [
            {"type": "status", "values": [200]},
            {"type": "word", "values": ["swagger", "api-docs"], "part": "body"},
        ],
    },
    {
        "id": "graphql-introspection",
        "name": "GraphQL introspection habilitada",
        "severity": "medio",
        "description": "El endpoint GraphQL permite introspection, revelando el schema completo.",
        "method": "POST",
        "path": "/graphql",
        "headers": {"Content-Type": "application/json"},
        "body": '{"query":"{ __schema { types { name } } }"}',
        "matchers": [
            {"type": "status", "values": [200]},
            {"type": "word", "values": ["__schema", "__type"], "part": "body"},
        ],
    },
    {
        "id": "cors-wildcard",
        "name": "CORS con wildcard",
        "severity": "medio",
        "description": "El servidor responde con Access-Control-Allow-Origin: * permitiendo requests desde cualquier origen.",
        "path": "/",
        "matchers": [
            {"type": "header", "key": "Access-Control-Allow-Origin", "values": ["*"]},
        ],
    },
    {
        "id": "x-powered-by",
        "name": "Header X-Powered-By presente",
        "severity": "bajo",
        "description": "El servidor expone la tecnologia backend via X-Powered-By.",
        "path": "/",
        "matchers": [
            {"type": "header", "key": "X-Powered-By", "values": [".*"]},
        ],
    },
    {
        "id": "admin-panel-open",
        "name": "Panel de administracion accesible",
        "severity": "alto",
        "description": "Se encontro un panel de administracion accesible sin restriccion.",
        "path": "/admin/",
        "matchers": [
            {"type": "status", "values": [200]},
            {"type": "word", "values": ["admin", "login", "dashboard", "panel"], "part": "body"},
        ],
    },
    {
        "id": "debug-mode",
        "name": "Modo debug habilitado",
        "severity": "alto",
        "description": "La aplicacion esta corriendo en modo debug, exponiendo informacion interna.",
        "path": "/",
        "matchers": [
            {"type": "word", "values": ["Traceback", "DEBUG = True", "stack trace", "DJANGO_SETTINGS"], "part": "body"},
        ],
    },
]


class TemplateEngine:
    """Ejecuta templates contra un objetivo"""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Vendetta-TemplateEngine/1.0"
        })
        self.session.verify = False
        requests.packages.urllib3.disable_warnings()

    def load_templates(self, custom_templates: Optional[List[Dict]] = None) -> List[Template]:
        """Carga templates builtin + custom"""
        templates = [Template.from_dict(t) for t in BUILTIN_TEMPLATES]
        if custom_templates:
            for ct in custom_templates:
                templates.append(Template.from_dict(ct))
        return templates

    def _check_matcher(self, matcher: Dict, response: requests.Response) -> bool:
        """Verifica si un matcher hace match"""
        mtype = matcher.get("type", "")
        values = matcher.get("values", [])

        if mtype == "status":
            return response.status_code in values

        elif mtype == "word":
            part = matcher.get("part", "body")
            text = response.text if part == "body" else str(response.headers)
            return any(v.lower() in text.lower() for v in values)

        elif mtype == "regex":
            part = matcher.get("part", "body")
            text = response.text if part == "body" else str(response.headers)
            return any(re.search(v, text, re.IGNORECASE) for v in values)

        elif mtype == "header":
            key = matcher.get("key", "")
            header_val = response.headers.get(key, "")
            if not header_val:
                return False
            return any(re.search(v, header_val, re.IGNORECASE) for v in values)

        return False

    def run_template(self, template: Template, base_url: str) -> Optional[TemplateMatch]:
        """Ejecuta un template contra la URL"""
        url = base_url.rstrip("/") + template.path

        try:
            if template.method.upper() == "POST":
                resp = self.session.post(
                    url, headers=template.headers,
                    data=template.body, timeout=self.timeout,
                    allow_redirects=True
                )
            else:
                resp = self.session.get(
                    url, headers=template.headers,
                    timeout=self.timeout, allow_redirects=True
                )

            # Todos los matchers deben coincidir (AND logic)
            all_match = all(
                self._check_matcher(m, resp) for m in template.matchers
            )

            if all_match and template.matchers:
                evidence_parts = [f"URL: {url}", f"Status: {resp.status_code}"]
                if resp.text:
                    preview = resp.text[:300].strip()
                    evidence_parts.append(f"Body preview: {preview}")

                return TemplateMatch(
                    template_id=template.id,
                    template_name=template.name,
                    severity=template.severity,
                    matched_at=url,
                    evidence="\n".join(evidence_parts),
                    description=template.description,
                )

        except Exception:
            pass

        return None

    def scan(self, base_url: str,
             custom_templates: Optional[List[Dict]] = None,
             template_ids: Optional[List[str]] = None) -> List[TemplateMatch]:
        """
        Ejecuta todos los templates contra un objetivo

        Args:
            base_url: URL base
            custom_templates: Templates custom adicionales
            template_ids: Si se especifica, solo ejecuta estos IDs
        """
        templates = self.load_templates(custom_templates)

        if template_ids:
            templates = [t for t in templates if t.id in template_ids]

        matches = []
        for template in templates:
            match = self.run_template(template, base_url)
            if match:
                matches.append(match)

        return matches
