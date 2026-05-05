# web_audit_safe

Herramienta de auditoría de seguridad **PASIVA** para aplicaciones web. Realiza análisis no intrusivos sin enviar payloads ofensivos, sin fuerza bruta, sin fuzzing agresivo ni bypass de autenticación.

## ⚠️ ADVERTENCIA LEGAL

**IMPORTANTE**: Esta herramienta está diseñada para uso ético y legal únicamente. 

- **Solo utilice esta herramienta en sistemas que posea o tenga autorización explícita por escrito para auditar.**
- El uso no autorizado de herramientas de seguridad puede violar leyes locales, estatales y federales.
- El usuario es el único responsable del uso de esta herramienta.
- Los desarrolladores no se hacen responsables del uso indebido de esta herramienta.

**Use bajo su propio riesgo y responsabilidad.**

## Características

- ✅ Auditoría **100% pasiva** (sin payloads ofensivos)
- ✅ Análisis de headers de seguridad HTTP
- ✅ Verificación de certificados TLS/SSL
- ✅ Detección de cookies inseguras
- ✅ Análisis de formularios y protección CSRF
- ✅ Detección de archivos expuestos
- ✅ Fingerprinting de tecnología
- ✅ Análisis CORS
- ✅ Respeta robots.txt y rate limiting
- ✅ Genera reportes en JSON y Markdown

## Instalación

```bash
# Clonar o descargar el proyecto
cd web_audit_safe

# Instalar dependencias
pip install -e .

# O usando requirements.txt
pip install -r requirements.txt
```

## Uso

### Uso básico

```bash
python -m web_audit_safe --url "https://example.com" --out ./output
```

### Opciones disponibles

```bash
python -m web_audit_safe \
    --url "https://example.com" \
    --out ./output \
    --max-pages 20 \
    --max-requests 200 \
    --delay 1.0
```

**Parámetros:**
- `--url`: URL objetivo a auditar (requerido)
- `--out`: Directorio de salida para reportes (default: `./output`)
- `--max-pages`: Máximo de páginas a analizar (default: 20)
- `--max-requests`: Máximo de requests totales (default: 200)
- `--delay`: Delay entre requests en segundos (default: 1.0)

## Checks Realizados

### 1. Identidad del Objetivo
- Normalización de URL y host
- Resolución de IP
- Detección de puertos
- Seguimiento de redirects (máx 5)

### 2. TLS/SSL
- Versión TLS negociada
- Información del certificado (issuer, sujeto, SAN)
- Fecha de vencimiento y días restantes
- Alerta si expira en <30 días

### 3. HTTP Security Headers
- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-Frame-Options / frame-ancestors
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- Cross-Origin-Policy headers
- Cache-Control en páginas sensibles

### 4. Cookies
- Verificación de flags: Secure, HttpOnly, SameSite
- Detección de cookies de sesión sin protección adecuada

### 5. Formularios
- Detección de métodos HTTP (GET vs POST)
- Señalamiento de formularios con GET para datos sensibles
- Detección heurística de tokens CSRF
- Análisis de campos de contraseña

### 6. Exposición de Archivos
- Verificación de archivos comunes: robots.txt, sitemap.xml
- Verificación de .well-known/security.txt
- Detección de archivos sensibles: .git, .env, backups

### 7. Tech Fingerprinting
- Headers Server y X-Powered-By
- Meta generator tags
- Hints de frameworks por rutas/headers

### 8. CORS
- Análisis de Access-Control-Allow-Origin
- Detección de configuraciones inseguras

## Estructura de Salida

```
output/
├── report.json          # Reporte estructurado en JSON
├── report.md            # Reporte legible en Markdown
└── evidence/            # Evidencias de requests
    ├── headers_*.txt    # Headers capturados
    └── responses_*.txt  # Snippets de respuestas
```

## Limitaciones de Seguridad

- **Rate limiting**: Máximo 1 request/segundo por host
- **Timeout**: 10 segundos por request
- **Retries**: 1 intento adicional
- **Tamaño máximo**: No descarga archivos >5MB
- **Redirects**: Máximo 5 seguimientos
- **Scope**: Solo analiza el mismo host y dominio especificado

## Requisitos

- Python 3.11 o superior
- Conexión a Internet (para análisis de URLs externas)

## Desarrollo

### Ejecutar tests

```bash
python -m pytest tests/
```

### Estructura del proyecto

```
web_audit_safe/
├── src/web_audit_safe/
│   ├── __init__.py
│   ├── cli.py           # Interfaz de línea de comandos
│   ├── crawler.py       # Crawler BFS
│   ├── report.py        # Generación de reportes
│   ├── utils.py         # Utilidades
│   └── checks/
│       ├── __init__.py
│       ├── headers.py   # Análisis de headers
│       ├── tls.py       # Análisis TLS/SSL
│       ├── cookies.py   # Análisis de cookies
│       ├── exposure.py  # Archivos expuestos
│       ├── forms.py     # Análisis de formularios
│       └── cors.py      # Análisis CORS
├── tests/               # Tests unitarios
├── pyproject.toml
└── README.md
```

## Licencia

MIT License - Ver archivo LICENSE para más detalles.

## Contribuciones

Las contribuciones son bienvenidas. Por favor, asegúrese de que cualquier cambio mantenga el carácter no intrusivo de la herramienta.

## Contacto

Para reportar problemas o sugerencias, por favor abra un issue en el repositorio.

