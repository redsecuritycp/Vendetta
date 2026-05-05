# Reporte de Auditoría de Seguridad

**Scope:** https://diaz.gob.ar/

**Fecha:** 2025-12-30 18:18:54

**Herramienta:** web_audit_safe v1.0.0

---

## Resumen Ejecutivo

- **Total de páginas analizadas:** 1
- **Total de hallazgos:** 10
- **Críticos:** 0
- **Altos:** 1
- **Medios:** 2
- **Bajos:** 4
- **Informativos:** 3

---

## Identidad del Objetivo

- **URL:** https://diaz.gob.ar/
- **IP:** 104.21.38.20
- **Puerto:** 443
- **Scheme:** https
- **Host:** diaz.gob.ar

---

## robots.txt

```
User-agent: *
Disallow:
Crawl-delay: 60 # 60 segundos entre cada request
Visit-time: 0300-1200 # 00:00 AM a 09:00 AM (America/Argentina/Buenos_Aires)
Request-rate: 6/60m # permite indexar 6 documentos cada 60 minutos
Request-rate: 3/60m 1200-0300 # permite indexar 3 documentos cada 60 minutos entre las 09:00 AM a 00:00 AM (America/Argentina/Buenos_Aires)

Disallow: /cgi-bin/
Disallow: /admin/
Disallow: /*.sql$

# Bloqueo de las URL dinamicas
Disallow: /*?

# Bloqueo de busquedas
Disallow: /?s=
Disallow: /search

# Bloqueo de trackbacks
Disallow: /trackback
Disallow: /*trackback
Disallow: /*trackback*
Disallow: /*/trackback

# Permitir Google Webmaster Tool
User-agent: Googlebot
Allow: /*.js$
Allow: /*.css$

# wordpress
Disallow: /xmlrpc.php
Disallow: /wp-admin/
Disallow: /wp-includes/
Disallow: /wp-content/plugins/
Disallow: /wp-content/cache/
Disallow: /wp-content/themes/

Disallow: /*/xmlrpc.php
Disallow: /*/wp-admin/
Disallow: /*/wp-includes/
Disallow: /*/wp-content/plugins/
Disallow: /*/wp-content/cache/
Disallow: /*/wp-content/themes/

# joomla
Disallow: /administrator/
Disallow: /bin/
Disallow: /cache/
Disallow: /cli/
Disallow: /components/
Disallow: /images/
Disallow: /includes/
Disallow: /installation/
Disallow: /language/
Disallow: /layouts/
Disallow: /libraries/
Disallow: /logs/
Disallow: /media/
Disallow: /modules/
Disallow: /plugins/
Disallow: /templates/
Disallow: /tmp/

Disallow: /*/administrator/
Disallow: /*/bin/
Disallow: /*/cache/
Disallow: /*/cli/
Disallow: /*/components/
Disallow: /*/images/
Disallow: /*/includes/
Disallow: /*/installation/
Disallow: /*/language/
Disallow: /*/layouts/
Disallow: /*/libraries/
Disallow: /*/logs/
Disallow: /*/media/
Disallow: /*/modules/
Disallow: /*/plugins/
Disallow: /*/templates/
Disallow: /*/tmp/


```

---

## 🟠 Hallazgos - Severidad High

### 1. Falta header de seguridad: HSTS

**Tipo:** `missing_security_header`

**Descripción:** Strict-Transport-Security (HSTS) no está presente en https://diaz.gob.ar/

**Recomendación:** Agregar header Strict-Transport-Security con max-age>=31536000 e includeSubDomains

**Evidencia:**

```json
{
  "url": "https://diaz.gob.ar/",
  "missing_header": "Strict-Transport-Security",
  "all_headers": [
    "Date",
    "Content-Type",
    "Connection",
    "x-powered-by",
    "link",
    "x-tec-api-version",
    "x-tec-api-root",
    "x-tec-api-origin",
    "Server",
    "cf-cache-status",
    "Server-Timing",
    "Report-To",
    "Nel",
    "Content-Encoding",
    "CF-RAY",
    "alt-svc"
  ]
}
```

---

## 🟡 Hallazgos - Severidad Medium

### 1. Falta header de seguridad: CSP

**Tipo:** `missing_security_header`

**Descripción:** Content-Security-Policy (CSP) no está presente en https://diaz.gob.ar/

**Recomendación:** Implementar CSP para prevenir XSS y otros ataques de inyección

**Evidencia:**

```json
{
  "url": "https://diaz.gob.ar/",
  "missing_header": "Content-Security-Policy",
  "all_headers": [
    "Date",
    "Content-Type",
    "Connection",
    "x-powered-by",
    "link",
    "x-tec-api-version",
    "x-tec-api-root",
    "x-tec-api-origin",
    "Server",
    "cf-cache-status",
    "Server-Timing",
    "Report-To",
    "Nel",
    "Content-Encoding",
    "CF-RAY",
    "alt-svc"
  ]
}
```

---

### 2. Falta header de seguridad: X-Frame-Options

**Tipo:** `missing_security_header`

**Descripción:** X-Frame-Options no está presente en https://diaz.gob.ar/

**Recomendación:** Agregar X-Frame-Options: DENY o SAMEORIGIN para prevenir clickjacking

**Evidencia:**

```json
{
  "url": "https://diaz.gob.ar/",
  "missing_header": "X-Frame-Options",
  "all_headers": [
    "Date",
    "Content-Type",
    "Connection",
    "x-powered-by",
    "link",
    "x-tec-api-version",
    "x-tec-api-root",
    "x-tec-api-origin",
    "Server",
    "cf-cache-status",
    "Server-Timing",
    "Report-To",
    "Nel",
    "Content-Encoding",
    "CF-RAY",
    "alt-svc"
  ]
}
```

---

## 🔵 Hallazgos - Severidad Low

### 1. Falta header de seguridad: X-Content-Type-Options

**Tipo:** `missing_security_header`

**Descripción:** X-Content-Type-Options no está presente en https://diaz.gob.ar/

**Recomendación:** Agregar X-Content-Type-Options: nosniff para prevenir MIME sniffing

**Evidencia:**

```json
{
  "url": "https://diaz.gob.ar/",
  "missing_header": "X-Content-Type-Options",
  "all_headers": [
    "Date",
    "Content-Type",
    "Connection",
    "x-powered-by",
    "link",
    "x-tec-api-version",
    "x-tec-api-root",
    "x-tec-api-origin",
    "Server",
    "cf-cache-status",
    "Server-Timing",
    "Report-To",
    "Nel",
    "Content-Encoding",
    "CF-RAY",
    "alt-svc"
  ]
}
```

---

### 2. Falta header de seguridad: Referrer-Policy

**Tipo:** `missing_security_header`

**Descripción:** Referrer-Policy no está presente en https://diaz.gob.ar/

**Recomendación:** Agregar Referrer-Policy para controlar información de referrer enviada

**Evidencia:**

```json
{
  "url": "https://diaz.gob.ar/",
  "missing_header": "Referrer-Policy",
  "all_headers": [
    "Date",
    "Content-Type",
    "Connection",
    "x-powered-by",
    "link",
    "x-tec-api-version",
    "x-tec-api-root",
    "x-tec-api-origin",
    "Server",
    "cf-cache-status",
    "Server-Timing",
    "Report-To",
    "Nel",
    "Content-Encoding",
    "CF-RAY",
    "alt-svc"
  ]
}
```

---

### 3. Falta header de seguridad: Permissions-Policy

**Tipo:** `missing_security_header`

**Descripción:** Permissions-Policy no está presente en https://diaz.gob.ar/

**Recomendación:** Agregar Permissions-Policy para controlar características del navegador

**Evidencia:**

```json
{
  "url": "https://diaz.gob.ar/",
  "missing_header": "Permissions-Policy",
  "all_headers": [
    "Date",
    "Content-Type",
    "Connection",
    "x-powered-by",
    "link",
    "x-tec-api-version",
    "x-tec-api-root",
    "x-tec-api-origin",
    "Server",
    "cf-cache-status",
    "Server-Timing",
    "Report-To",
    "Nel",
    "Content-Encoding",
    "CF-RAY",
    "alt-svc"
  ]
}
```

---

### 4. Falta header de seguridad: COOP

**Tipo:** `missing_security_header`

**Descripción:** Cross-Origin-Opener-Policy no está presente en https://diaz.gob.ar/

**Recomendación:** Considerar agregar COOP para aislar el contexto de navegación

**Evidencia:**

```json
{
  "url": "https://diaz.gob.ar/",
  "missing_header": "Cross-Origin-Opener-Policy",
  "all_headers": [
    "Date",
    "Content-Type",
    "Connection",
    "x-powered-by",
    "link",
    "x-tec-api-version",
    "x-tec-api-root",
    "x-tec-api-origin",
    "Server",
    "cf-cache-status",
    "Server-Timing",
    "Report-To",
    "Nel",
    "Content-Encoding",
    "CF-RAY",
    "alt-svc"
  ]
}
```

---

## ℹ️ Hallazgos - Severidad Info

### 1. Información del certificado TLS

**Tipo:** `cert_info`

**Descripción:** Información del certificado obtenida

**Recomendación:** N/A

**Evidencia:**

```json
{
  "url": "https://diaz.gob.ar/",
  "tls_version": "TLSv1.3",
  "issuer": {
    "countryName": "US",
    "organizationName": "Google Trust Services",
    "commonName": "WE1"
  },
  "subject": {
    "commonName": "diaz.gob.ar"
  },
  "san": [
    "diaz.gob.ar",
    "*.diaz.gob.ar"
  ],
  "valid_from": "2025-11-03T17:41:37",
  "valid_until": "2026-02-01T18:39:20",
  "days_until_expiry": 33
}
```

---

### 2. Falta header de seguridad: COEP

**Tipo:** `missing_security_header`

**Descripción:** Cross-Origin-Embedder-Policy no está presente en https://diaz.gob.ar/

**Recomendación:** Considerar COEP si se requiere aislamiento estricto de recursos

**Evidencia:**

```json
{
  "url": "https://diaz.gob.ar/",
  "missing_header": "Cross-Origin-Embedder-Policy",
  "all_headers": [
    "Date",
    "Content-Type",
    "Connection",
    "x-powered-by",
    "link",
    "x-tec-api-version",
    "x-tec-api-root",
    "x-tec-api-origin",
    "Server",
    "cf-cache-status",
    "Server-Timing",
    "Report-To",
    "Nel",
    "Content-Encoding",
    "CF-RAY",
    "alt-svc"
  ]
}
```

---

### 3. Falta header de seguridad: CORP

**Tipo:** `missing_security_header`

**Descripción:** Cross-Origin-Resource-Policy no está presente en https://diaz.gob.ar/

**Recomendación:** Considerar CORP para controlar cómo otros sitios pueden cargar recursos

**Evidencia:**

```json
{
  "url": "https://diaz.gob.ar/",
  "missing_header": "Cross-Origin-Resource-Policy",
  "all_headers": [
    "Date",
    "Content-Type",
    "Connection",
    "x-powered-by",
    "link",
    "x-tec-api-version",
    "x-tec-api-root",
    "x-tec-api-origin",
    "Server",
    "cf-cache-status",
    "Server-Timing",
    "Report-To",
    "Nel",
    "Content-Encoding",
    "CF-RAY",
    "alt-svc"
  ]
}
```

---

## Tabla de Hallazgos

| Severidad | Tipo | Título | URL |
|-----------|------|--------|-----|
| High | `missing_security_header` | Falta header de seguridad: HSTS | https://diaz.gob.ar/ |
| Medium | `missing_security_header` | Falta header de seguridad: CSP | https://diaz.gob.ar/ |
| Medium | `missing_security_header` | Falta header de seguridad: X-Frame-Options | https://diaz.gob.ar/ |
| Low | `missing_security_header` | Falta header de seguridad: X-Content-Type-Options | https://diaz.gob.ar/ |
| Low | `missing_security_header` | Falta header de seguridad: Referrer-Policy | https://diaz.gob.ar/ |
| Low | `missing_security_header` | Falta header de seguridad: Permissions-Policy | https://diaz.gob.ar/ |
| Low | `missing_security_header` | Falta header de seguridad: COOP | https://diaz.gob.ar/ |
| Info | `cert_info` | Información del certificado TLS | https://diaz.gob.ar/ |
| Info | `missing_security_header` | Falta header de seguridad: COEP | https://diaz.gob.ar/ |
| Info | `missing_security_header` | Falta header de seguridad: CORP | https://diaz.gob.ar/ |

---

## Páginas Analizadas

Total: 1

| URL | Status | Content-Type | Size |
|-----|--------|--------------|------|
| https://diaz.gob.ar/ | 200 | text/html; charset=UTF-8 | 2063 bytes |

---

## Notas

- Este reporte fue generado mediante auditoría **pasiva** (no intrusiva)
- No se enviaron payloads ofensivos ni se intentó explotar vulnerabilidades
- Los hallazgos se basan en análisis de headers, configuración y exposición de archivos
- Se recomienda revisar manualmente los hallazgos antes de tomar acciones correctivas

