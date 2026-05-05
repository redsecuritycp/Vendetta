# Herramientas Educativas de Seguridad

⚠️ **ADVERTENCIA LEGAL IMPORTANTE**

Estas herramientas están diseñadas **ÚNICAMENTE** para:
- **Aprendizaje y educación en seguridad**
- **Pruebas en sistemas propios**
- **Pruebas autorizadas por escrito en sistemas de terceros**
- **Entender vulnerabilidades para poder defenderse**

**NO utilice estas herramientas para:**
- Atacar sistemas sin autorización
- Acceder no autorizado a sistemas
- Modificar contenido sin permiso
- Realizar actividades ilegales

El uso no autorizado puede:
- Violar leyes locales, estatales y federales
- Constituir un delito informático
- Resultar en acciones legales y penales

**El usuario es el único responsable del uso de estas herramientas.**

## Herramientas Incluidas

### 1. SSLStrip Simulator (`sslstrip_sim.py`)
Simula el comportamiento de SSLStrip detectando:
- Enlaces HTTP en páginas HTTPS
- Redirecciones inseguras
- Mixed content

### 2. XSS Tester (`xss_test.py`)
Prueba básica de vulnerabilidades XSS:
- Reflected XSS
- Stored XSS (básico)
- Payloads comunes

### 3. Clickjacking Tester (`clickjacking_test.html`)
HTML para probar si un sitio puede ser embebido en iframe

### 4. Reconocimiento (`recon.py`)
Herramientas de reconocimiento pasivo:
- Análisis de robots.txt
- Detección de headers informativos
- Fingerprinting básico

## Instalación

```bash
pip install -r requirements.txt
```

## Uso

Cada herramienta tiene su propio archivo con instrucciones. Lee los comentarios en cada script.

## Responsabilidad

Estas herramientas son para **EDUCACIÓN Y DEFENSA**. Úsalas responsablemente y solo en sistemas que poseas o tengas autorización explícita para probar.
