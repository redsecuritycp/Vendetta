## scanners/slowloris (OPT-IN)

Simulación de ataque Slowloris — mantiene cientos de conexiones HTTP
abiertas enviando headers parciales muy lentamente, consumiendo recursos
del servidor sin generar tráfico alto. Sirve para verificar si un web
server tiene protección anti-slowloris activa (timeouts, mod_reqtimeout,
reverse proxy, rate-limit por IP).

## OPT-IN — NO se ejecuta automáticamente

A diferencia del resto de scanners de `modules/scanners/`, slowloris es
**destructivo por naturaleza** (consume sockets del target hasta saturarlo)
y NO se invoca desde `POST /api/scan` ni desde el orchestrator
`FullScanner`. No está registrado en el pipeline.

Para correrlo:
1. Verificar autorización del owner del sistema target.
2. Importar y ejecutar manualmente desde Python (ver "Interfaz pública").
3. O invocar via CLI: `python -m modules.scanners.slowloris.scanner <url> [sockets] [duracion]`.

**Solo para uso en sistemas propios o con autorización explícita.** Usar
contra terceros sin permiso = ataque DoS = ilegal.

## Qué hace

1. Parsea la URL (host, port, scheme http/https).
2. Crea `socket_count` sockets TCP (por defecto 200), abre conexión HTTP,
   envía headers parciales (`GET / HTTP/1.1`, `Host`, `User-Agent`,
   `Accept-Language`) sin terminar la request.
3. Cada 10 segundos manda un header extra (`X-a: <rand>`) por cada
   socket para mantenerlos abiertos. Re-abre los que se cerraron.
4. Mide cuántos sockets sobrevivieron al final del periodo (`duration`,
   30s por defecto).
5. Reporta `vulnerable=True` si:
   - `sockets_created > socket_count * 0.5` (el server aceptó muchas
     conexiones).
   - Y `sockets_alive > socket_count * 0.3` (las mantuvo abiertas).
6. Devuelve `SlowlorisResult` con stats + recomendaciones de hardening.

## Interfaz pública

```python
from modules.scanners.slowloris import (
    SlowlorisAttacker,
    SlowlorisResult,
    analyze,
)

# Uso completo
attacker = SlowlorisAttacker()
result: SlowlorisResult = attacker.analyze(
    "https://mi-server-propio.com",
    socket_count=200,
    duration=30,
)
print(result.vulnerable)            # bool
print(result.sockets_created)       # int
print(result.sockets_alive)         # int
for line in result.details:
    print(line)
for rec in result.recommendations:
    print(rec)

# Cancelación manual mid-ejecución (desde otro thread)
attacker.stop()

# Helper de conveniencia (equivale a las 3 líneas de arriba)
result = analyze("https://mi-server-propio.com", socket_count=100, duration=20)
```

## CLI

```bash
python -m modules.scanners.slowloris.scanner <url> [sockets] [duracion]
# Ejemplo:
python -m modules.scanners.slowloris.scanner https://mi-server-propio.com 200 30
```

## Dependencias

- stdlib: `socket`, `ssl`, `random`, `time`, `asyncio`, `dataclasses`,
  `typing`, `urllib.parse`.

No depende de `requests` ni de otros módulos vendetta. Es 100% stdlib.

## Retro-compatibilidad

`slowloris.py` en la raíz del repo es un wrapper que reexporta de este
módulo. Se borrará 2-4 semanas después de Fase 9 (2026-05-14) salvo que
algún consumer externo lo siga importando.

Imports flat soportados:

```python
from slowloris import SlowlorisAttacker
from slowloris import SlowlorisAttacker, SlowlorisResult, analyze
```

`full_scan.py` NO importa slowloris — sigue fuera del pipeline (esto es
intencional, no un olvido).

## Tests

Pendiente. Smoke test manual: ejecutar contra un container local con
nginx default (sin mod_reqtimeout) y otro con nginx + `client_body_timeout 5s`.
El primero debería reportar `vulnerable=True`, el segundo `False`.

## Cómo desactivar / desinstalar

Nada que desactivar — ya está OFF por defecto. Si querés removerlo del
repo:
1. Borrar `modules/scanners/slowloris/`.
2. Borrar `slowloris.py` (wrapper) del root.
3. Si algún script lo importaba directo (`from slowloris import …`),
   actualizarlo o quitar la dependencia.
