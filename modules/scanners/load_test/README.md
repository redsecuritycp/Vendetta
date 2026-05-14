## scanners/load_test (OPT-IN)

Motor de prueba de carga HTTP concurrente — genera tráfico sostenido de
alta concurrencia contra una URL para medir cómo responde el server bajo
estrés (latencia, errores, RPS sostenido, comportamiento del rate-limit).
Útil para validar capacity planning, configuración de reverse proxy,
auto-scaling y defensas L7 anti-flood.

## OPT-IN — NO se ejecuta automáticamente

A diferencia de los scanners de `modules/scanners/recon`, `xss`,
`clickjacking`, `dir_fuzz`, `forms`, `hsts_ssl`, `subdomain_enum` y
`bypass_403` — que sí corren dentro de `POST /api/scan` via
`FullScanner` — load_test es **destructivo por naturaleza** (puede saturar
el target en segundos con cientos de conexiones simultáneas) y **NO se
invoca desde `POST /api/scan` ni desde el orchestrator `FullScanner`**.
No está registrado en el pipeline.

Para correrlo:
1. Verificar autorización del owner del sistema target.
2. Importar y ejecutar manualmente desde Python (ver "Interfaz pública").
3. O invocar via CLI: `python -m modules.scanners.load_test.scanner <url> [concurrent] [duracion]`.

**Solo para uso en sistemas propios o con autorización explícita.** Usar
contra terceros sin permiso = ataque DoS = ilegal.

## Qué hace

1. Crea una `aiohttp.ClientSession` con `TCPConnector(limit=max_concurrent)`
   y un `asyncio.Semaphore(max_concurrent)` para limitar concurrencia real.
2. Dispara requests GET asíncronos contra `target_url` en loop apretado
   hasta cumplir la duración (`duration_seconds`) o hasta `stop_test()`.
3. Cada request registra `status`, `latency` y `error` en una cola
   thread-safe (`Queue`) procesada por `get_stats()`.
4. Corre en un thread aparte (`threading.Thread(daemon=True)`) con su
   propio event loop, así no bloquea al caller (Streamlit / Flask / CLI).
5. Reporta stats agregadas: `total_sent`, `total_completed`, `successes`
   (HTTP 200), `errors`, `latency_{min,avg,max}` y `rps` calculado sobre
   el `elapsed` real.

## Interfaz pública

```python
from modules.scanners.load_test import LoadTestEngine, analyze

# --- Modo no-bloqueante (UI / monitoring en vivo) ---
engine = LoadTestEngine()
engine.start_test(
    "https://mi-server-propio.com",
    max_concurrent=600,
    duration_seconds=30,
)

# Polling de stats mientras corre
while True:
    stats = engine.get_stats()
    print(stats['rps'], stats['latency_avg'], stats['errors'])
    if not stats['is_running']:
        break
    time.sleep(1)

print(engine.generate_report())

# Cancelación manual mid-ejecución
engine.stop_test()

# --- Modo bloqueante (CLI / scripting) ---
stats = analyze(
    "https://mi-server-propio.com",
    max_concurrent=600,
    duration_seconds=30,
)
print(stats['rps'])
```

## CLI

```bash
python -m modules.scanners.load_test.scanner <url> [concurrent] [duracion]
# Ejemplo:
python -m modules.scanners.load_test.scanner https://mi-server-propio.com 600 30
```

Defaults: `concurrent=600`, `duracion=30` segundos.

## Parámetros y límites recomendados

| Parámetro | Default | Recomendación |
|---|---|---|
| `max_concurrent` | 600 | 100-600 para test estándar. >1000 puede agotar puertos efímeros del cliente. |
| `duration_seconds` | 30 (CLI/helper) / 0 ilimitado (API) | 10-60s alcanza para baseline. `0` (ilimitado) solo desde `LoadTestEngine.start_test()` y bajo supervisión. |
| Timeout por request | 20s (hardcoded) | Cubre servers lentos sin colgar al worker. |

## Dependencias

- `aiohttp` — cliente HTTP async (ya está en `requirements.txt` del proyecto).
- stdlib: `asyncio`, `time`, `threading`, `queue`, `datetime`, `typing`.

No depende de `requests` ni de otros módulos vendetta. Solo aiohttp + stdlib.

## Retro-compatibilidad

`load_test_engine.py` en la raíz del repo es un wrapper que reexporta de
este módulo. Se borrará 2-4 semanas después de Fase 10 (2026-05-14) salvo
que algún consumer externo lo siga importando.

Imports flat soportados:

```python
from load_test_engine import LoadTestEngine
from load_test_engine import LoadTestEngine, analyze
```

`full_scan.py` NO importa load_test — sigue fuera del pipeline (esto es
intencional, no un olvido).

## Tests

Pendiente. Smoke test manual: ejecutar contra un container local con
nginx default y otro con nginx + `limit_req_zone` + `limit_req` (10 r/s).
El primero debería mostrar `rps` cercano a `max_concurrent`, el segundo
una caída fuerte de `successes` y subida de `errors` (HTTP 503).

## Cómo desactivar / desinstalar

Nada que desactivar — ya está OFF por defecto. Si querés removerlo del
repo:
1. Borrar `modules/scanners/load_test/`.
2. Borrar `load_test_engine.py` (wrapper) del root.
3. Si algún script lo importaba directo (`from load_test_engine import …`),
   actualizarlo o quitar la dependencia.
