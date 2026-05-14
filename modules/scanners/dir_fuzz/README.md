# scanners/dir_fuzz

Fuzzer de directorios y archivos expuestos. Busca paths comunes (`.git`, `.env`,
backups, paneles admin, configs) y archivos sensibles por extensión, clasifica
por nivel de riesgo (`critico`, `alto`, `medio`, `bajo`, `info`).

## Qué hace

1. Descarga `robots.txt` y extrae paths de `Disallow:` / `Allow:` (signal extra).
2. Itera la lista `COMMON_PATHS` (~100 paths conocidos) + combinaciones con
   `SENSITIVE_EXTENSIONS` (`.bak`, `.sql`, `.zip`, `.key`, etc.).
3. Hace `GET` paralelo (ThreadPoolExecutor, 10 hilos por defecto), considera
   "encontrado" si responde `200`, `301`, `302`, o `403` (con filtro anti-404
   custom para 200 con cuerpo chico).
4. Asigna riesgo via `RISK_LEVELS` (mapa keyword → nivel) y consolida un
   `risk_level` agregado para el target.

## Interfaz pública

```python
from modules.scanners.dir_fuzz import DirectoryFuzzer, FuzzerResult

fuzzer = DirectoryFuzzer()
result: FuzzerResult = fuzzer.analyze("https://target.com", threads=10)

print(result.risk_level)     # 'critico' | 'alto' | 'medio' | 'bajo' | 'ninguno'
print(result.found_paths)    # list[dict] con path, url, status, size, content_type, risk
print(result.total_checked)  # int
print(result.duration)       # segundos
```

Argumentos opcionales de `analyze`:

- `custom_paths: list[str]` — paths extra (ej: salidos del `robots.txt`).
- `threads: int = 10` — paralelismo.
- `include_extensions: bool = True` — incluir combinaciones `<base>.<ext>`.

## Dependencias

- `requests`
- stdlib: `dataclasses`, `typing`, `urllib.parse`, `time`, `concurrent.futures`

No depende de otros módulos vendetta.

## CLI

```bash
python -m modules.scanners.dir_fuzz.scanner 'https://ejemplo.com'
# o vía wrapper compat:
python dir_fuzzer.py 'https://ejemplo.com'
```

## Retro-compatibilidad

`dir_fuzzer.py` en la raíz del repo es un wrapper que reexporta de este módulo.
Se borrará 2-4 semanas después de Fase 4 (2026-05-14) salvo que algún consumer
externo lo siga importando.

Imports flat soportados:

```python
from dir_fuzzer import DirectoryFuzzer
from dir_fuzzer import DirectoryFuzzer, FuzzerResult
```

## Tests

Pendiente. Smoke test: `POST /api/scan` con target real →
`raw_results.dir_fuzz` debe traer al menos `robots.txt` en sitios públicos
estándar.

## Cómo desinstalar / desactivar

Pasar `skip_tools=["dirs"]` al `POST /api/scan`, o comentar el paso en
`full_scan.py` (futuro: `modules/scan_orchestrator/orchestrator.py`).
