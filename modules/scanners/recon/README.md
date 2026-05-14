# modules/scanners/recon

Scanner de **reconocimiento pasivo**. Recopila información pública de un dominio sin lanzar ataques activos.

## Qué hace

Para una URL dada:
1. Resuelve DNS (IPs).
2. Lee headers HTTP del response inicial.
3. Detecta tecnologías por patrones (server, powered-by, contenido HTML — Apache/Nginx/PHP/WordPress/React/etc.).
4. Inspecciona certificado SSL/TLS (issuer, fechas, SAN, protocolo, cipher).
5. Extrae info del servidor (server, x-powered-by, x-aspnet-version).
6. Genera findings + recomendaciones por headers de seguridad faltantes (HSTS, CSP, X-Frame-Options) e info expuesta.

## Interfaz pública

```python
from modules.scanners.recon import PassiveRecon, ReconResult

recon = PassiveRecon()
result: ReconResult = recon.analyze("https://example.com")
print(result.findings, result.recommendations)
```

`ReconResult` es un `@dataclass` con: `url`, `domain`, `ip_addresses`, `headers`, `security_headers`, `technologies`, `ssl_info`, `dns_info`, `server_info`, `findings`, `recommendations`.

## CLI

```bash
python -m modules.scanners.recon.scanner https://example.com
```

## Dependencias

- `requests` (HTTP client)
- stdlib: `socket`, `ssl`, `re`, `urllib.parse`, `dataclasses`

No depende de otros módulos del proyecto. Es self-contained.

## Cómo se usa hoy en vendetta

Lo invoca `full_scan.py` como **paso 1** del pipeline de FullScanner (`_run_recon`). El endpoint `POST /api/scan` lo dispara como parte del scan completo.

## Retro-compat (importante)

El path viejo `from recon import PassiveRecon` **sigue funcionando** durante 2-4 semanas vía wrapper en `/recon.py` (root del proyecto) que re-exporta desde acá. No editar el wrapper — modificar este módulo.

Cuando el wrapper se borre (después de verificar que ningún otro módulo lo importa), se documentará el descarte en `_deprecated/README.md`.

## Tests

Pendiente. Smoke test mínimo:

```bash
cd /home/ubuntu/projects/vendetta
./venv/bin/python -c "from modules.scanners.recon import PassiveRecon; r = PassiveRecon().analyze('https://example.com'); print(len(r.findings), 'findings')"
```

## Roadmap

- Tests unitarios con responses mockeados (requests-mock).
- Interfaz común `run(target, options) -> List[Finding]` cuando se cree `core/findings.py` en Fase 1 del plan original.
- Cache por dominio para no repetir DNS/SSL en scans encadenados.

## Movido desde

`recon.py` (root) → `modules/scanners/recon/scanner.py` el 2026-05-14, Fase 1 modular según `MODULAR_PLAN.md` de vendetta.
