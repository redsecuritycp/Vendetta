# Módulo `scan_storage`

**Fecha**: 2026-05-14 (Fase 14 de modularización)
**Estado**: activo en producción
**Endpoints API que lo usan**: `GET /api/scans`, `GET /api/scans/<id>`, `GET /api/scans/<id>/report`, `GET /api/targets`, y `POST /api/scan` (al persistir el resultado del orchestrator).

## Qué hace

Capa de persistencia SQLite de vendetta. Guarda cada scan ejecutado por el
`scan_orchestrator` y lo expone para:

- Listar histórico (`get_scans`) — global o por target.
- Recuperar reporte completo de un scan (`get_scan_report`) — incluye HTML y JSON serializados.
- Listar targets escaneados (`get_targets`).
- Borrar un scan (`delete_scan`).
- Obtener serie histórica de risk_score por target (`get_comparison`).

Schema:

```sql
CREATE TABLE scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    scan_date TEXT NOT NULL,
    duration REAL,
    risk_score INTEGER,
    total_findings INTEGER,
    critico INTEGER, alto INTEGER, medio INTEGER, bajo INTEGER, info INTEGER,
    tools_used TEXT,        -- JSON array
    report_json TEXT,       -- ScanReport.to_json()
    report_html TEXT        -- ReportGenerator.generate_html()
);
```

Índices: `idx_scans_target`, `idx_scans_date`.

## Interfaz pública

```python
from modules.scan_storage import DBManager, DB_PATH

db = DBManager()                              # usa DB_PATH default (root proyecto)
scan_id = db.save_scan(target, score, summary, tools_used, duration, report_json, report_html)
scans = db.get_scans(target="https://x.com", limit=20)
report = db.get_scan_report(scan_id)
targets = db.get_targets()
history = db.get_comparison("https://x.com")
db.delete_scan(scan_id)
```

## Path de la DB

`DB_PATH = <project_root>/vendetta.db`, donde `<project_root>` es
`/home/ubuntu/projects/vendetta/` (o el `current` de cada release ARM).
En producción es un symlink a `/home/ubuntu/deployments/vendetta-api/shared/vendetta.db`
— la DB persiste entre deploys.

El módulo resuelve el root subiendo dos niveles desde `storage.py`
(`modules/scan_storage/storage.py` → `vendetta/`). Si se mueve el módulo,
ajustar `_PROJECT_ROOT` o aceptar `db_path` explícito al instanciar.

## Dependencias

- `sqlite3` (stdlib)
- No depende de otros módulos. **Es infra core** — todos los módulos de scan
  y el `api_server` lo consumen.

## Retro-compatibilidad

`db_manager.py` en el root sigue funcionando como wrapper:

```python
from db_manager import DBManager   # re-exporta de modules.scan_storage
```

El wrapper se mantiene 2-4 semanas. Después se borra. **NO editarlo** — cambios
van en `modules/scan_storage/storage.py`.

## Cómo se prueba

```bash
cd /home/ubuntu/projects/vendetta
python3 -c "from modules.scan_storage import DBManager; db = DBManager(); print(len(db.get_scans()), 'scans;', len(db.get_targets()), 'targets')"
```

## Cómo se desinstala

No aplica — es infra core. Si se quisiera reemplazar (ej: pasar a Postgres),
mantener la interfaz `DBManager` y los métodos públicos para que el
orchestrator y `api_server` no se enteren.
