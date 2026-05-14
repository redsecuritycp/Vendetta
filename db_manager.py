"""
DEPRECATED PATH — wrapper de retro-compatibilidad.

El código real vive en `modules/scan_storage/storage.py` desde
2026-05-14 (Fase 14 modular según MODULAR_PLAN.md).

Este wrapper queda durante 2-4 semanas para no romper:
    from db_manager import DBManager, DB_PATH

Después se borra. NO editar — modificar el módulo nuevo.
"""

from modules.scan_storage import DBManager, DB_PATH  # noqa: F401

__all__ = ["DBManager", "DB_PATH"]
