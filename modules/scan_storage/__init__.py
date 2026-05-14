"""
Módulo Scan Storage
Persistencia con SQLite para guardar scans, listar historial,
recuperar reportes y obtener targets escaneados.

Interfaz pública:
    from modules.scan_storage import DBManager, DB_PATH
"""

from .storage import DBManager, DB_PATH

__all__ = ["DBManager", "DB_PATH"]
