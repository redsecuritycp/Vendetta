"""
Persistencia con SQLite para guardar scans y comparar historico
"""

import sqlite3
import json
import os
from datetime import datetime
from typing import List, Dict, Optional


DB_PATH = os.path.join(os.path.dirname(__file__), "vendetta.db")


class DBManager:
    """Maneja persistencia de scans en SQLite"""

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    scan_date TEXT NOT NULL,
                    duration REAL DEFAULT 0,
                    risk_score INTEGER DEFAULT 0,
                    total_findings INTEGER DEFAULT 0,
                    critico INTEGER DEFAULT 0,
                    alto INTEGER DEFAULT 0,
                    medio INTEGER DEFAULT 0,
                    bajo INTEGER DEFAULT 0,
                    info INTEGER DEFAULT 0,
                    tools_used TEXT DEFAULT '[]',
                    report_json TEXT DEFAULT '{}',
                    report_html TEXT DEFAULT ''
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_scans_date ON scans(scan_date)
            """)

    def save_scan(self, target: str, risk_score: int, summary: Dict,
                  tools_used: List[str], duration: float,
                  report_json: str, report_html: str) -> int:
        """Guarda un scan y retorna su ID"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                INSERT INTO scans (target, scan_date, duration, risk_score,
                    total_findings, critico, alto, medio, bajo, info,
                    tools_used, report_json, report_html)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                target,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                duration,
                risk_score,
                sum(summary.values()),
                summary.get("critico", 0),
                summary.get("alto", 0),
                summary.get("medio", 0),
                summary.get("bajo", 0),
                summary.get("info", 0),
                json.dumps(tools_used),
                report_json,
                report_html,
            ))
            return cursor.lastrowid

    def get_scans(self, target: Optional[str] = None, limit: int = 50) -> List[Dict]:
        """Obtiene scans, opcionalmente filtrados por target"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            if target:
                rows = conn.execute(
                    "SELECT id, target, scan_date, duration, risk_score, total_findings, "
                    "critico, alto, medio, bajo, info, tools_used "
                    "FROM scans WHERE target = ? ORDER BY scan_date DESC LIMIT ?",
                    (target, limit)
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT id, target, scan_date, duration, risk_score, total_findings, "
                    "critico, alto, medio, bajo, info, tools_used "
                    "FROM scans ORDER BY scan_date DESC LIMIT ?",
                    (limit,)
                ).fetchall()
            return [dict(r) for r in rows]

    def get_scan_report(self, scan_id: int) -> Optional[Dict]:
        """Obtiene reporte completo de un scan"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()
            if row:
                return dict(row)
            return None

    def get_targets(self) -> List[str]:
        """Lista todos los targets escaneados"""
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT DISTINCT target FROM scans ORDER BY target"
            ).fetchall()
            return [r[0] for r in rows]

    def delete_scan(self, scan_id: int) -> bool:
        """Elimina un scan"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            return cursor.rowcount > 0

    def get_comparison(self, target: str) -> List[Dict]:
        """Obtiene historico para comparacion de un target"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT scan_date, risk_score, total_findings, critico, alto, medio, bajo "
                "FROM scans WHERE target = ? ORDER BY scan_date ASC LIMIT 20",
                (target,)
            ).fetchall()
            return [dict(r) for r in rows]
