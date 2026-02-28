"""
NIDS Database module - SQLite storage for alerts.
"""

import sqlite3
import logging
from datetime import datetime
from contextlib import contextmanager
from typing import Optional

import config

logger = logging.getLogger(__name__)


class Database:
    """Handles SQLite database operations for NIDS alerts."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or config.DATABASE_PATH

    @contextmanager
    def get_connection(self):
        """Context manager for database connections."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.exception("Database error: %s", e)
            raise
        finally:
            conn.close()

    def init_db(self) -> None:
        """Create alerts table if it does not exist."""
        with self.get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    attack_type TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    description TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            logger.info("Database initialized at %s", self.db_path)

    def insert_alert(
        self,
        attack_type: str,
        source_ip: str,
        description: str,
        timestamp: Optional[str] = None,
    ) -> None:
        """Insert a new alert into the database."""
        ts = timestamp or datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO alerts (timestamp, attack_type, source_ip, description)
                VALUES (?, ?, ?, ?)
                """,
                (ts, attack_type, source_ip, description),
            )
        logger.debug("Alert saved: %s from %s", attack_type, source_ip)

    def get_all_alerts(self, limit: int = 1000) -> list:
        """Fetch all alerts, most recent first."""
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT id, timestamp, attack_type, source_ip, description
                FROM alerts
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            )
            rows = cursor.fetchall()
        return [dict(row) for row in rows]

    def get_alert_count(self) -> int:
        """Return total number of alerts in database."""
        with self.get_connection() as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM alerts")
            return cursor.fetchone()[0]
