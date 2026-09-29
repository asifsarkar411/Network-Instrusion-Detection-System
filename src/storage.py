"""
Storage Layer — SQLite Database
================================
Persists alerts, flow data, and statistics for the dashboard.

Tables:
  - alerts: Detection results from the hybrid detector
  - flow_stats: Aggregated statistics for dashboard charts
"""

import os
import json
import sqlite3
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from contextlib import contextmanager


class DatabaseManager:
    """
    Manages SQLite database for SOC-NIDS alert storage.
    
    Thread-safe via SQLite's built-in serialized mode.
    All writes are immediate — no batching needed for this scale.
    """
    
    def __init__(self, db_path: str = "data/nids_alerts.db"):
        """
        Initialize database connection.
        
        Args:
            db_path: Path to SQLite database file
        """
        # Ensure directory exists
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        self.db_path = db_path
        self._init_database()
        print(f"[Storage] Database initialized: {db_path}")
    
    @contextmanager
    def _get_connection(self):
        """Context manager for safe database connections."""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    def _init_database(self) -> None:
        """Create tables if they don't exist."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Main alerts table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    attack_type TEXT,
                    severity TEXT NOT NULL,
                    final_score REAL NOT NULL,
                    rule_score REAL DEFAULT 0.0,
                    ml_score REAL DEFAULT 0.0,
                    source_ip TEXT,
                    destination_ip TEXT,
                    source_port INTEGER,
                    destination_port INTEGER,
                    protocol INTEGER,
                    flow_features TEXT,
                    rule_details TEXT,
                    ml_details TEXT,
                    packet_summary TEXT
                )
            """)
            
            # Index for fast queries
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_alerts_timestamp 
                ON alerts(timestamp DESC)
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_alerts_severity 
                ON alerts(severity)
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_alerts_attack_type 
                ON alerts(attack_type)
            """)
            
            # Flow statistics table (aggregated for dashboard)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS flow_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    total_flows INTEGER DEFAULT 0,
                    benign_flows INTEGER DEFAULT 0,
                    attack_flows INTEGER DEFAULT 0,
                    alerts_high INTEGER DEFAULT 0,
                    alerts_medium INTEGER DEFAULT 0,
                    alerts_low INTEGER DEFAULT 0
                )
            """)
    
    # ──────────────────────────────────────────────────────────
    # Alert Operations
    # ──────────────────────────────────────────────────────────
    
    def save_alert(self, alert_data: Dict) -> int:
        """
        Save a detection alert to the database.
        
        Args:
            alert_data: Dict from HybridDetector.analyze_flow() or analyze_packet()
                        plus optional flow metadata
            
        Returns:
            ID of the inserted row
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO alerts (
                    timestamp,
                    attack_type,
                    severity,
                    final_score,
                    rule_score,
                    ml_score,
                    source_ip,
                    destination_ip,
                    source_port,
                    destination_port,
                    protocol,
                    flow_features,
                    rule_details,
                    ml_details,
                    packet_summary
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert_data.get("timestamp", datetime.now().isoformat()),
                alert_data.get("attack_type"),
                alert_data.get("severity", "low"),
                alert_data.get("final_score", 0.0),
                alert_data.get("rule_score", 0.0),
                alert_data.get("ml_score", 0.0),
                alert_data.get("source_ip"),
                alert_data.get("destination_ip"),
                alert_data.get("source_port"),
                alert_data.get("destination_port"),
                alert_data.get("protocol"),
                json.dumps(alert_data.get("flow_features", {})) if alert_data.get("flow_features") else None,
                json.dumps(alert_data.get("rule_details", {})) if alert_data.get("rule_details") else None,
                json.dumps(alert_data.get("ml_details", {})) if alert_data.get("ml_details") else None,
                alert_data.get("packet_summary"),
            ))
            
            return cursor.lastrowid
    
    def get_recent_alerts(self, limit: int = 50, severity: Optional[str] = None) -> List[Dict]:
        """
        Get recent alerts, newest first.
        
        Args:
            limit: Maximum number of alerts to return
            severity: Optional filter ('high', 'medium', 'low')
            
        Returns:
            List of alert dicts
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            if severity:
                cursor.execute("""
                    SELECT * FROM alerts 
                    WHERE severity = ?
                    ORDER BY timestamp DESC 
                    LIMIT ?
                """, (severity, limit))
            else:
                cursor.execute("""
                    SELECT * FROM alerts 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                """, (limit,))
            
            return [dict(row) for row in cursor.fetchall()]
    
    def get_alert_by_id(self, alert_id: int) -> Optional[Dict]:
        """Get a single alert by its ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def get_alert_count(self, since_minutes: int = 60) -> Dict:
        """
        Get alert counts for the dashboard.
        
        Args:
            since_minutes: Time window in minutes
            
        Returns:
            Dict with counts by severity and attack type
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            since_time = datetime.now().replace(microsecond=0).isoformat()
            
            # Total alerts
            cursor.execute("""
                SELECT COUNT(*) FROM alerts 
                WHERE timestamp >= datetime('now', ? || ' minutes')
            """, (f"-{since_minutes}",))
            total = cursor.fetchone()[0]
            
            # By severity
            cursor.execute("""
                SELECT severity, COUNT(*) FROM alerts 
                WHERE timestamp >= datetime('now', ? || ' minutes')
                GROUP BY severity
            """, (f"-{since_minutes}",))
            by_severity = {row[0]: row[1] for row in cursor.fetchall()}
            
            # By attack type
            cursor.execute("""
                SELECT attack_type, COUNT(*) FROM alerts 
                WHERE timestamp >= datetime('now', ? || ' minutes')
                AND attack_type IS NOT NULL
                GROUP BY attack_type
            """, (f"-{since_minutes}",))
            by_type = {row[0]: row[1] for row in cursor.fetchall()}
            
            return {
                "total": total,
                "by_severity": by_severity,
                "by_type": by_type,
                "window_minutes": since_minutes,
            }
    
    def get_alert_timeline(self, since_minutes: int = 60, interval_seconds: int = 60) -> List[Dict]:
        """
        Get alert counts over time for timeline charts.
        
        Args:
            since_minutes: Time window
            interval_seconds: Bucket size
            
        Returns:
            List of {timestamp, count} dicts
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT 
                    strftime('%Y-%m-%dT%H:%M:%S', timestamp) as bucket,
                    COUNT(*) as count
                FROM alerts
                WHERE timestamp >= datetime('now', ? || ' minutes')
                GROUP BY strftime('%s', timestamp) / ?
                ORDER BY bucket
            """, (f"-{since_minutes}", interval_seconds))
            
            return [dict(row) for row in cursor.fetchall()]
    
    def get_top_source_ips(self, limit: int = 10, since_minutes: int = 60) -> List[Dict]:
        """Get most frequent source IPs in alerts."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT source_ip, COUNT(*) as alert_count
                FROM alerts
                WHERE timestamp >= datetime('now', ? || ' minutes')
                AND source_ip IS NOT NULL
                GROUP BY source_ip
                ORDER BY alert_count DESC
                LIMIT ?
            """, (f"-{since_minutes}", limit))
            
            return [dict(row) for row in cursor.fetchall()]
    
    # ──────────────────────────────────────────────────────────
    # Statistics Operations
    # ──────────────────────────────────────────────────────────
    
    def save_flow_stats(self, stats: Dict) -> None:
        """Save periodic flow statistics snapshot."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO flow_stats (
                    timestamp, total_flows, benign_flows, 
                    attack_flows, alerts_high, alerts_medium, alerts_low
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                datetime.now().isoformat(),
                stats.get("total_flows", 0),
                stats.get("benign_flows", 0),
                stats.get("attack_flows", 0),
                stats.get("alerts_high", 0),
                stats.get("alerts_medium", 0),
                stats.get("alerts_low", 0),
            ))
    
    def get_flow_stats(self, since_minutes: int = 60) -> Dict:
        """Get aggregated flow statistics."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT 
                    SUM(total_flows) as total_flows,
                    SUM(benign_flows) as benign_flows,
                    SUM(attack_flows) as attack_flows,
                    SUM(alerts_high) as alerts_high,
                    SUM(alerts_medium) as alerts_medium,
                    SUM(alerts_low) as alerts_low
                FROM flow_stats
                WHERE timestamp >= datetime('now', ? || ' minutes')
            """, (f"-{since_minutes}",))
            
            row = cursor.fetchone()
            if row:
                return {
                    "total_flows": row[0] or 0,
                    "benign_flows": row[1] or 0,
                    "attack_flows": row[2] or 0,
                    "alerts_high": row[3] or 0,
                    "alerts_medium": row[4] or 0,
                    "alerts_low": row[5] or 0,
                }
            return {}
    
    # ──────────────────────────────────────────────────────────
    # Maintenance
    # ──────────────────────────────────────────────────────────
    
    def clear_all_alerts(self) -> int:
        """
        Delete all alerts from the database.
        
        Returns:
            Number of deleted rows
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM alerts")
            deleted = cursor.rowcount
            cursor.execute("DELETE FROM flow_stats")
            print(f"[Storage] Cleared {deleted} alerts from database")
            return deleted

    def cleanup_old_alerts(self, older_than_hours: int = 24) -> int:
        """
        Remove alerts older than specified hours.
        
        Returns:
            Number of deleted rows
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                DELETE FROM alerts 
                WHERE timestamp < datetime('now', ? || ' hours')
            """, (f"-{older_than_hours}",))
            deleted = cursor.rowcount
            if deleted > 0:
                print(f"[Storage] Cleaned up {deleted} old alerts")
            return deleted
    
    def get_database_size(self) -> Tuple[int, int]:
        """
        Get database file size and row counts.
        
        Returns:
            (size_bytes, alert_count)
        """
        size = os.path.getsize(self.db_path) if os.path.exists(self.db_path) else 0
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM alerts")
            count = cursor.fetchone()[0]
        
        return size, count
    
    def vacuum(self) -> None:
        """Reclaim disk space after deletions."""
        with self._get_connection() as conn:
            conn.execute("VACUUM")
