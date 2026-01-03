"""Database backend for historical registry change analysis.

This module provides SQLite and optional SQL Server database support
for persistent storage and historical analysis of registry changes.
"""

import sqlite3
import json
import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from pathlib import Path
import threading


class RegistryDatabase:
    """SQLite database for registry change history."""
    
    def __init__(self, db_path: str = "registry_monitor.db"):
        """Initialize database.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = Path(db_path)
        self.logger = logging.getLogger(__name__)
        self.lock = threading.Lock()
        self._init_database()
    
    def _init_database(self):
        """Initialize database schema."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            # Create registry changes table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS registry_changes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    key_path TEXT NOT NULL,
                    value_name TEXT,
                    old_value TEXT,
                    new_value TEXT,
                    change_type TEXT,
                    risk_level TEXT,
                    alert_type TEXT,
                    description TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(timestamp, key_path, value_name)
                )
            ''')
            
            # Create alerts table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    risk_level TEXT,
                    message TEXT,
                    registry_change_id INTEGER,
                    webhook_sent BOOLEAN DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(registry_change_id) REFERENCES registry_changes(id)
                )
            ''')
            
            # Create indices for performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON registry_changes(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_key_path ON registry_changes(key_path)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_risk_level ON registry_changes(risk_level)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alert_timestamp ON alerts(timestamp)')
            
            conn.commit()
            conn.close()
            self.logger.info(f"Database initialized: {self.db_path}")
            
        except Exception as e:
            self.logger.error(f"Database initialization error: {e}")
    
    def insert_change(self, change_data: Dict) -> int:
        """Insert registry change record.
        
        Args:
            change_data: Dictionary with change details
            
        Returns:
            Record ID if successful, -1 on error
        """
        with self.lock:
            try:
                conn = sqlite3.connect(str(self.db_path))
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO registry_changes 
                    (timestamp, key_path, value_name, old_value, new_value, change_type, risk_level, alert_type, description)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    change_data.get('timestamp'),
                    change_data.get('key_path'),
                    change_data.get('value_name'),
                    change_data.get('old_value'),
                    change_data.get('new_value'),
                    change_data.get('change_type'),
                    change_data.get('risk_level'),
                    change_data.get('alert_type'),
                    change_data.get('description')
                ))
                
                conn.commit()
                record_id = cursor.lastrowid
                conn.close()
                
                return record_id
                
            except sqlite3.IntegrityError:
                self.logger.debug("Duplicate entry skipped")
                return -1
            except Exception as e:
                self.logger.error(f"Error inserting change: {e}")
                return -1
    
    def insert_alert(self, alert_data: Dict, change_id: Optional[int] = None) -> int:
        """Insert alert record.
        
        Args:
            alert_data: Alert details
            change_id: Associated registry change ID
            
        Returns:
            Alert ID if successful
        """
        with self.lock:
            try:
                conn = sqlite3.connect(str(self.db_path))
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO alerts 
                    (timestamp, alert_type, risk_level, message, registry_change_id)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    alert_data.get('timestamp'),
                    alert_data.get('type'),
                    alert_data.get('risk_level'),
                    alert_data.get('description'),
                    change_id
                ))
                
                conn.commit()
                alert_id = cursor.lastrowid
                conn.close()
                
                return alert_id
                
            except Exception as e:
                self.logger.error(f"Error inserting alert: {e}")
                return -1
    
    def get_changes_by_date_range(self, start_date: datetime, end_date: datetime) -> List[Dict]:
        """Get registry changes within date range.
        
        Args:
            start_date: Start datetime
            end_date: End datetime
            
        Returns:
            List of change records
        """
        try:
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM registry_changes 
                WHERE timestamp BETWEEN ? AND ?
                ORDER BY timestamp DESC
            ''', (start_date.isoformat(), end_date.isoformat()))
            
            records = [dict(row) for row in cursor.fetchall()]
            conn.close()
            
            return records
            
        except Exception as e:
            self.logger.error(f"Error querying changes: {e}")
            return []
    
    def get_high_risk_changes(self, limit: int = 100) -> List[Dict]:
        """Get high-risk registry changes.
        
        Args:
            limit: Maximum number of records to return
            
        Returns:
            List of high-risk change records
        """
        try:
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM registry_changes 
                WHERE risk_level IN ('CRITICAL', 'HIGH')
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (limit,))
            
            records = [dict(row) for row in cursor.fetchall()]
            conn.close()
            
            return records
            
        except Exception as e:
            self.logger.error(f"Error querying high-risk changes: {e}")
            return []
    
    def get_statistics(self) -> Dict:
        """Get database statistics.
        
        Returns:
            Dictionary with statistics
        """
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            stats = {}
            
            # Total changes
            cursor.execute('SELECT COUNT(*) FROM registry_changes')
            stats['total_changes'] = cursor.fetchone()[0]
            
            # Total alerts
            cursor.execute('SELECT COUNT(*) FROM alerts')
            stats['total_alerts'] = cursor.fetchone()[0]
            
            # Risk level breakdown
            cursor.execute('''
                SELECT risk_level, COUNT(*) 
                FROM registry_changes 
                GROUP BY risk_level
            ''')
            stats['by_risk_level'] = dict(cursor.fetchall())
            
            # Alert type breakdown
            cursor.execute('''
                SELECT alert_type, COUNT(*) 
                FROM registry_changes 
                GROUP BY alert_type
            ''')
            stats['by_alert_type'] = dict(cursor.fetchall())
            
            conn.close()
            return stats
            
        except Exception as e:
            self.logger.error(f"Error generating statistics: {e}")
            return {}
    
    def export_to_json(self, output_file: str, start_date: Optional[datetime] = None):
        """Export registry changes to JSON file.
        
        Args:
            output_file: Output JSON file path
            start_date: Optional start date filter
        """
        try:
            if start_date:
                records = self.get_changes_by_date_range(start_date, datetime.now())
            else:
                conn = sqlite3.connect(str(self.db_path))
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM registry_changes ORDER BY timestamp DESC')
                records = [dict(row) for row in cursor.fetchall()]
                conn.close()
            
            with open(output_file, 'w') as f:
                json.dump(records, f, indent=2)
                
            self.logger.info(f"Data exported to {output_file}")
            
        except Exception as e:
            self.logger.error(f"Error exporting to JSON: {e}")
    
    def cleanup_old_records(self, days: int = 90):
        """Remove records older than specified days.
        
        Args:
            days: Days to retain (default 90 days)
        """
        with self.lock:
            try:
                conn = sqlite3.connect(str(self.db_path))
                cursor = conn.cursor()
                
                cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
                
                # Delete old changes and associated alerts
                cursor.execute('''
                    DELETE FROM registry_changes 
                    WHERE timestamp < ?
                ''', (cutoff_date,))
                
                deleted_count = cursor.rowcount
                conn.commit()
                conn.close()
                
                self.logger.info(f"Deleted {deleted_count} records older than {days} days")
                
            except Exception as e:
                self.logger.error(f"Error cleaning up old records: {e}")
