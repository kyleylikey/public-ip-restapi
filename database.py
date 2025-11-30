"""
Database module for storing historical IP lookups
Uses SQLite for lightweight persistence
"""

import sqlite3
import json
import os
from datetime import datetime
from typing import List, Optional, Dict, Any
from config import Config


class IPDatabase:
    """Database class for storing and retrieving IP lookup history"""
    
    def __init__(self, db_path: str = None):
        """
        Initialize database connection
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path or getattr(Config, 'DATABASE_PATH', 'ip_history.db')
        self._init_database()
    
    def _init_database(self):
        """Initialize database tables if they don't exist"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Create IP lookups table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ip_lookups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL,
                    ip_version TEXT,
                    country_name TEXT,
                    country_code TEXT,
                    region_name TEXT,
                    city TEXT,
                    zip_code TEXT,
                    latitude REAL,
                    longitude REAL,
                    timezone TEXT,
                    isp TEXT,
                    asn TEXT,
                    hostname TEXT,
                    is_proxy INTEGER DEFAULT 0,
                    is_vpn INTEGER DEFAULT 0,
                    is_tor INTEGER DEFAULT 0,
                    raw_data TEXT,
                    lookup_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    source TEXT DEFAULT 'ipapi.co'
                )
            ''')
            
            # Create index on ip_address for faster lookups
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_ip_address 
                ON ip_lookups(ip_address)
            ''')
            
            # Create index on lookup_timestamp for time-based queries
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_timestamp 
                ON ip_lookups(lookup_timestamp)
            ''')
            
            # Create IP monitoring table for scheduled tracking
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ip_monitors (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL UNIQUE,
                    monitor_name TEXT,
                    check_interval_minutes INTEGER DEFAULT 60,
                    last_checked DATETIME,
                    last_change_detected DATETIME,
                    is_active INTEGER DEFAULT 1,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create IP changes history table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ip_changes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    monitor_id INTEGER,
                    old_data TEXT,
                    new_data TEXT,
                    change_type TEXT,
                    detected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (monitor_id) REFERENCES ip_monitors(id)
                )
            ''')
            
            conn.commit()
    
    def store_lookup(self, ip_data: Dict[str, Any]) -> int:
        """
        Store an IP lookup result in the database
        Args:
            ip_data: Dictionary containing IP information
        Returns:
            ID of inserted record
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO ip_lookups (
                    ip_address, ip_version, country_name, country_code,
                    region_name, city, zip_code, latitude, longitude,
                    timezone, isp, asn, hostname, is_proxy, is_vpn,
                    is_tor, raw_data, source
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                ip_data.get('ip'),
                ip_data.get('type', ip_data.get('version')),
                ip_data.get('country_name'),
                ip_data.get('country_code'),
                ip_data.get('region_name', ip_data.get('region')),
                ip_data.get('city'),
                ip_data.get('zip', ip_data.get('postal')),
                ip_data.get('latitude'),
                ip_data.get('longitude'),
                ip_data.get('timezone'),
                ip_data.get('isp', ip_data.get('org')),
                ip_data.get('asn'),
                ip_data.get('hostname'),
                1 if ip_data.get('proxy') else 0,
                1 if ip_data.get('vpn') else 0,
                1 if ip_data.get('tor') else 0,
                json.dumps(ip_data),
                ip_data.get('source', 'ipapi.co')
            ))
            
            conn.commit()
            return cursor.lastrowid
    
    def get_lookup_history(self, ip_address: str = None, limit: int = 100) -> List[Dict]:
        """
        Get lookup history from database
        Args:
            ip_address: Optional filter by IP address
            limit: Maximum number of records to return
        Returns:
            List of lookup records
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            if ip_address:
                cursor.execute('''
                    SELECT * FROM ip_lookups 
                    WHERE ip_address = ? 
                    ORDER BY lookup_timestamp DESC 
                    LIMIT ?
                ''', (ip_address, limit))
            else:
                cursor.execute('''
                    SELECT * FROM ip_lookups 
                    ORDER BY lookup_timestamp DESC 
                    LIMIT ?
                ''', (limit,))
            
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
    
    def get_unique_ips(self) -> List[str]:
        """Get list of unique IP addresses in the database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT DISTINCT ip_address FROM ip_lookups ORDER BY ip_address')
            return [row[0] for row in cursor.fetchall()]
    
    def get_statistics(self) -> Dict:
        """Get database statistics"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Total lookups
            cursor.execute('SELECT COUNT(*) FROM ip_lookups')
            total_lookups = cursor.fetchone()[0]
            
            # Unique IPs
            cursor.execute('SELECT COUNT(DISTINCT ip_address) FROM ip_lookups')
            unique_ips = cursor.fetchone()[0]
            
            # Lookups by country
            cursor.execute('''
                SELECT country_name, COUNT(*) as count 
                FROM ip_lookups 
                WHERE country_name IS NOT NULL
                GROUP BY country_name 
                ORDER BY count DESC 
                LIMIT 10
            ''')
            top_countries = [{'country': row[0], 'count': row[1]} for row in cursor.fetchall()]
            
            # Recent lookups
            cursor.execute('''
                SELECT ip_address, lookup_timestamp 
                FROM ip_lookups 
                ORDER BY lookup_timestamp DESC 
                LIMIT 5
            ''')
            recent_lookups = [{'ip': row[0], 'timestamp': row[1]} for row in cursor.fetchall()]
            
            return {
                'total_lookups': total_lookups,
                'unique_ips': unique_ips,
                'top_countries': top_countries,
                'recent_lookups': recent_lookups
            }
    
    def add_monitor(self, ip_address: str, monitor_name: str = None, 
                    check_interval: int = 60) -> int:
        """
        Add an IP address to monitoring
        Args:
            ip_address: IP address to monitor
            monitor_name: Optional friendly name
            check_interval: Check interval in minutes
        Returns:
            Monitor ID
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO ip_monitors 
                (ip_address, monitor_name, check_interval_minutes)
                VALUES (?, ?, ?)
            ''', (ip_address, monitor_name or ip_address, check_interval))
            
            conn.commit()
            return cursor.lastrowid
    
    def get_monitors(self, active_only: bool = True) -> List[Dict]:
        """Get list of monitored IP addresses"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            if active_only:
                cursor.execute('SELECT * FROM ip_monitors WHERE is_active = 1')
            else:
                cursor.execute('SELECT * FROM ip_monitors')
            
            return [dict(row) for row in cursor.fetchall()]
    
    def record_change(self, monitor_id: int, old_data: Dict, 
                      new_data: Dict, change_type: str) -> int:
        """Record an IP change detection"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO ip_changes (monitor_id, old_data, new_data, change_type)
                VALUES (?, ?, ?, ?)
            ''', (monitor_id, json.dumps(old_data), json.dumps(new_data), change_type))
            
            # Update last_change_detected
            cursor.execute('''
                UPDATE ip_monitors 
                SET last_change_detected = CURRENT_TIMESTAMP,
                    last_checked = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (monitor_id,))
            
            conn.commit()
            return cursor.lastrowid
    
    def get_changes(self, monitor_id: int = None, limit: int = 50) -> List[Dict]:
        """Get IP change history"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            if monitor_id:
                cursor.execute('''
                    SELECT c.*, m.ip_address, m.monitor_name
                    FROM ip_changes c
                    JOIN ip_monitors m ON c.monitor_id = m.id
                    WHERE c.monitor_id = ?
                    ORDER BY c.detected_at DESC
                    LIMIT ?
                ''', (monitor_id, limit))
            else:
                cursor.execute('''
                    SELECT c.*, m.ip_address, m.monitor_name
                    FROM ip_changes c
                    JOIN ip_monitors m ON c.monitor_id = m.id
                    ORDER BY c.detected_at DESC
                    LIMIT ?
                ''', (limit,))
            
            return [dict(row) for row in cursor.fetchall()]
    
    def search_lookups(self, query: str) -> List[Dict]:
        """
        Search lookups by IP, country, city, or ISP
        Args:
            query: Search query string
        Returns:
            List of matching records
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            search_pattern = f'%{query}%'
            cursor.execute('''
                SELECT * FROM ip_lookups 
                WHERE ip_address LIKE ? 
                   OR country_name LIKE ? 
                   OR city LIKE ? 
                   OR isp LIKE ?
                ORDER BY lookup_timestamp DESC
                LIMIT 100
            ''', (search_pattern, search_pattern, search_pattern, search_pattern))
            
            return [dict(row) for row in cursor.fetchall()]
    
    def delete_lookup(self, lookup_id: int) -> bool:
        """Delete a lookup record by ID"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM ip_lookups WHERE id = ?', (lookup_id,))
            conn.commit()
            return cursor.rowcount > 0
    
    def clear_history(self, before_date: str = None) -> int:
        """
        Clear lookup history
        Args:
            before_date: Optional date string (YYYY-MM-DD) to clear records before
        Returns:
            Number of deleted records
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            if before_date:
                cursor.execute(
                    'DELETE FROM ip_lookups WHERE DATE(lookup_timestamp) < ?',
                    (before_date,)
                )
            else:
                cursor.execute('DELETE FROM ip_lookups')
            
            conn.commit()
            return cursor.rowcount
