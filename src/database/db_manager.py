"""
Database management for CyberSentinel
SQLite database for storing threat intelligence data
"""

import sqlite3
from pathlib import Path
import logging
from datetime import datetime

logger = logging.getLogger("cybersentinel")

class DatabaseManager:
    """Manages SQLite database operations"""
    
    def __init__(self, db_path=None):
        if db_path is None:
            db_path = Path(__file__).parent.parent.parent / "data" / "cybersentinel.db"
        
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(exist_ok=True)
        self.conn = None
        
    def connect(self):
        """Establish database connection"""
        try:
            self.conn = sqlite3.connect(self.db_path)
            self.conn.row_factory = sqlite3.Row  # Enable dict-like access
            return self.conn
        except Exception as e:
            logger.error(f"Database connection error: {e}")
            raise
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
            self.conn = None
    
    def initialize(self):
        """Create database tables"""
        conn = self.connect()
        cursor = conn.cursor()
        
        try:
            # CVE/Vulnerabilities table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT UNIQUE NOT NULL,
                    description TEXT,
                    severity TEXT,
                    cvss_score REAL,
                    published_date TEXT,
                    last_modified TEXT,
                    source TEXT DEFAULT 'NVD',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # IP Reputation table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ip_reputation (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT UNIQUE NOT NULL,
                    abuse_confidence_score INTEGER,
                    country_code TEXT,
                    usage_type TEXT,
                    is_whitelisted BOOLEAN DEFAULT 0,
                    total_reports INTEGER DEFAULT 0,
                    last_checked TIMESTAMP,
                    source TEXT DEFAULT 'AbuseIPDB',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # File/URL Scan Results table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    positives INTEGER,
                    total_scans INTEGER,
                    scan_date TEXT,
                    malicious BOOLEAN,
                    source TEXT DEFAULT 'VirusTotal',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Threat Intelligence Pulses table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_pulses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pulse_id TEXT UNIQUE,
                    name TEXT,
                    description TEXT,
                    author TEXT,
                    tags TEXT,
                    created_date TEXT,
                    modified_date TEXT,
                    indicator_count INTEGER,
                    source TEXT DEFAULT 'AlienVault OTX',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Query History table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS query_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    query_type TEXT NOT NULL,
                    query_value TEXT NOT NULL,
                    result_count INTEGER,
                    success BOOLEAN,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
            logger.info("Database tables initialized successfully")
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Database initialization error: {e}")
            raise
        finally:
            self.close()
    
    def execute_query(self, query, params=None):
        """Execute a SELECT query"""
        conn = self.connect()
        cursor = conn.cursor()
        
        try:
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            
            results = cursor.fetchall()
            return [dict(row) for row in results]
            
        except Exception as e:
            logger.error(f"Query execution error: {e}")
            return []
        finally:
            self.close()
    
    def execute_update(self, query, params=None):
        """Execute an INSERT/UPDATE/DELETE query"""
        conn = self.connect()
        cursor = conn.cursor()
        
        try:
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            
            conn.commit()
            return cursor.lastrowid
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Update execution error: {e}")
            return None
        finally:
            self.close()
    
    def save_vulnerability(self, cve_data):
        """Save CVE vulnerability data"""
        query = '''
            INSERT OR REPLACE INTO vulnerabilities 
            (cve_id, description, severity, cvss_score, published_date, last_modified)
            VALUES (?, ?, ?, ?, ?, ?)
        '''
        params = (
            cve_data.get('cve_id'),
            cve_data.get('description'),
            cve_data.get('severity'),
            cve_data.get('cvss_score'),
            cve_data.get('published_date'),
            cve_data.get('last_modified')
        )
        return self.execute_update(query, params)
    
    def save_ip_reputation(self, ip_data):
        """Save IP reputation data"""
        query = '''
            INSERT OR REPLACE INTO ip_reputation 
            (ip_address, abuse_confidence_score, country_code, usage_type, 
             total_reports, last_checked)
            VALUES (?, ?, ?, ?, ?, ?)
        '''
        params = (
            ip_data.get('ip_address'),
            ip_data.get('abuse_confidence_score'),
            ip_data.get('country_code'),
            ip_data.get('usage_type'),
            ip_data.get('total_reports'),
            datetime.now().isoformat()
        )
        return self.execute_update(query, params)
    
    def get_recent_vulnerabilities(self, limit=10):
        """Get recent vulnerabilities"""
        query = '''
            SELECT * FROM vulnerabilities 
            ORDER BY published_date DESC 
            LIMIT ?
        '''
        return self.execute_query(query, (limit,))
    
    def get_statistics(self):
        """Get database statistics"""
        stats = {}
        
        # Total vulnerabilities
        result = self.execute_query('SELECT COUNT(*) as count FROM vulnerabilities')
        stats['total_vulnerabilities'] = result[0]['count'] if result else 0
        
        # Total IP checks
        result = self.execute_query('SELECT COUNT(*) as count FROM ip_reputation')
        stats['total_ip_checks'] = result[0]['count'] if result else 0
        
        # Total scans
        result = self.execute_query('SELECT COUNT(*) as count FROM scan_results')
        stats['total_scans'] = result[0]['count'] if result else 0
        
        # Total threat pulses
        result = self.execute_query('SELECT COUNT(*) as count FROM threat_pulses')
        stats['total_threat_pulses'] = result[0]['count'] if result else 0
        
        return stats
