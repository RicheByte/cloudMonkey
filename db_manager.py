#!/usr/bin/env python3
"""
Database Manager for Cloud Security Scanner
Provides persistent storage and historical comparison capabilities

Author: RicheByte
Version: 1.0
"""

import sqlite3
import json
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class ScanDelta:
    """Represents changes between two scans"""
    new_findings: List[Dict] = field(default_factory=list)
    resolved_findings: List[Dict] = field(default_factory=list)
    risk_score_change: int = 0
    severity_changes: Dict = field(default_factory=dict)
    timestamp_old: str = ""
    timestamp_new: str = ""


class DatabaseManager:
    """SQLite-based persistence for scan results and historical tracking"""
    
    def __init__(self, db_path: str = "scan_history.db"):
        self.db_path = db_path
        self.conn = None
        self.init_database()
    
    def init_database(self):
        """Initialize database schema"""
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        
        cursor = self.conn.cursor()
        
        # Scans table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                scan_mode TEXT,
                scan_duration REAL,
                risk_score INTEGER,
                total_findings INTEGER,
                verified_findings INTEGER,
                results_json TEXT,
                scan_hash TEXT UNIQUE,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Findings table (normalized for better querying)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                finding_type TEXT,
                severity TEXT,
                location TEXT,
                description TEXT,
                evidence TEXT,
                confidence TEXT,
                verified BOOLEAN,
                risk_score INTEGER,
                false_positive_score REAL,
                timestamp TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
        """)
        
        # Trends table (for dashboard analytics)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS trends (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                date TEXT NOT NULL,
                risk_score INTEGER,
                critical_count INTEGER,
                high_count INTEGER,
                medium_count INTEGER,
                low_count INTEGER,
                info_count INTEGER,
                UNIQUE(domain, date)
            )
        """)
        
        # Create indexes for performance
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_trends_domain_date ON trends(domain, date)")
        
        self.conn.commit()
    
    def _generate_scan_hash(self, results: Dict) -> str:
        """Generate unique hash for scan results to detect duplicates"""
        # Use domain + findings to create hash
        key_data = {
            'domain': results['domain'],
            'findings': sorted([f['type'] for f in results['findings']])
        }
        return hashlib.sha256(json.dumps(key_data, sort_keys=True).encode()).hexdigest()[:16]
    
    def save_scan(self, results: Dict) -> int:
        """Save scan results to database"""
        cursor = self.conn.cursor()
        
        scan_hash = self._generate_scan_hash(results)
        
        # Check if identical scan already exists
        cursor.execute("SELECT id FROM scans WHERE scan_hash = ?", (scan_hash,))
        existing = cursor.fetchone()
        if existing:
            print(f"ℹ️  Identical scan already exists (ID: {existing[0]})")
            return existing[0]
        
        # Insert scan record
        cursor.execute("""
            INSERT INTO scans 
            (domain, timestamp, scan_mode, scan_duration, risk_score, 
             total_findings, verified_findings, results_json, scan_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            results['domain'],
            results['timestamp'],
            results.get('scan_mode', 'normal'),
            results['scan_duration'],
            results['risk_score'],
            len(results['findings']),
            sum(1 for f in results['findings'] if f.get('verified', False)),
            json.dumps(results),
            scan_hash
        ))
        
        scan_id = cursor.lastrowid
        
        # Insert findings
        for finding in results['findings']:
            cursor.execute("""
                INSERT INTO findings
                (scan_id, finding_type, severity, location, description, 
                 evidence, confidence, verified, risk_score, false_positive_score, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id,
                finding['type'],
                finding['severity'],
                finding['location'],
                finding['description'],
                finding['evidence'],
                finding['confidence'],
                finding.get('verified', False),
                finding.get('risk_score', 0),
                finding.get('false_positive_score', 0.0),
                finding['timestamp']
            ))
        
        # Update trends table
        self._update_trends(results)
        
        self.conn.commit()
        return scan_id
    
    def _update_trends(self, results: Dict):
        """Update daily trends for dashboard analytics"""
        cursor = self.conn.cursor()
        
        date = datetime.now().strftime('%Y-%m-%d')
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        
        for finding in results['findings']:
            severity = finding['severity']
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        cursor.execute("""
            INSERT OR REPLACE INTO trends
            (domain, date, risk_score, critical_count, high_count, 
             medium_count, low_count, info_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            results['domain'],
            date,
            results['risk_score'],
            severity_counts['CRITICAL'],
            severity_counts['HIGH'],
            severity_counts['MEDIUM'],
            severity_counts['LOW'],
            severity_counts['INFO']
        ))
        
        self.conn.commit()
    
    def get_latest_scan(self, domain: str) -> Optional[Dict]:
        """Get most recent scan for a domain"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT results_json FROM scans
            WHERE domain = ?
            ORDER BY timestamp DESC
            LIMIT 1
        """, (domain,))
        
        row = cursor.fetchone()
        if row:
            return json.loads(row['results_json'])
        return None
    
    def get_scan_history(self, domain: str, limit: int = 10) -> List[Dict]:
        """Get scan history for a domain"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT id, timestamp, scan_mode, scan_duration, risk_score, 
                   total_findings, verified_findings
            FROM scans
            WHERE domain = ?
            ORDER BY timestamp DESC
            LIMIT ?
        """, (domain, limit))
        
        return [dict(row) for row in cursor.fetchall()]
    
    def compare_scans(self, domain: str, scan1_id: Optional[int] = None, 
                     scan2_id: Optional[int] = None) -> ScanDelta:
        """Compare two scans and return delta"""
        cursor = self.conn.cursor()
        
        # If IDs not provided, compare last two scans
        if not scan1_id or not scan2_id:
            cursor.execute("""
                SELECT id, results_json, timestamp FROM scans
                WHERE domain = ?
                ORDER BY timestamp DESC
                LIMIT 2
            """, (domain,))
            
            rows = cursor.fetchall()
            if len(rows) < 2:
                return ScanDelta()
            
            scan2 = json.loads(rows[0]['results_json'])  # Latest
            scan1 = json.loads(rows[1]['results_json'])  # Previous
            timestamp_new = rows[0]['timestamp']
            timestamp_old = rows[1]['timestamp']
        else:
            cursor.execute("SELECT results_json, timestamp FROM scans WHERE id = ?", (scan1_id,))
            row1 = cursor.fetchone()
            cursor.execute("SELECT results_json, timestamp FROM scans WHERE id = ?", (scan2_id,))
            row2 = cursor.fetchone()
            
            if not row1 or not row2:
                return ScanDelta()
            
            scan1 = json.loads(row1['results_json'])
            scan2 = json.loads(row2['results_json'])
            timestamp_old = row1['timestamp']
            timestamp_new = row2['timestamp']
        
        # Calculate delta
        delta = ScanDelta(
            timestamp_old=timestamp_old,
            timestamp_new=timestamp_new,
            risk_score_change=scan2['risk_score'] - scan1['risk_score']
        )
        
        # Create finding signatures for comparison
        old_findings = {self._finding_signature(f): f for f in scan1['findings']}
        new_findings = {self._finding_signature(f): f for f in scan2['findings']}
        
        # Find new and resolved findings
        delta.new_findings = [
            f for sig, f in new_findings.items() if sig not in old_findings
        ]
        delta.resolved_findings = [
            f for sig, f in old_findings.items() if sig not in new_findings
        ]
        
        # Severity changes
        old_severity = self._count_by_severity(scan1['findings'])
        new_severity = self._count_by_severity(scan2['findings'])
        
        delta.severity_changes = {
            severity: new_severity.get(severity, 0) - old_severity.get(severity, 0)
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
        }
        
        return delta
    
    def _finding_signature(self, finding: Dict) -> str:
        """Create unique signature for finding comparison"""
        return f"{finding['type']}:{finding['location']}"
    
    def _count_by_severity(self, findings: List[Dict]) -> Dict[str, int]:
        """Count findings by severity"""
        counts = {}
        for finding in findings:
            severity = finding['severity']
            counts[severity] = counts.get(severity, 0) + 1
        return counts
    
    def get_trends(self, domain: str, days: int = 30) -> List[Dict]:
        """Get risk trends over time"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT * FROM trends
            WHERE domain = ?
            ORDER BY date DESC
            LIMIT ?
        """, (domain, days))
        
        return [dict(row) for row in cursor.fetchall()]
    
    def get_statistics(self) -> Dict:
        """Get overall database statistics"""
        cursor = self.conn.cursor()
        
        stats = {}
        
        # Total scans
        cursor.execute("SELECT COUNT(*) as count FROM scans")
        stats['total_scans'] = cursor.fetchone()['count']
        
        # Unique domains
        cursor.execute("SELECT COUNT(DISTINCT domain) as count FROM scans")
        stats['unique_domains'] = cursor.fetchone()['count']
        
        # Total findings
        cursor.execute("SELECT COUNT(*) as count FROM findings")
        stats['total_findings'] = cursor.fetchone()['count']
        
        # Average risk score
        cursor.execute("SELECT AVG(risk_score) as avg FROM scans")
        stats['avg_risk_score'] = round(cursor.fetchone()['avg'] or 0, 2)
        
        # Most scanned domain
        cursor.execute("""
            SELECT domain, COUNT(*) as count FROM scans
            GROUP BY domain
            ORDER BY count DESC
            LIMIT 1
        """)
        row = cursor.fetchone()
        stats['most_scanned_domain'] = {'domain': row['domain'], 'count': row['count']} if row else None
        
        return stats
    
    def export_domain_data(self, domain: str, output_file: str):
        """Export all scan data for a domain to JSON"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT results_json FROM scans
            WHERE domain = ?
            ORDER BY timestamp DESC
        """, (domain,))
        
        scans = [json.loads(row['results_json']) for row in cursor.fetchall()]
        
        export_data = {
            'domain': domain,
            'export_timestamp': datetime.now().isoformat(),
            'total_scans': len(scans),
            'scans': scans
        }
        
        Path(output_file).write_text(json.dumps(export_data, indent=2), encoding='utf-8')
    
    def cleanup_old_scans(self, days: int = 90):
        """Remove scans older than specified days"""
        cursor = self.conn.cursor()
        cutoff_date = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        cutoff_date = cutoff_date.replace(day=cutoff_date.day - days)
        
        cursor.execute("""
            DELETE FROM scans
            WHERE timestamp < ?
        """, (cutoff_date.isoformat(),))
        
        deleted = cursor.rowcount
        self.conn.commit()
        return deleted
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
