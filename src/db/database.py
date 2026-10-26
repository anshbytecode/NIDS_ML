import sqlite3
import os
import json
import uuid
import datetime
from src.config import DB_PATH

def get_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    
    # Alerts Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        src_ip TEXT,
        dst_ip TEXT,
        dst_port INTEGER,
        protocol TEXT,
        attack_type TEXT,
        threat_score REAL,
        severity TEXT,
        confidence REAL,
        detection_reason TEXT,
        acknowledged INTEGER DEFAULT 0,
        raw_flow TEXT
    )
    """)
    
    # Incidents Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ticket_id TEXT UNIQUE,
        timestamp TEXT,
        src_ip TEXT,
        dst_ip TEXT,
        dst_port INTEGER,
        attack_type TEXT,
        threat_score REAL,
        severity TEXT,
        confidence REAL,
        status TEXT DEFAULT 'New',
        assignee TEXT DEFAULT 'SOC Analyst',
        resolution_notes TEXT DEFAULT '',
        playbook_status TEXT DEFAULT 'Completed'
    )
    """)
    
    # Blocklist Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS blocklist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT UNIQUE,
        reason TEXT,
        severity TEXT,
        timestamp TEXT,
        rule_source TEXT DEFAULT 'Automated Playbook'
    )
    """)
    
    # False Positive Feedback Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS false_positives (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        flow_json TEXT,
        original_prediction TEXT,
        user_notes TEXT
    )
    """)
    
    conn.commit()
    conn.close()

def log_alert(alert_data: dict) -> int:
    conn = get_connection()
    cursor = conn.cursor()
    now = alert_data.get("timestamp") or datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    raw_flow_str = json.dumps(alert_data.get("raw_flow", {}))
    
    cursor.execute("""
    INSERT INTO alerts (
        timestamp, src_ip, dst_ip, dst_port, protocol,
        attack_type, threat_score, severity, confidence,
        detection_reason, acknowledged, raw_flow
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        now,
        alert_data.get("src_ip", "0.0.0.0"),
        alert_data.get("dst_ip", "0.0.0.0"),
        alert_data.get("dst_port", 0),
        alert_data.get("protocol", "TCP"),
        alert_data.get("attack_type", "Normal"),
        float(alert_data.get("threat_score", 0.0)),
        alert_data.get("severity", "LOW"),
        float(alert_data.get("confidence", 0.95)),
        alert_data.get("detection_reason", "ML Consensus"),
        1 if alert_data.get("acknowledged") else 0,
        raw_flow_str
    ))
    alert_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return alert_id

def get_recent_alerts(limit=50):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows

def get_threat_summary():
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) as total FROM alerts")
    total_alerts = cursor.fetchone()["total"]
    
    cursor.execute("SELECT COUNT(*) as threats FROM alerts WHERE severity IN ('MEDIUM', 'HIGH', 'CRITICAL')")
    threat_alerts = cursor.fetchone()["threats"]
    
    cursor.execute("SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity")
    severity_dist = {r["severity"]: r["cnt"] for r in cursor.fetchall()}
    
    cursor.execute("SELECT attack_type, COUNT(*) as cnt FROM alerts WHERE attack_type != 'Normal' GROUP BY attack_type")
    attack_dist = {r["attack_type"]: r["cnt"] for r in cursor.fetchall()}
    
    cursor.execute("SELECT COUNT(*) as count FROM incidents WHERE status != 'Resolved'")
    active_incidents = cursor.fetchone()["count"]
    
    cursor.execute("SELECT COUNT(*) as count FROM blocklist")
    blocked_ips_count = cursor.fetchone()["count"]
    
    conn.close()
    return {
        "total_alerts": total_alerts,
        "threat_count": threat_alerts,
        "anomaly_rate": round((threat_alerts / total_alerts * 100), 1) if total_alerts > 0 else 0.0,
        "active_incidents": active_incidents,
        "blocked_ips_count": blocked_ips_count,
        "severity_distribution": severity_dist,
        "attack_distribution": attack_dist
    }

def create_incident(data: dict) -> str:
    conn = get_connection()
    cursor = conn.cursor()
    
    random_suffix = str(uuid.uuid4()).split("-")[0].upper()
    ticket_id = f"INC-2026-{random_suffix}"
    now = data.get("timestamp") or datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    cursor.execute("""
    INSERT INTO incidents (
        ticket_id, timestamp, src_ip, dst_ip, dst_port,
        attack_type, threat_score, severity, confidence,
        status, assignee, resolution_notes, playbook_status
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        ticket_id,
        now,
        data.get("src_ip", "0.0.0.0"),
        data.get("dst_ip", "0.0.0.0"),
        data.get("dst_port", 0),
        data.get("attack_type", "Unknown"),
        float(data.get("threat_score", 0.0)),
        data.get("severity", "MEDIUM"),
        float(data.get("confidence", 0.9)),
        data.get("status", "New"),
        data.get("assignee", "SOC Analyst"),
        data.get("resolution_notes", ""),
        data.get("playbook_status", "Active")
    ))
    conn.commit()
    conn.close()
    return ticket_id

def update_incident_status(ticket_id: str, status: str, notes: str = None):
    conn = get_connection()
    cursor = conn.cursor()
    if notes is not None:
        cursor.execute("""
        UPDATE incidents SET status = ?, resolution_notes = ? WHERE ticket_id = ?
        """, (status, notes, ticket_id))
    else:
        cursor.execute("""
        UPDATE incidents SET status = ? WHERE ticket_id = ?
        """, (status, ticket_id))
    conn.commit()
    conn.close()

def get_incidents(status_filter=None):
    conn = get_connection()
    cursor = conn.cursor()
    if status_filter:
        cursor.execute("SELECT * FROM incidents WHERE status = ? ORDER BY id DESC", (status_filter,))
    else:
        cursor.execute("SELECT * FROM incidents ORDER BY id DESC")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows

def add_to_blocklist(ip: str, reason: str = "Automated NIDS Threat Block", severity: str = "HIGH"):
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        cursor.execute("""
        INSERT OR REPLACE INTO blocklist (ip, reason, severity, timestamp, rule_source)
        VALUES (?, ?, ?, ?, 'Automated Playbook')
        """, (ip, reason, severity, now))
        conn.commit()
    finally:
        conn.close()

def get_blocklist():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM blocklist ORDER BY id DESC")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows

def record_false_positive(flow_dict: dict, attack_type: str, user_notes: str = ""):
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
    INSERT INTO false_positives (timestamp, flow_json, original_prediction, user_notes)
    VALUES (?, ?, ?, ?)
    """, (now, json.dumps(flow_dict), attack_type, user_notes))
    conn.commit()
    conn.close()
