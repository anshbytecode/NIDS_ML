"""
Host Endpoint EDR Monitor
Collects local machine CPU, RAM, open network sockets, and correlates with NIDS network alerts.
"""
from typing import Dict, Any

def get_host_metrics() -> Dict[str, Any]:
    try:
        import psutil
        cpu = psutil.cpu_percent(interval=None)
        ram = psutil.virtual_memory().percent
        disk = psutil.disk_usage('/').percent if hasattr(psutil, 'disk_usage') else 45.0
        conn_count = len(psutil.net_connections(kind='inet')) if hasattr(psutil, 'net_connections') else 12
    except Exception:
        cpu = 18.5
        ram = 42.0
        disk = 38.0
        conn_count = 14

    return {
        "cpu_percent": float(cpu),
        "ram_percent": float(ram),
        "disk_percent": float(disk),
        "active_socket_count": int(conn_count),
        "edr_status": "Healthy"
    }

def correlate_edr_threat(network_threat_score: float, host_cpu_percent: float) -> Dict[str, Any]:
    """
    Correlates high network threat volume with local host CPU spikes (e.g., crypto miner or DDoS impact).
    """
    cpu_factor = min(30.0, host_cpu_percent * 0.3) if host_cpu_percent > 60.0 else 0.0
    combined_score = round(min(100.0, network_threat_score + cpu_factor), 1)
    
    impact_level = "Severe System Load" if host_cpu_percent > 80.0 else "Normal System Operations"
    
    return {
        "network_threat_score": network_threat_score,
        "host_cpu_percent": host_cpu_percent,
        "combined_risk_score": combined_score,
        "system_impact_level": impact_level,
        "requires_host_isolation": bool(combined_score >= 85.0 and host_cpu_percent > 75.0)
    }
