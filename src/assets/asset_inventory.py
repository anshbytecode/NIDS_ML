"""
Host Asset Discovery & Inventory Management
Maintains a dynamic inventory of observed network endpoints, device types, open services, and risk ratings.
"""
from typing import Dict, Any, List

MANAGED_ASSETS = [
    {
        "ip": "10.0.0.15",
        "hostname": "prod-web-ingress-01",
        "device_type": "Linux Web Server (Nginx)",
        "observed_ports": [80, 443],
        "mac_address": "00:1A:2B:3C:4D:5E",
        "criticality": "HIGH",
        "threat_encounters": 342,
        "risk_score": 78.5,
        "status": "Monitored"
    },
    {
        "ip": "10.0.0.1",
        "hostname": "core-gateway-router",
        "device_type": "Edge Firewall / Gateway",
        "observed_ports": [22, 53, 80],
        "mac_address": "00:1A:2B:99:88:77",
        "criticality": "CRITICAL",
        "threat_encounters": 210,
        "risk_score": 64.0,
        "status": "Healthy"
    },
    {
        "ip": "10.0.0.88",
        "hostname": "app-internal-api-srv",
        "device_type": "Internal Microservice (Docker)",
        "observed_ports": [8443, 9090],
        "mac_address": "02:42:AC:11:00:02",
        "criticality": "HIGH",
        "threat_encounters": 128,
        "risk_score": 82.0,
        "status": "Under Investigation"
    },
    {
        "ip": "10.0.0.10",
        "hostname": "backup-nas-storage",
        "device_type": "Network Attached Storage",
        "observed_ports": [21, 445, 2049],
        "mac_address": "00:11:32:AA:BB:CC",
        "criticality": "MEDIUM",
        "threat_encounters": 94,
        "risk_score": 42.0,
        "status": "Normal"
    },
    {
        "ip": "192.168.1.105",
        "hostname": "dev-workstation-laptop",
        "device_type": "Windows 11 Client",
        "observed_ports": [135, 445],
        "mac_address": "A4:83:E7:12:34:56",
        "criticality": "LOW",
        "threat_encounters": 2,
        "risk_score": 12.0,
        "status": "Normal"
    }
]

def get_asset_inventory() -> List[Dict[str, Any]]:
    return list(MANAGED_ASSETS)

def discover_asset(ip: str, port: int = 80, protocol: str = "TCP"):
    for asset in MANAGED_ASSETS:
        if asset["ip"] == ip:
            if port not in asset["observed_ports"]:
                asset["observed_ports"].append(port)
            asset["threat_encounters"] += 1
            return asset
    # Auto-add newly discovered host
    new_asset = {
        "ip": ip,
        "hostname": f"discovered-host-{ip.replace('.', '-')}",
        "device_type": "Generic Network Host",
        "observed_ports": [port],
        "mac_address": "Dynamic (ARP)",
        "criticality": "MEDIUM",
        "threat_encounters": 1,
        "risk_score": 35.0,
        "status": "Discovered"
    }
    MANAGED_ASSETS.append(new_asset)
    return new_asset
