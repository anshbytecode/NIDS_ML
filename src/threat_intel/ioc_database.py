"""
Indicators of Compromise (IOC) Matching, Threat Feeds, and Suspicious Pattern Detection.
Tracks malicious domains, IPs, DNS tunneling indicators, and beaconing behaviors.
"""
import time
import math
from typing import Dict, Any, List

# Standard Enterprise IOC Threat Feeds
KNOWN_IOCS = {
    "ips": {
        "45.155.205.233": {"type": "Malware C2 / Botnet", "confidence": 0.98, "campaign": "CobaltStrike Beacon", "mitre": "T1071"},
        "185.220.101.5": {"type": "Tor Exit Node / Scanner", "confidence": 0.92, "campaign": "Recon Campaign", "mitre": "T1046"},
        "91.240.118.172": {"type": "Brute-Force Source", "confidence": 0.89, "campaign": "SSH Password Spray", "mitre": "T1110"},
        "194.26.29.112": {"type": "Data Exfiltration Endpoint", "confidence": 0.94, "campaign": "Stealer Exfil", "mitre": "T1048"},
        "103.145.13.4": {"type": "Phishing C2 Host", "confidence": 0.87, "campaign": "Credential Harvesting", "mitre": "T1566"}
    },
    "domains": {
        "c2-tunnel-update.xyz": {"type": "DNS Tunneling / C2", "confidence": 0.95, "campaign": "APT Emulation"},
        "malicious-login-update.xyz": {"type": "Credential Phishing", "confidence": 0.99, "campaign": "Banking Phish"},
        "secure-auth-gateway.top": {"type": "Typosquatting", "confidence": 0.91, "campaign": "Brand Abuse"},
        "data-sync-pool.cloud": {"type": "Exfiltration Receiver", "confidence": 0.88, "campaign": "Cloud Exfil"}
    }
}

def match_ioc(target: str) -> Dict[str, Any]:
    """Matches an IP or domain against known threat intelligence feeds."""
    target_clean = str(target).strip().lower()
    
    # Check IP IOCs
    if target_clean in KNOWN_IOCS["ips"]:
        info = KNOWN_IOCS["ips"][target_clean]
        return {
            "matched": True,
            "indicator": target_clean,
            "category": info["type"],
            "confidence": info["confidence"],
            "campaign": info["campaign"],
            "mitre_technique": info.get("mitre", "T1071"),
            "feed_source": "SentinelNet Global IOC Feed",
            "last_updated": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
    # Check Domain IOCs
    for domain, info in KNOWN_IOCS["domains"].items():
        if domain in target_clean:
            return {
                "matched": True,
                "indicator": target_clean,
                "category": info["type"],
                "confidence": info["confidence"],
                "campaign": info["campaign"],
                "mitre_technique": "T1071.004",
                "feed_source": "SentinelNet Domain Threat Feed",
                "last_updated": time.strftime("%Y-%m-%d %H:%M:%S")
            }
            
    return {"matched": False, "indicator": target_clean}

def calculate_domain_entropy(domain: str) -> float:
    """Calculates Shannon entropy of domain string to identify algorithmic DNS tunneling."""
    s = domain.split(".")[0] # Check subdomain / prefix
    if not s:
        return 0.0
    entropy = 0.0
    for char in set(s):
        p_x = float(s.count(char)) / len(s)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return round(entropy, 2)

def detect_dns_tunneling(query_name: str, payload_len: int = 0) -> Dict[str, Any]:
    """Detects DNS exfiltration or C2 tunneling through query entropy and length."""
    entropy = calculate_domain_entropy(query_name)
    length = len(query_name)
    
    is_suspicious = (entropy >= 3.8 and length > 28) or (length > 45)
    threat_score = min(99.0, max(5.0, (entropy * 18.0) + (length * 0.4))) if is_suspicious else 8.0
    
    return {
        "query": query_name,
        "entropy": entropy,
        "query_length": length,
        "is_tunneling_indicator": is_suspicious,
        "threat_score": round(threat_score, 1),
        "reason": "High Shannon entropy and excessive query length indicative of Base32/Base64 DNS tunneling" if is_suspicious else "Normal lexical structure"
    }

def detect_beaconing(connection_timestamps: List[float], jitter_threshold: float = 0.25) -> Dict[str, Any]:
    """Detects periodic C2 beaconing with low interval variance."""
    if len(connection_timestamps) < 4:
        return {"is_beaconing": False, "confidence": 0.0, "reason": "Insufficient session samples"}
        
    deltas = [connection_timestamps[i] - connection_timestamps[i-1] for i in range(1, len(connection_timestamps))]
    mean_interval = sum(deltas) / len(deltas)
    if mean_interval == 0:
        return {"is_beaconing": False, "confidence": 0.0, "reason": "Zero interval"}
        
    variance = sum((d - mean_interval)**2 for d in deltas) / len(deltas)
    std_dev = math.sqrt(variance)
    jitter = std_dev / mean_interval
    
    is_beacon = (jitter <= jitter_threshold and mean_interval >= 5.0)
    return {
        "is_beaconing": is_beacon,
        "mean_interval_sec": round(mean_interval, 2),
        "jitter_ratio": round(jitter, 3),
        "confidence": round(max(0.0, min(1.0, 1.0 - jitter)), 2),
        "reason": f"Periodic communication observed every ~{int(mean_interval)}s (low jitter: {jitter:.2f})" if is_beacon else "Natural bursty connection pattern"
    }
