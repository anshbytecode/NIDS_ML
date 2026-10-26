"""
Explainable AI (XAI) Attribution Module for SentinelNet NIDS
Decomposes threat and anomaly scores into interpretable feature contributions.
"""
from typing import Dict, Any, List

class NIDSExplainer:
    def __init__(self):
        # Baseline normal values for standard web/DNS traffic
        self.baselines = {
            "count": 3.0,
            "src_bytes": 350.0,
            "dst_bytes": 4200.0,
            "duration": 0.2,
            "serror_rate": 0.0,
            "rerror_rate": 0.0,
            "diff_srv_rate": 0.05,
            "num_failed_logins": 0.0
        }

    def explain(self, flow: Dict[str, Any], prediction: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """
        Calculates feature attribution weights showing why a flow was classified as malicious or anomalous.
        """
        contributions = []
        
        count = float(flow.get("count", 1))
        src_bytes = float(flow.get("src_bytes", 0))
        dst_bytes = float(flow.get("dst_bytes", 0))
        serror_rate = float(flow.get("serror_rate", 0))
        rerror_rate = float(flow.get("rerror_rate", 0))
        diff_srv = float(flow.get("diff_srv_rate", 0))
        flag = str(flow.get("flag", "SF")).upper()
        failed_logins = int(flow.get("num_failed_logins", 0))
        
        # 1. Connection frequency attribution
        if count > 15:
            weight = min(42.0, (count / 150.0) * 40.0)
            contributions.append({
                "feature": "count",
                "value": count,
                "impact_pct": round(weight, 1),
                "direction": "+",
                "explanation": f"Abnormal connection frequency ({int(count)} concurrent sessions)"
            })
            
        # 2. Asymmetric payload / outbound burst
        if src_bytes > 2000 and dst_bytes < 500:
            weight = min(35.0, (src_bytes / 20000.0) * 35.0)
            contributions.append({
                "feature": "src_bytes",
                "value": src_bytes,
                "impact_pct": round(weight, 1),
                "direction": "+",
                "explanation": f"High outbound payload ({int(src_bytes)} bytes) without proportional response"
            })
            
        # 3. SYN / Connection state errors
        if flag in ["S0", "RSTR", "REJ"] or serror_rate > 0.3:
            weight = 25.0 if flag == "S0" else 20.0
            contributions.append({
                "feature": "flag / serror_rate",
                "value": flag,
                "impact_pct": round(weight, 1),
                "direction": "+",
                "explanation": f"TCP handshake anomaly (Flag: {flag}, Serror: {serror_rate:.2f})"
            })
            
        # 4. Multi-port / Service scan reconnaissance
        if diff_srv > 0.5 or rerror_rate > 0.4:
            weight = 22.0
            contributions.append({
                "feature": "diff_srv_rate",
                "value": round(diff_srv, 2),
                "impact_pct": round(weight, 1),
                "direction": "+",
                "explanation": "High ratio of different services contacted (Reconnaissance Port Sweep)"
            })
            
        # 5. Failed authentication attempts
        if failed_logins > 0:
            weight = min(30.0, failed_logins * 10.0)
            contributions.append({
                "feature": "num_failed_logins",
                "value": failed_logins,
                "impact_pct": round(weight, 1),
                "direction": "+",
                "explanation": f"Repeated unauthorized authentication failures ({failed_logins} attempts)"
            })
            
        # Normal traffic baseline
        if not contributions:
            contributions.append({
                "feature": "balanced_ratio",
                "value": "Normal",
                "impact_pct": 98.0,
                "direction": "-",
                "explanation": "Bidirectional flow bytes and packet rates match safe baseline traffic"
            })
            
        # Sort by impact
        contributions.sort(key=lambda x: x["impact_pct"], reverse=True)
        return contributions
