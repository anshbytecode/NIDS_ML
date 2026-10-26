"""
URL & Web Link Security Threat Scanner
Analyzes URLs in real-time to determine whether a pasted link is SAFE, CAUTIOUS / SUSPICIOUS, or FRAUD / PHISHING.
"""
import re
import math
from urllib.parse import urlparse
from typing import Dict, Any

SAFE_DOMAINS = {
    "google.com", "github.com", "microsoft.com", "apple.com", "amazon.com",
    "cloudflare.com", "wikipedia.org", "youtube.com", "linkedin.com", "twitter.com",
    "x.com", "facebook.com", "netflix.com", "instagram.com", "reddit.com"
}

PHISHING_BRANDS = [
    "paypal", "chase", "bankofamerica", "wellsfargo", "appleid", "netflix",
    "binance", "metamask", "coinbase", "whatsapp", "microsoftonline", "steamcommunity"
]

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "update", "account", "banking", "secure",
    "wallet", "password", "authenticate", "credential", "recover", "security-check",
    "free-gift", "claim-reward", "airdrop", "support-ticket"
]

SUSPICIOUS_TLDS = {".xyz", ".top", ".buzz", ".work", ".click", ".fit", ".icu", ".cam", ".cfd", ".gq", ".ml", ".cf"}

def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    entropy = 0.0
    for char in set(text):
        p_x = float(text.count(char)) / len(text)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return round(entropy, 2)

def scan_url(url: str) -> Dict[str, Any]:
    url_clean = str(url).strip()
    if not url_clean.startswith(("http://", "https://")):
        url_clean = "http://" + url_clean
        
    try:
        parsed = urlparse(url_clean)
        hostname = (parsed.hostname or "").lower()
        path = (parsed.path or "").lower()
        query = (parsed.query or "").lower()
    except Exception:
        hostname = ""
        path = ""
        query = ""
    
    # 1. Check known safe enterprise root domains
    for safe in SAFE_DOMAINS:
        if hostname == safe or hostname.endswith("." + safe):
            return {
                "url": url,
                "domain": hostname,
                "threat_score": 5.0,
                "severity": "LOW",
                "verdict_category": "SAFE",
                "verdict_icon": "🟢",
                "verdict": "SAFE & CLEAN LINK",
                "safety_rating": "High Trust Verified Domain",
                "recommendation": "Safe to visit. The domain is a recognized legitimate enterprise destination.",
                "reasons": ["Verified legitimate enterprise domain", "Valid standard domain structure", "No malicious signatures detected"]
            }
            
    # 2. Risk scoring heuristics
    risk = 0.0
    reasons = []
    is_fraud = False
    
    # Brand impersonation check (e.g. paypal in a non-paypal domain)
    for brand in PHISHING_BRANDS:
        if brand in hostname and not (hostname == f"{brand}.com" or hostname.endswith(f".{brand}.com")):
            risk += 50.0
            is_fraud = True
            reasons.append(f"Deceptive brand impersonation detected for '{brand}'")
        elif brand in path or brand in query:
            risk += 35.0
            reasons.append(f"Targeting '{brand}' credentials via path/query parameter")

    # High-risk TLD
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            risk += 35.0
            reasons.append(f"High-risk, abuse-prone top-level domain ({tld})")
            break
            
    # Phishing / credential harvesting keywords
    matched_kws = [kw for kw in SUSPICIOUS_KEYWORDS if kw in hostname or kw in path]
    if matched_kws:
        risk += min(40.0, len(matched_kws) * 20.0)
        reasons.append(f"Detected sensitive auth keywords: {', '.join(matched_kws[:3])}")
        
    # Direct IP address used instead of domain
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
        risk += 35.0
        reasons.append("Raw IP address used as destination instead of domain name")
        
    # Suspicious domain entropy (e.g., dga / algorithmic random domains)
    domain_entropy = calculate_entropy(hostname.split(".")[0])
    if domain_entropy >= 3.7 and len(hostname.split(".")[0]) >= 12:
        risk += 25.0
        reasons.append(f"High Shannon entropy ({domain_entropy}) indicating algorithmically generated domain")
        
    # Excessive subdomains (e.g., login.paypal.com.verify.xyz)
    subdomain_count = len(hostname.split("."))
    if subdomain_count >= 4:
        risk += 20.0
        reasons.append(f"Excessive subdomains ({subdomain_count} levels) used for obfuscation")
        
    # Insecure plain HTTP used for sensitive action
    if parsed.scheme == "http" and (any(k in url_clean for k in ["login", "signin", "verify", "paypal"])):
        risk += 25.0
        reasons.append("Insecure plain HTTP used for sensitive login/banking destination")
        
    # Multiple '@' symbol or URL tricks
    if "@" in url_clean:
        risk += 35.0
        reasons.append("Detected '@' symbol in URL (browser credential deception trick)")
        
    threat_score = round(min(99.0, max(5.0, risk)), 1)
    
    # Categorize Verdict: SAFE vs CAUTIOUS vs FRAUD
    if threat_score >= 70.0 or is_fraud:
        severity = "CRITICAL" if threat_score >= 85.0 else "HIGH"
        verdict_category = "FRAUD"
        verdict_icon = "🔴"
        verdict = "MALICIOUS PHISHING LINK DETECTED"
        safety_rating = "CRITICAL THREAT / FRAUD"
        recommendation = "DO NOT CLICK OR SUBMIT CREDENTIALS! This link displays strong indicators of credential harvesting, fraud, or brand impersonation."
    elif threat_score >= 35.0:
        severity = "MEDIUM"
        verdict_category = "CAUTIOUS"
        verdict_icon = "🟡"
        verdict = "SUSPICIOUS UNVERIFIED LINK"
        safety_rating = "CAUTIOUS / SUSPICIOUS"
        recommendation = "PROCEED WITH CAUTION. The domain structure or hosting characteristics present unusual anomalies. Verify sender identity before browsing."
    else:
        severity = "LOW"
        verdict_category = "SAFE"
        verdict_icon = "🟢"
        verdict = "SAFE & CLEAN LINK"
        safety_rating = "LOW RISK"
        recommendation = "No prominent threat signatures detected. Standard browsing precautions apply."
        
    return {
        "url": url,
        "domain": hostname,
        "threat_score": threat_score,
        "severity": severity,
        "verdict_category": verdict_category,
        "verdict_icon": verdict_icon,
        "verdict": verdict,
        "safety_rating": safety_rating,
        "recommendation": recommendation,
        "reasons": reasons if reasons else ["No known anomalies detected in URL lexical inspection"]
    }
