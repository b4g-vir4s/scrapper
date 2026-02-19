"""
THREAT ANALYZER (LEAN)
======================
Scoring and risk classification engine for Cyber-Pulse Pro.
"""
from typing import Dict, List, Any

# Global weights for risk calculation
WEIGHTS = {
    'ips': 2, 'cves': 10, 'emails': 1, 'btc_addresses': 15,
    'md5_hashes': 5, 'sha1_hashes': 5, 'sha256_hashes': 5,
    'malware_keywords': 8, 'base64_strings': 3, 'hex_strings': 3
}

def analyze_threats(indicators: Dict[str, List]) -> Dict[str, Any]:
    """Performs full risk assessment and scoring."""
    score = sum(len(indicators.get(k, [])) * w for k, w in WEIGHTS.items())
    
    # Threshold mapping
    if score == 0: lv, cl, ds = "CLEAN", "#00ff00", "No threats detected."
    elif score < 10: lv, cl, ds = "LOW", "#ffff00", "Minor indicators found."
    elif score < 30: lv, cl, ds = "MEDIUM", "#ffa500", "Concerning indicators."
    elif score < 60: lv, cl, ds = "HIGH", "#ff4500", "Significant threats detected."
    else: lv, cl, ds = "CRITICAL", "#ff0000", "Severe threats detected!"

    return {
        'total_score': score,
        'threat_level': lv,
        'severity_color': cl,
        'description': ds,
        'indicator_count': sum(len(v) for v in indicators.values() if isinstance(v, list))
    }

def get_recommendations(level: str) -> List[str]:
    """Provides incident response actions based on risk level."""
    recs = {
        "CLEAN": ["Continue monitoring", "Maintain regular scans"],
        "LOW": ["Review flagged indicators", "Monitor for changes"],
        "MEDIUM": ["Investigate flags", "Block suspicious IPs"],
        "HIGH": ["⚠️ Do NOT interact", "Report to security team"],
        "CRITICAL": ["🚨 URGENT: Isolate systems", "Begin forensic analysis"]
    }
    return recs.get(level, ["Seek expert advice"])