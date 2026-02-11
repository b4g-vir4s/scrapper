"""
THREAT ANALYZER MODULE
======================
Pure functions for analyzing and scoring threats.
Calculates risk levels based on indicators found.
"""

from typing import Dict, List, Any


def calculate_threat_score(indicators: Dict[str, List]) -> int:
    """
    PURE FUNCTION: Calculates total threat score
    
    Scoring system:
    - Each IP: +2 points
    - Each CVE: +10 points
    - Each email: +1 point
    - Each Bitcoin address: +15 points (ransomware!)
    - Each hash: +5 points
    - Each malware keyword: +8 points
    - Base64/Hex strings: +3 points each
    
    Args:
        indicators: Dictionary of threat indicators
    
    Returns:
        Total threat score (integer)
    """
    weights = {
        'ips': 2,
        'cves': 10,
        'emails': 1,
        'btc_addresses': 15,
        'md5_hashes': 5,
        'sha1_hashes': 5,
        'sha256_hashes': 5,
        'malware_keywords': 8,
        'base64_strings': 3,
        'hex_strings': 3
    }
    
    total_score = sum(
        len(indicators.get(key, [])) * weight
        for key, weight in weights.items()
    )
    
    return total_score


def categorize_threat_level(score: int) -> str:
    """
    PURE FUNCTION: Maps score to threat level category
    
    Categories:
    - CLEAN: 0 points
    - LOW: 1-9 points
    - MEDIUM: 10-29 points
    - HIGH: 30-59 points
    - CRITICAL: 60+ points
    
    Args:
        score: Threat score (integer)
    
    Returns:
        Threat level string
    """
    if score == 0:
        return "CLEAN"
    elif score < 10:
        return "LOW"
    elif score < 30:
        return "MEDIUM"
    elif score < 60:
        return "HIGH"
    else:
        return "CRITICAL"


def get_severity_color(level: str) -> str:
    """
    PURE FUNCTION: Maps threat level to display color
    
    Color scheme:
    - CLEAN: Green
    - LOW: Yellow
    - MEDIUM: Orange
    - HIGH: Red-Orange
    - CRITICAL: Dark Red
    
    Args:
        level: Threat level string
    
    Returns:
        Hex color code
    """
    color_map = {
        "CLEAN": "#00ff00",
        "LOW": "#ffff00",
        "MEDIUM": "#ffa500",
        "HIGH": "#ff4500",
        "CRITICAL": "#ff0000"
    }
    return color_map.get(level, "#ffffff")


def get_threat_description(level: str) -> str:
    """
    PURE FUNCTION: Provides human-readable threat description
    
    Args:
        level: Threat level string
    
    Returns:
        Description of what the threat level means
    """
    descriptions = {
        "CLEAN": "No threats detected. Site appears safe.",
        "LOW": "Minor indicators found. Generally safe but monitor.",
        "MEDIUM": "Some concerning indicators. Exercise caution.",
        "HIGH": "Significant threats detected. High risk content.",
        "CRITICAL": "Severe threats detected. Dangerous content!"
    }
    return descriptions.get(level, "Unknown threat level")


def analyze_threats(indicators: Dict[str, List]) -> Dict[str, Any]:
    """
    PURE FUNCTION: Complete threat analysis
    
    FUNCTIONAL COMPOSITION: Combines multiple analysis functions
    
    Args:
        indicators: Dictionary of threat indicators
    
    Returns:
        Dictionary with complete analysis:
        - total_score
        - threat_level
        - severity_color
        - description
        - indicator_count (total indicators found)
    """
    score = calculate_threat_score(indicators)
    level = categorize_threat_level(score)
    color = get_severity_color(level)
    description = get_threat_description(level)
    
    # Count total indicators
    indicator_count = sum(len(v) for v in indicators.values() if isinstance(v, list))
    
    return {
        'total_score': score,
        'threat_level': level,
        'severity_color': color,
        'description': description,
        'indicator_count': indicator_count
    }


def get_top_threats(indicators: Dict[str, List], top_n: int = 3) -> List[Dict[str, Any]]:
    """
    PURE FUNCTION: Identifies the most significant threat types
    
    Args:
        indicators: Dictionary of threat indicators
        top_n: Number of top threats to return
    
    Returns:
        List of top threat types with counts
    """
    # Calculate score contribution for each type
    weights = {
        'ips': 2, 'cves': 10, 'emails': 1, 'btc_addresses': 15,
        'md5_hashes': 5, 'sha1_hashes': 5, 'sha256_hashes': 5,
        'malware_keywords': 8
    }
    
    threat_scores = []
    for key, weight in weights.items():
        count = len(indicators.get(key, []))
        if count > 0:
            threat_scores.append({
                'type': key.replace('_', ' ').title(),
                'count': count,
                'score_contribution': count * weight
            })
    
    # Sort by score contribution (highest first)
    threat_scores.sort(key=lambda x: x['score_contribution'], reverse=True)
    
    return threat_scores[:top_n]


def get_recommendations(threat_level: str) -> List[str]:
    """
    PURE FUNCTION: Provides security recommendations based on threat level
    
    Args:
        threat_level: Threat level string
    
    Returns:
        List of recommended actions
    """
    recommendations = {
        "CLEAN": [
            "No immediate action required",
            "Continue monitoring for changes",
            "Maintain regular security scans"
        ],
        "LOW": [
            "Review flagged indicators manually",
            "Monitor site for changes",
            "Consider adding to watchlist"
        ],
        "MEDIUM": [
            "Investigate all flagged indicators",
            "Avoid sharing personal information",
            "Block suspicious IPs if applicable",
            "Monitor closely for escalation"
        ],
        "HIGH": [
            "⚠️ Do NOT interact with flagged content",
            "Block all suspicious IPs and domains",
            "Report to security team immediately",
            "Consider quarantining related systems"
        ],
        "CRITICAL": [
            "🚨 URGENT: Isolate affected systems",
            "Report to incident response team",
            "Do NOT access flagged resources",
            "Begin forensic analysis",
            "Alert all stakeholders"
        ]
    }
    return recommendations.get(threat_level, ["Unknown threat level - seek expert advice"])