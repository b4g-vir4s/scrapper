"""
UI FORMATTERS (LEAN)
====================
Data-to-string conversion for GUI display.
"""
from typing import Dict

def format_threat_report(inds: Dict) -> str:
    """Formats forensic indicators into a structured console report."""
    ans = inds.get('threat_analysis', {})
    rep = f"{'='*60}\n🔍 THREAT REPORT | LEVEL: {ans.get('threat_level')}\n{'='*60}\n"
    rep += f"SCORE: {ans.get('total_score')} | {ans.get('description')}\n"

    sections = [
        ('📍 IPs', 'ips'), ('🔐 CVEs', 'cves'), ('📧 EMAILS', 'emails'),
        ('🚨 BTC', 'btc_addresses'), ('🦠 MALWARE', 'malware_keywords'), ('🔗 URLs', 'urls')
    ]
    
    for label, key in sections:
        items = inds.get(key, [])
        if items:
            rep += f"\n{label} ({len(items)}):\n" + "\n".join(f"  • {i}" for i in items[:15])
            if len(items) > 15: rep += f"\n  ... (+{len(items)-15} more)"
            rep += "\n"

    return rep + f"{'='*60}\n✅ ANALYSIS COMPLETE"

def format_data_preview(data: Dict) -> str:
    """Formats raw DOM data for the preview tab."""
    prev = f"{'='*60}\n📄 DATA PREVIEW\n{'='*60}\n"
    if data.get("text"): prev += f"📝 TEXT:\n{data['text'][:500]}...\n"
    
    for k, label in [("links", "🔗 LINKS"), ("images", "🖼️ IMAGES")]:
        items = data.get(k, [])
        if items:
            prev += f"\n{label} ({len(items)}):\n" + "\n".join(f"  → {i}" for i in items[:10]) + "\n"
    
    return prev + f"{'='*60}"

def get_help_text() -> str:
    """Returns the application user manual."""
    return """
CYBER-PULSE PRO GUIDE
---------------------
1. Enter Target URL.
2. Select extraction flags.
3. Click 'START SCAN'.

DETECTION ENGINE:
- Network: IPs & URLs
- Vulnerabilities: CVE IDs
- Ransomware: BTC Addresses
- Obfuscation: Base64 & Hex
---------------------
FORENSIC GRADE OSINT TOOL
"""