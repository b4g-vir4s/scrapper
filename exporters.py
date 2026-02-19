"""
EXPORTERS MODULE
================
Optimized for high-fidelity Forensic PDF generation.
"""
import json
from datetime import datetime
from typing import Dict

def generate_text_report(data: Dict) -> str:
    """Generates a structured forensic summary for PDF conversion."""
    inds = data.get('threat_indicators', {})
    ans = inds.get('threat_analysis', {})
    
    report = f"{'='*60}\nCYBER-PULSE PRO: FORENSIC REPORT\n{'='*60}\n"
    report += f"TARGET: {data.get('url')}\nTIME: {data.get('timestamp')}\n"
    report += f"LEVEL: {ans.get('threat_level')} | SCORE: {ans.get('total_score')}\n{'-'*60}\n"

    sections = [('IPs', 'ips'), ('CVEs', 'cves'), ('BTC', 'btc_addresses'), ('Malware', 'malware_keywords')]
    for label, key in sections:
        items = inds.get(key, [])
        if items:
            report += f"\n{label} ({len(items)}):\n" + "\n".join(f" • {i}" for i in items[:10]) + "\n"
            if len(items) > 10: report += f" ... (+{len(items)-10} more)\n"

    return report + f"{'='*60}\nEND OF FORENSIC RECORD"

def save_as_text_report(data: Dict, path: str) -> bool:
    """Saves the final forensic intelligence record."""
    try:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(generate_text_report(data))
        return True
    except Exception as e:
        print(f"Export Error: {e}")
        return False