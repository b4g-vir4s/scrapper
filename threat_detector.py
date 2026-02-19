"""
THREAT DETECTOR (LEAN)
======================
Regex-driven IoC (Indicator of Compromise) extraction engine.
"""
import re
from typing import Dict, List

# Core Regex Patterns for Intelligence Gathering
PATTERNS = {
    'ips': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    'cves': r'(?i)CVE-\d{4}-\d{4,7}',
    'emails': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    'btc_addresses': r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
    'md5_hashes': r'\b[a-fA-F0-9]{32}\b',
    'sha256_hashes': r'\b[a-fA-F0-9]{64}\b',
    'base64_strings': r'\b[A-Za-z0-9+/]{20,}={0,2}\b',
    'hex_strings': r'\b(?:0x)?[a-fA-F0-9]{16,}\b'
}

KEYWORDS = [
    'ransomware', 'malware', 'trojan', 'backdoor', 'phishing', 'exploit', 
    'zero-day', 'botnet', 'ddos', 'metasploit', 'cobalt strike', 'shellcode',
    'c2', 'apt', 'spyware'
]

def extract_all_threats(text: str) -> Dict[str, List[str]]:
    """Master extraction function using functional pattern mapping."""
    # Process regex indicators
    results = {k: list(set(re.findall(p, text))) for k, p in PATTERNS.items()}
    
    # Process keyword-based threats
    text_lower = text.lower()
    results['malware_keywords'] = [kw for kw in KEYWORDS if kw in text_lower]
    
    return results