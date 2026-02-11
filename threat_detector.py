"""
THREAT DETECTOR MODULE
======================
Pure functions for detecting cybersecurity threats and indicators.
Implements pattern matching for various threat types.
"""

import re
from typing import Dict, List


def extract_ips(text: str) -> List[str]:
    """
    PURE FUNCTION: Extract IPv4 addresses from text
    
    Args:
        text: Input text to scan
    
    Returns:
        List of unique IP addresses found
    """
    pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    return list(set(re.findall(pattern, text)))


def extract_cves(text: str) -> List[str]:
    """
    PURE FUNCTION: Extract CVE identifiers from text
    
    CVE format: CVE-YYYY-NNNNN (where Y=year, N=number)
    
    Args:
        text: Input text to scan
    
    Returns:
        List of unique CVE identifiers found
    """
    pattern = r'CVE-\d{4}-\d{4,7}'
    return list(set(re.findall(pattern, text, re.IGNORECASE)))


def extract_emails(text: str) -> List[str]:
    """
    PURE FUNCTION: Extract email addresses from text
    
    Args:
        text: Input text to scan
    
    Returns:
        List of unique email addresses found
    """
    pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    return list(set(re.findall(pattern, text)))


def extract_bitcoin_addresses(text: str) -> List[str]:
    """
    PURE FUNCTION: Extract Bitcoin addresses from text
    
    Bitcoin addresses start with 1 or 3 and are 26-35 chars
    CRITICAL: Bitcoin addresses indicate ransomware!
    
    Args:
        text: Input text to scan
    
    Returns:
        List of unique Bitcoin addresses found
    """
    pattern = r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'
    return list(set(re.findall(pattern, text)))


def extract_md5_hashes(text: str) -> List[str]:
    """
    PURE FUNCTION: Extract MD5 hashes (32 hex chars)
    
    Args:
        text: Input text to scan
    
    Returns:
        List of unique MD5 hashes found
    """
    pattern = r'\b[a-fA-F0-9]{32}\b'
    return list(set(re.findall(pattern, text)))


def extract_sha1_hashes(text: str) -> List[str]:
    """
    PURE FUNCTION: Extract SHA1 hashes (40 hex chars)
    
    Args:
        text: Input text to scan
    
    Returns:
        List of unique SHA1 hashes found
    """
    pattern = r'\b[a-fA-F0-9]{40}\b'
    return list(set(re.findall(pattern, text)))


def extract_sha256_hashes(text: str) -> List[str]:
    """
    PURE FUNCTION: Extract SHA256 hashes (64 hex chars)
    
    Args:
        text: Input text to scan
    
    Returns:
        List of unique SHA256 hashes found
    """
    pattern = r'\b[a-fA-F0-9]{64}\b'
    return list(set(re.findall(pattern, text)))


def extract_urls(text: str) -> List[str]:
    """
    PURE FUNCTION: Extract URLs from text
    
    Args:
        text: Input text to scan
    
    Returns:
        List of unique URLs found
    """
    pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    return list(set(re.findall(pattern, text)))


def extract_malware_keywords(text: str) -> List[str]:
    """
    PURE FUNCTION: Detects cybersecurity threat keywords
    
    Searches for common malware, exploit, and attack terms
    
    Args:
        text: Input text to scan
    
    Returns:
        List of threat keywords found in text
    """
    threat_terms = [
        'ransomware', 'malware', 'trojan', 'backdoor', 'rootkit',
        'phishing', 'exploit', 'vulnerability', 'zero-day', 'botnet',
        'ddos', 'injection', 'xss', 'csrf', 'metasploit', 'cobalt strike',
        'mimikatz', 'powershell empire', 'shellcode', 'privilege escalation',
        'lateral movement', 'command and control', 'c2', 'apt', 'spyware'
    ]
    
    text_lower = text.lower()
    found = [term for term in threat_terms if term in text_lower]
    return list(set(found))


def extract_base64_strings(text: str) -> List[str]:
    """
    PURE FUNCTION: Detects Base64-encoded strings
    
    Base64 is often used to hide malicious payloads
    
    Args:
        text: Input text to scan
    
    Returns:
        List of potential Base64 strings (min 20 chars)
    """
    pattern = r'\b[A-Za-z0-9+/]{20,}={0,2}\b'
    return re.findall(pattern, text)


def extract_hex_strings(text: str) -> List[str]:
    """
    PURE FUNCTION: Detects hexadecimal strings
    
    Hex encoding is used to obfuscate malicious code
    
    Args:
        text: Input text to scan
    
    Returns:
        List of potential hex strings (min 16 chars)
    """
    pattern = r'\b(?:0x)?[a-fA-F0-9]{16,}\b'
    return re.findall(pattern, text)


def extract_all_threats(text: str) -> Dict[str, List[str]]:
    """
    PURE FUNCTION: Master function - extracts ALL threat indicators
    
    This is a FUNCTIONAL COMPOSITION of all extraction functions
    
    Args:
        text: Input text to scan
    
    Returns:
        Dictionary with all threat types and their findings
    """
    return {
        'ips': extract_ips(text),
        'cves': extract_cves(text),
        'emails': extract_emails(text),
        'btc_addresses': extract_bitcoin_addresses(text),
        'md5_hashes': extract_md5_hashes(text),
        'sha1_hashes': extract_sha1_hashes(text),
        'sha256_hashes': extract_sha256_hashes(text),
        'urls': extract_urls(text),
        'malware_keywords': extract_malware_keywords(text),
        'base64_strings': extract_base64_strings(text),
        'hex_strings': extract_hex_strings(text)
    }