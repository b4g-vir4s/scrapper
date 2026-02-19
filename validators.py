"""
VALIDATORS (LEAN)
=================
Security-focused input validation and sanitization.
"""
import re
from typing import Tuple

def validate_url(url: str) -> Tuple[bool, str]:
    """Pure security function to prevent SSRF and local file leaks."""
    if url.startswith('file://'): 
        return False, "Local file access blocked"
    
    # Private IP ranges (RFC 1918) and Localhost
    private = r'(localhost|127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)'
    if re.search(private, url, re.I):
        return False, "Private network access blocked"
    
    if not url.startswith(('http://', 'https://')):
        return False, "Invalid protocol (use HTTP/HTTPS)"
        
    return True, "Valid"

def sanitize_filename(f: str) -> str:
    """Removes filesystem-unsafe characters."""
    return re.sub(r'[<>:"/\\|?*]', '_', f)[:100]

def is_valid_format(text: str, mode: str) -> bool:
    """Unified validator for Emails and IPs."""
    patterns = {
        'email': r'^[\w.%+-]+@[\w.-]+\.[A-Za-z]{2,}$',
        'ip': r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$'
    }
    return bool(re.match(patterns.get(mode, ''), text))