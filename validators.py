"""
VALIDATORS MODULE
==================
Pure functions for URL validation and input sanitization.
All functions are PURE - same input always gives same output.
"""

import re
from typing import Tuple


def validate_url(url: str) -> Tuple[bool, str]:
    """
    PURE FUNCTION: Validates if URL is safe to scrape
    
    SECURITY: Prevents scraping of local files, private IPs
    
    Args:
        url: URL string to validate
    
    Returns:
        Tuple of (is_valid, error_message)
    
    Example:
        valid, msg = validate_url("https://example.com")
        if not valid:
            print(msg)
    """
    # Block file:// protocol
    if url.startswith('file://'):
        return False, "Local file access blocked for security"
    
    # Block localhost and private IP ranges
    private_patterns = [
        r'localhost',
        r'127\.0\.0\.\d+',
        r'192\.168\.\d+\.\d+',
        r'10\.\d+\.\d+\.\d+',
        r'172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+'
    ]
    
    for pattern in private_patterns:
        if re.search(pattern, url, re.IGNORECASE):
            return False, "Private/Local network access blocked"
    
    # Must start with http:// or https://
    if not url.startswith(('http://', 'https://')):
        return False, "URL must start with http:// or https://"
    
    return True, "Valid URL"


def sanitize_filename(filename: str) -> str:
    """
    PURE FUNCTION: Creates safe filename from string
    
    Removes characters that could be dangerous in filenames
    
    Args:
        filename: Original filename
    
    Returns:
        Sanitized filename (max 100 chars)
    """
    # Remove dangerous characters
    safe = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Limit length
    return safe[:100]


def is_valid_email(email: str) -> bool:
    """
    PURE FUNCTION: Basic email validation
    
    Args:
        email: Email address to validate
    
    Returns:
        True if valid format, False otherwise
    """
    pattern = r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}$'
    return bool(re.match(pattern, email))


def is_valid_ip(ip: str) -> bool:
    """
    PURE FUNCTION: Validates IPv4 address
    
    Args:
        ip: IP address string
    
    Returns:
        True if valid IPv4, False otherwise
    """
    pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    return bool(re.match(pattern, ip))