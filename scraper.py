"""
SCRAPER MODULE (LEAN)
=====================
Pure acquisition engine for raw threat data.
"""
import requests, urllib3
from bs4 import BeautifulSoup

urllib3.disable_warnings()

def fetch_content(url: str) -> dict:
    """Acquires and cleans web content for forensic analysis."""
    h = {'User-Agent': 'CyberPulse-Intel-Bot/3.0', 'Accept': 'text/html'}
    try:
        r = requests.get(url, headers=h, timeout=10, verify=False)
        r.raise_for_status()
        s = BeautifulSoup(r.text, 'html.parser')
        
        # Strip DOM noise
        for t in s(["script", "style", "nav", "footer"]): t.decompose()

        return {
            'status': 'success',
            'text': s.get_text(separator=' ', strip=True),
            'title': s.title.string if s.title else "Untitled",
            'links': [a.get('href') for a in s.find_all('a', href=True)][:50],
            'images': [i.get('src') for i in s.find_all('img', src=True)][:20],
            'meta': {m.get('name'): m.get('content') for m in s.find_all('meta') if m.get('name')}
        }
    except Exception as e:
        return {'status': 'failed', 'error': str(e)}