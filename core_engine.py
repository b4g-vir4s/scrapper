import requests
from bs4 import BeautifulSoup

def fetch_source(url):
    """Fetches HTML with automatic Tor routing for .onion addresses."""
    # SOCKS5 proxy for Tor (9050 is the default Tor service port)
    proxies = {
        'http': 'socks5h://127.0.0.1:9050',
        'https': 'socks5h://127.0.0.1:9050'
    }
    
    # Use proxies ONLY if it's an onion link
    use_proxy = proxies if url.endswith(".onion") else None
    
    try:
        res = requests.get(
            url, 
            proxies=use_proxy, 
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0'}, 
            timeout=20
        )
        return res.text, res.status_code
    except Exception as e:
        return f"CONNECTION ERROR: Ensure Tor is running on port 9050.\nError: {str(e)}", 500

def parse_intel(html, flags):
    """Extracts data and prepares it for the unified UI preview."""
    soup = BeautifulSoup(html, 'html.parser')
    data = {}

    if flags.get("Text"):
        data["Text"] = "\n".join([p.get_text().strip() for p in soup.find_all(['p', 'h1', 'h2']) if p.get_text().strip()])
    
    if flags.get("Links"):
        data["Links"] = [a.get('href') for a in soup.find_all('a', href=True)]
    
    if flags.get("Images"):
        data["Images"] = [img.get('src') for img in soup.find_all('img', src=True)]
    
    if flags.get("Metadata"):
        data["Metadata"] = {m.get('name', m.get('property', 'unnamed')): m.get('content', 'no-content') 
                           for m in soup.find_all('meta')}
    return data