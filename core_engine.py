import requests
from bs4 import BeautifulSoup
import re
from wordcloud import WordCloud, STOPWORDS
import matplotlib.pyplot as plt
from collections import Counter

# --- PURE FUNCTIONS ---

def fetch_source(url, headers=None):
    """Fetches raw HTML. Returns (html, status_code)."""
    try:
        res = requests.get(url, headers=headers or {'User-Agent': 'Mozilla/5.0'}, timeout=10)
        return res.text, res.status_code
    except Exception as e:
        return str(e), 500

def parse_elements(html, selector_flags):
    """Extracts specific data based on GUI checkboxes."""
    soup = BeautifulSoup(html, 'html.parser')
    extracted = {}
    
    if selector_flags.get("Text"):
        extracted["text"] = " ".join([t.get_text() for t in soup.find_all(['p', 'h1', 'h2', 'h3'])])
    if selector_flags.get("Links"):
        extracted["links"] = [a.get('href') for a in soup.find_all('a', href=True)]
    if selector_flags.get("Images"):
        extracted["images"] = [img.get('src') for img in soup.find_all('img', src=True)]
    if selector_flags.get("Metadata"):
        extracted["meta"] = {m.get('name'): m.get('content') for m in soup.find_all('meta') if m.get('name')}
        
    return extracted

def cyber_sanitizer(text, custom_regex=None):
    """Cleans text and extracts Cyber Indicators (IPs, CVEs)."""
    # Standard cleaning
    words = re.findall(r'\b[a-z]{3,}\b', text.lower())
    
    # Advanced Extraction: IPs and CVEs
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    cve_pattern = r'CVE-\d{4}-\d{4,7}'
    
    indicators = {
        "ips": re.findall(ip_pattern, text),
        "cves": re.findall(cve_pattern, text)
    }
    
    clean_text = " ".join([w for w in words if w not in STOPWORDS])
    return clean_text, indicators

def generate_report_viz(text, theme_color="viridis"):
    """Generates the Word Cloud object."""
    return WordCloud(
        width=1200, height=600,
        background_color="#0a0a0a",
        colormap=theme_color,
        max_words=150
    ).generate(text)