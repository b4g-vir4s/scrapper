"""
TEXT PROCESSOR (LEAN)
=====================
Functional sanitization and OSINT visualization.
"""
import re
from wordcloud import WordCloud, STOPWORDS

def sanitize_for_wordcloud(text: str) -> str:
    """Cleans, filters, and joins text for visualization."""
    words = re.findall(r'\b[a-z]{3,}\b', text.lower())
    return ' '.join(w for w in words if w not in STOPWORDS)

def generate_word_cloud(text: str, theme: str = "viridis"):
    """Creates a high-resolution threat intelligence word cloud."""
    t = text if text.strip() else "no data"
    return WordCloud(width=1200, height=600, background_color="#0a0a0a", 
                     colormap=theme, max_words=150).generate(t)

def get_top_words(text: str, n: int = 10):
    """Calculates frequency of key terms in the target content."""
    words = [w for w in re.findall(r'\b[a-z]{3,}\b', text.lower()) if w not in STOPWORDS]
    freq = {w: words.count(w) for w in set(words)}
    return sorted(freq.items(), key=lambda x: x[1], reverse=True)[:n]

def calculate_text_stats(text: str) -> dict:
    """Generates linguistic metrics for the target data."""
    w = re.findall(r'\b[a-z]{3,}\b', text.lower())
    return {
        'chars': len(text),
        'words': len(w),
        'unique': len(set(w)),
        'avg_len': sum(len(i) for i in w) / len(w) if w else 0
    }