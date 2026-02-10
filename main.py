import requests
from bs4 import BeautifulSoup
from wordcloud import WordCloud, STOPWORDS
import matplotlib.pyplot as plt
import numpy as np
from PIL import Image
import re
import nltk
from nltk.corpus import stopwords

# Ensure stopworks are downloaded for text cleaning
nltk.download('stopwords', quiet=True)

def fetch_html(url):
    """Fetches the raw HTML content from a URL."""
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.text
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return ""

def extract_text(html):
    """Parses HTML and extracts text from paragraphs and headings."""
    if not html: return ""
    soup = BeautifulSoup(html, 'html.parser')
    # Focus on main content areas to avoid footer/nav noise
    tags = soup.find_all(['p', 'h1', 'h2', 'h3'])
    return " ".join([tag.get_text() for tag in tags])

def clean_text(text):
    """Cleans text by removing punctuation, numbers, and stopwords."""
    # Convert to lowercase and remove non-alphabetical characters
    words = re.findall(r'\b[a-z]{3,}\b', text.lower())
    
    # Define stopwords
    stop_words = set(stopwords.words('english')).union(STOPWORDS)
    
    # Filter out stopwords using functional list comprehension
    filtered_words = [w for w in words if w not in stop_words]
    return " ".join(filtered_words)

def generate_wordcloud(text, title="Word Cloud", color="black", mask_path=None):
    """Generates and displays the word cloud visualization."""
    mask = np.array(Image.open(mask_path)) if mask_path else None
    
    wc = WordCloud(
        width=800, 
        height=400,
        background_color=color,
        max_words=200,
        mask=mask,
        contour_width=3,
        contour_color='steelblue',
        colormap='viridis'
    ).generate(text)

    plt.figure(figsize=(10, 5))
    plt.imshow(wc, interpolation='bilinear')
    plt.title(title, fontsize=20)
    plt.axis("off")
    plt.show()

def run_project(url):
    """Main pipeline execution."""
    print(f"🚀 Processing: {url}")
    
    # Functional pipeline flow
    html_content = fetch_html(url)
    raw_text = extract_text(html_content)
    processed_text = clean_text(raw_text)
    
    if processed_text:
        generate_wordcloud(processed_text, title=f"Top Terms from {url}")
    else:
        print("❌ No text found to visualize.")

if __name__ == "__main__": #its a good practice to use this guard to allow for better modularity and potential reuse of functions in other contexts
    target_url = "https://en.wikipedia.org/wiki/Data_science"
    run_project(target_url)