"""
TEXT PROCESSOR MODULE
=====================
Pure functions for text cleaning and processing.
Handles text sanitization and word cloud generation.
"""

import re
from wordcloud import WordCloud, STOPWORDS
from typing import List, Set


def clean_text(text: str) -> str:
    """
    PURE FUNCTION: Removes special characters and extra whitespace
    
    Args:
        text: Raw text to clean
    
    Returns:
        Cleaned text
    """
    # Remove special characters but keep spaces
    cleaned = re.sub(r'[^a-zA-Z0-9\s]', ' ', text)
    # Remove extra whitespace
    cleaned = ' '.join(cleaned.split())
    return cleaned


def extract_words(text: str, min_length: int = 3) -> List[str]:
    """
    PURE FUNCTION: Extracts words from text
    
    Args:
        text: Input text
        min_length: Minimum word length to include
    
    Returns:
        List of words
    """
    words = re.findall(r'\b[a-z]{' + str(min_length) + r',}\b', text.lower())
    return words


def remove_stopwords(words: List[str]) -> List[str]:
    """
    PURE FUNCTION: Removes common English stopwords
    
    Args:
        words: List of words
    
    Returns:
        List of words with stopwords removed
    """
    return [w for w in words if w not in STOPWORDS]


def sanitize_for_wordcloud(text: str) -> str:
    """
    PURE FUNCTION: Prepares text for word cloud generation
    
    FUNCTIONAL COMPOSITION:
    clean → extract words → remove stopwords → join
    
    Args:
        text: Raw text
    
    Returns:
        Cleaned text ready for word cloud
    """
    # Extract words (min 3 letters)
    words = extract_words(text, min_length=3)
    
    # Remove stopwords
    filtered_words = remove_stopwords(words)
    
    # Join back into string
    return ' '.join(filtered_words)


def generate_word_cloud(text: str, theme_color: str = "viridis") -> WordCloud:
    """
    Generates Word Cloud visualization
    
    NOTE: This returns an object, but generation is deterministic
    
    Args:
        text: Input text
        theme_color: Color scheme (matplotlib colormap)
    
    Returns:
        WordCloud object
    """
    if not text.strip():
        text = "no data available"
    
    return WordCloud(
        width=1200,
        height=600,
        background_color="#0a0a0a",
        colormap=theme_color,
        max_words=150,
        collocations=False
    ).generate(text)


def count_word_frequency(text: str) -> dict:
    """
    PURE FUNCTION: Counts word frequencies
    
    Args:
        text: Input text
    
    Returns:
        Dictionary of {word: count}
    """
    words = extract_words(text)
    filtered = remove_stopwords(words)
    
    freq = {}
    for word in filtered:
        freq[word] = freq.get(word, 0) + 1
    
    return freq


def get_top_words(text: str, n: int = 10) -> List[tuple]:
    """
    PURE FUNCTION: Gets most frequent words
    
    Args:
        text: Input text
        n: Number of top words to return
    
    Returns:
        List of (word, count) tuples, sorted by count
    """
    freq = count_word_frequency(text)
    sorted_words = sorted(freq.items(), key=lambda x: x[1], reverse=True)
    return sorted_words[:n]


def calculate_text_stats(text: str) -> dict:
    """
    PURE FUNCTION: Calculates text statistics
    
    Args:
        text: Input text
    
    Returns:
        Dictionary with text statistics
    """
    words = extract_words(text)
    unique_words = set(words)
    
    return {
        'total_chars': len(text),
        'total_words': len(words),
        'unique_words': len(unique_words),
        'avg_word_length': sum(len(w) for w in words) / len(words) if words else 0
    }