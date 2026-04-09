"""
PhishShield Pro - Machine Learning Model
=========================================
Trains a Random Forest classifier on synthetic URL data
to predict phishing probability.
"""

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import re
import pickle
import os

# ── Suspicious TLDs commonly used in phishing ──
SUSPICIOUS_TLDS = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.buzz',
                   '.club', '.work', '.info', '.click', '.link', '.surf']

# ── Phishing keywords ──
PHISHING_KEYWORDS = ['login', 'verify', 'secure', 'account', 'update',
                     'confirm', 'banking', 'password', 'signin', 'wallet']


def extract_features(url: str) -> dict:
    """
    Extract numerical features from a URL for ML prediction.

    Args:
        url: The URL string to analyze.

    Returns:
        Dictionary of extracted feature values.
    """
    url_lower = url.lower()

    # Basic length
    url_length = len(url)

    # HTTPS check (1 = has https, 0 = no)
    has_https = 1 if url_lower.startswith('https://') else 0

    # Count hyphens in the URL
    num_hyphens = url.count('-')

    # Count dots in the URL
    num_dots = url.count('.')

    # Check for IP address pattern (e.g., http://192.168.1.1/...)
    ip_pattern = r'(\d{1,3}\.){3}\d{1,3}'
    has_ip = 1 if re.search(ip_pattern, url) else 0

    # Check for suspicious TLD
    has_suspicious_tld = 0
    for tld in SUSPICIOUS_TLDS:
        if tld in url_lower:
            has_suspicious_tld = 1
            break

    # Count phishing keywords found
    keyword_count = sum(1 for kw in PHISHING_KEYWORDS if kw in url_lower)

    # Count special characters (@, !, ~, %, &, #, =, etc.)
    special_chars = sum(1 for c in url if c in '@!~%&#=?+^*|{}[]<>')

    # Subdomain count (number of dots before the main domain)
    subdomain_count = max(0, num_dots - 1)

    # Path depth (number of / after the domain)
    path_depth = url.count('/') - 2 if '://' in url else url.count('/')

    # URL entropy (randomness measure)
    from collections import Counter
    freq = Counter(url_lower)
    length = len(url_lower) if len(url_lower) > 0 else 1
    entropy = -sum((count / length) * np.log2(count / length)
                    for count in freq.values())

    return {
        'url_length': url_length,
        'has_https': has_https,
        'num_hyphens': num_hyphens,
        'num_dots': num_dots,
        'has_ip': has_ip,
        'has_suspicious_tld': has_suspicious_tld,
        'keyword_count': keyword_count,
        'special_chars': special_chars,
        'subdomain_count': subdomain_count,
        'path_depth': path_depth,
        'entropy': round(entropy, 4)
    }


def features_to_vector(features: dict) -> list:
    """Convert feature dictionary to ordered list for ML input."""
    keys = ['url_length', 'has_https', 'num_hyphens', 'num_dots', 'has_ip',
            'has_suspicious_tld', 'keyword_count', 'special_chars',
            'subdomain_count', 'path_depth', 'entropy']
    return [features[k] for k in keys]


def generate_training_data():
    """
    Generate a synthetic dataset of safe and phishing URLs.
    Returns feature matrix X and label vector y.
    """
    # ── Safe URLs ──
    safe_urls = [
        "https://www.google.com",
        "https://www.github.com",
        "https://stackoverflow.com/questions",
        "https://www.wikipedia.org",
        "https://www.amazon.com/products",
        "https://www.microsoft.com",
        "https://www.apple.com",
        "https://www.netflix.com",
        "https://www.youtube.com/watch?v=abc123",
        "https://docs.python.org/3/library/",
        "https://www.reddit.com/r/programming",
        "https://www.linkedin.com/in/johndoe",
        "https://medium.com/technology",
        "https://www.nytimes.com/2024/news",
        "https://www.bbc.com/news/world",
        "https://www.spotify.com",
        "https://www.twitch.tv",
        "https://www.dropbox.com",
        "https://www.slack.com",
        "https://www.zoom.us/meeting",
        "https://www.coursera.org/learn/ml",
        "https://www.udemy.com/course/python",
        "https://www.figma.com/design",
        "https://www.notion.so/workspace",
        "https://www.canva.com/design",
        "https://www.shopify.com",
        "https://www.stripe.com/payments",
        "https://www.cloudflare.com",
        "https://www.digitalocean.com",
        "https://www.heroku.com",
        "https://www.vercel.com/dashboard",
        "https://www.npmjs.com/package/express",
        "https://www.docker.com/get-started",
        "https://www.tensorflow.org/tutorials",
        "https://pytorch.org/docs/stable",
        "https://www.kaggle.com/datasets",
        "https://www.nasa.gov",
        "https://www.who.int/health",
        "https://www.un.org",
        "https://www.imdb.com/title/tt0111161",
        "https://www.goodreads.com/book/show/1",
        "https://www.etsy.com/shop/handmade",
        "https://www.airbnb.com/rooms/12345",
        "https://www.booking.com/hotel/us",
        "https://www.tripadvisor.com/Attraction",
        "https://www.weather.com/forecast",
        "https://www.wolframalpha.com",
        "https://www.archive.org",
        "https://www.khanacademy.org/math",
        "https://www.duolingo.com/learn",
    ]

    # ── Phishing URLs ──
    phishing_urls = [
        "http://192.168.1.1/login/verify-account",
        "http://secure-banking-login.tk/verify",
        "http://paypal-login-verify.xyz/account",
        "http://www.g00gle-secure.ml/login",
        "http://microsoft-account-verify.ga/signin",
        "http://apple-id-login-secure.cf/verify",
        "http://netflix-account-update.gq/login",
        "http://amazon-verify-account.top/secure",
        "http://192.168.0.100/banking/login/verify",
        "http://secure-login-banking.buzz/account",
        "http://update-your-account-now.xyz/verify",
        "http://10.0.0.1/phishing/login/page",
        "http://free-gift-card-login.tk/account-verify",
        "http://verify-your-identity-secure.ml/login",
        "http://account-locked-verify.ga/update",
        "http://urgent-password-reset.cf/login/verify",
        "http://banking-secure-login.gq/account",
        "http://login-verify-account.xyz/secure",
        "http://172.16.0.1/admin/login/verify",
        "http://confirm-your-account-update.tk/login",
        "http://secure-wallet-login.ml/verify",
        "http://password-reset-verify.ga/account",
        "http://signin-update-account.cf/login",
        "http://verify-banking-login.gq/secure",
        "http://account-verify-update.top/login",
        "http://free-money-login.buzz/verify",
        "http://192.168.10.5/login/account/verify",
        "http://click-here-to-verify.xyz/login",
        "http://your-account-suspended.tk/verify",
        "http://login-verify-secure.ml/account/update",
        "http://suspicious-link-login.ga/verify",
        "http://account-confirm-update.cf/login",
        "http://secure-signin-verify.gq/account",
        "http://verify-now-or-lose-account.xyz/login",
        "http://banking-update-login.top/verify",
        "http://free-iphone-login.buzz/account",
        "http://10.20.30.40/login/password/verify",
        "http://reset-password-verify.tk/login",
        "http://update-account-verify.ml/secure",
        "http://login-banking-verify.ga/account",
        "http://confirm-signin-account.cf/login/verify",
        "http://secure-update-verify.gq/login",
        "http://account-login-update.xyz/verify",
        "http://verify-password-reset.top/login",
        "http://click-verify-account.buzz/secure",
        "http://192.168.255.1/global/login/verify",
        "http://urgent-account-login.tk/verify/update",
        "http://secure-verify-signin.ml/login/account",
        "http://login-password-verify.ga/update",
        "http://account-update-verify-now.cf/login",
    ]

    X = []
    y = []

    for url in safe_urls:
        features = extract_features(url)
        X.append(features_to_vector(features))
        y.append(0)  # 0 = safe

    for url in phishing_urls:
        features = extract_features(url)
        X.append(features_to_vector(features))
        y.append(1)  # 1 = phishing

    return np.array(X), np.array(y)


# ── Global model instance ──
_model = None
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'phishshield_model.pkl')


def train_model():
    """Train the Random Forest model and cache it."""
    global _model
    X, y = generate_training_data()

    # Split for validation
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    # Train Random Forest
    _model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42
    )
    _model.fit(X_train, y_train)

    # Print accuracy
    accuracy = _model.score(X_test, y_test)
    print(f"[PhishShield] Model trained — Accuracy: {accuracy:.2%}")

    # Save model to disk
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(_model, f)

    return _model


def get_model():
    """Load or train the ML model."""
    global _model
    if _model is not None:
        return _model

    # Try loading from disk
    if os.path.exists(MODEL_PATH):
        with open(MODEL_PATH, 'rb') as f:
            _model = pickle.load(f)
        print("[PhishShield] Model loaded from disk.")
        return _model

    # Otherwise, train fresh
    return train_model()


def predict_phishing_probability(url: str) -> float:
    """
    Predict the probability that a URL is phishing.

    Args:
        url: The URL to analyze.

    Returns:
        Float between 0.0 and 1.0 (probability of being phishing).
    """
    model = get_model()
    features = extract_features(url)
    vector = np.array([features_to_vector(features)])
    proba = model.predict_proba(vector)[0]

    # proba[1] = probability of class 1 (phishing)
    return float(proba[1])
