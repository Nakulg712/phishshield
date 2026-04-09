"""
PhishShield Pro - URL Analyzer
================================
Combines rule-based scoring with ML prediction
to produce a final hybrid risk assessment.
"""

import re
from model import extract_features, predict_phishing_probability

# ── Suspicious TLDs ──
SUSPICIOUS_TLDS = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.top',
                   '.buzz', '.club', '.work', '.click', '.link', '.surf']


def rule_based_score(url: str, features: dict) -> tuple:
    """
    Calculate a rule-based phishing score and collect reasons.

    Args:
        url: The URL string.
        features: Pre-extracted feature dictionary.

    Returns:
        Tuple of (score: int, reasons: list[str])
    """
    score = 0
    reasons = []
    url_lower = url.lower()

    # ── Rule 1: URL length ──
    if features['url_length'] > 75:
        score += 25
        reasons.append("⚠️ Extremely long URL — common phishing tactic")
    elif features['url_length'] > 50:
        score += 20
        reasons.append("⚠️ Unusually long URL detected")

    # ── Rule 2: Phishing keywords ──
    if 'login' in url_lower:
        score += 30
        reasons.append("🔑 Suspicious keyword 'login' found in URL")
    if 'verify' in url_lower:
        score += 20
        reasons.append("🔍 Suspicious keyword 'verify' found in URL")
    if 'secure' in url_lower:
        score += 15
        reasons.append("🛡️ Suspicious keyword 'secure' found in URL")
    if 'account' in url_lower:
        score += 15
        reasons.append("👤 Suspicious keyword 'account' found in URL")
    if 'update' in url_lower:
        score += 10
        reasons.append("🔄 Suspicious keyword 'update' found in URL")
    if 'confirm' in url_lower:
        score += 10
        reasons.append("✅ Suspicious keyword 'confirm' found in URL")
    if 'password' in url_lower:
        score += 20
        reasons.append("🔒 Suspicious keyword 'password' found in URL")
    if 'signin' in url_lower:
        score += 15
        reasons.append("🚪 Suspicious keyword 'signin' found in URL")

    # ── Rule 3: No HTTPS ──
    if features['has_https'] == 0:
        score += 10
        reasons.append("🔓 Unsecured HTTP connection — no encryption")

    # ── Rule 4: Excessive hyphens ──
    if features['num_hyphens'] > 4:
        score += 25
        reasons.append("➖ Excessive hyphens in URL — obfuscation detected")
    elif features['num_hyphens'] > 2:
        score += 15
        reasons.append("➖ Unusual number of hyphens in URL")

    # ── Rule 5: IP address ──
    if features['has_ip'] == 1:
        score += 40
        reasons.append("🌐 IP address used instead of domain name")

    # ── Rule 6: Suspicious TLD ──
    if features['has_suspicious_tld'] == 1:
        score += 25
        reasons.append("🏷️ Suspicious top-level domain detected")

    # ── Rule 7: Too many dots (subdomain abuse) ──
    if features['num_dots'] > 4:
        score += 15
        reasons.append("📍 Excessive subdomains detected")

    # ── Rule 8: Special characters ──
    if features['special_chars'] > 5:
        score += 15
        reasons.append("🔣 High number of special characters")
    elif features['special_chars'] > 2:
        score += 5
        reasons.append("🔣 Unusual special characters present")

    # ── Rule 9: High entropy (randomness) ──
    if features.get('entropy', 0) > 4.5:
        score += 10
        reasons.append("🎲 High URL entropy — possible random string")

    # ── Rule 10: @ symbol (credential injection) ──
    if '@' in url:
        score += 30
        reasons.append("📧 '@' symbol in URL — possible credential injection")

    return score, reasons


def analyze_url(url: str) -> dict:
    """
    Perform full hybrid analysis on a URL.

    Args:
        url: The URL to analyze.

    Returns:
        Dictionary with risk level, score, reasons, and features.
    """
    # Extract features
    features = extract_features(url)

    # ── Rule-based scoring ──
    rb_score, reasons = rule_based_score(url, features)

    # ── ML prediction ──
    ml_probability = predict_phishing_probability(url)
    ml_score = int(ml_probability * 100)

    # ── Hybrid score: weighted combination ──
    # Rule-based is capped at 100, ML score is 0-100
    # Final = 40% rule-based + 60% ML (ML is more reliable)
    rule_capped = min(rb_score, 100)
    final_score = int(0.4 * rule_capped + 0.6 * ml_score)
    final_score = max(0, min(100, final_score))  # Clamp to 0-100

    # ── Determine risk level ──
    if final_score >= 70:
        risk = "HIGH"
    elif final_score >= 40:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    # Add ML context to reasons
    if ml_probability > 0.7:
        reasons.append("🤖 ML model flags this URL as highly suspicious")
    elif ml_probability > 0.4:
        reasons.append("🤖 ML model detects moderate phishing indicators")
    else:
        reasons.append("🤖 ML model considers this URL relatively safe")

    # If no rule-based flags but ML is concerned
    if rb_score == 0 and ml_probability < 0.3:
        reasons.insert(0, "✅ No significant phishing indicators detected")

    return {
        "url": url,
        "risk": risk,
        "score": final_score,
        "reasons": reasons,
        "features": features,
        "details": {
            "rule_based_score": rule_capped,
            "ml_probability": round(ml_probability, 4),
            "ml_score": ml_score
        }
    }
