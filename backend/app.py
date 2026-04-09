"""
PhishShield Pro - Flask API Server
====================================
REST API that accepts URLs and returns phishing risk analysis.
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from analyzer import analyze_url
from model import get_model
import re

# ── Initialize Flask app ──
app = Flask(__name__)
CORS(app)  # Enable CORS for frontend communication


def is_valid_url(url: str) -> bool:
    """
    Basic URL validation — checks for a reasonable URL pattern.
    Accepts http://, https://, and raw domains.
    """
    pattern = re.compile(
        r'^(https?://)?'                # optional scheme
        r'(\d{1,3}\.){3}\d{1,3}'       # ...or IP
        r'|'
        r'^(https?://)?'                # optional scheme
        r'[a-zA-Z0-9]+'                # domain
        r'([-.][a-zA-Z0-9]+)*'         # sub-domains
        r'\.[a-zA-Z]{2,}'              # TLD
        r'(:\d+)?'                     # optional port
        r'(/.*)?$',                    # optional path
        re.IGNORECASE
    )
    return bool(pattern.match(url.strip()))


@app.route('/scan', methods=['POST'])
def scan_url():
    """
    POST /scan
    ----------
    Accepts JSON: { "url": "http://example.com" }
    Returns risk analysis with score, reasons, and features.
    """
    # Parse request body
    data = request.get_json(silent=True)

    if not data or 'url' not in data:
        return jsonify({
            "error": "Missing 'url' field in request body",
            "example": {"url": "http://example.com"}
        }), 400

    url = data['url'].strip()

    if not url:
        return jsonify({"error": "URL cannot be empty"}), 400

    # Add scheme if missing (for analysis consistency)
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    try:
        # Run the full analysis
        result = analyze_url(url)
        return jsonify(result), 200

    except Exception as e:
        return jsonify({
            "error": f"Analysis failed: {str(e)}",
            "url": url
        }), 500


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({"status": "ok", "service": "PhishShield Pro API"}), 200


# ── Start server ──
if __name__ == '__main__':
    # Pre-train/load the ML model on startup
    print("[PhishShield] Initializing ML model...")
    get_model()
    print("[PhishShield] Server starting on http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
