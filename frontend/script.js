/**
 * PhishShield Pro — Frontend Logic
 * ==================================
 * Handles URL scanning, API communication,
 * loading animations, and result rendering.
 */

// ── Configuration ──
const API_BASE = 'http://localhost:5000';

// ── DOM Elements ──
const urlInput = document.getElementById('urlInput');
const scanBtn = document.getElementById('scanBtn');
const clearBtn = document.getElementById('clearBtn');
const errorMsg = document.getElementById('errorMsg');
const loadingSection = document.getElementById('loadingSection');
const resultsSection = document.getElementById('resultsSection');
const scannerSection = document.getElementById('scannerSection');

// ── Initialize particles on load ──
document.addEventListener('DOMContentLoaded', () => {
    createParticles();
    setupInputListeners();
});


// ═══════════════════════════════════════
//  Background Particles
// ═══════════════════════════════════════

function createParticles() {
    const container = document.getElementById('bgParticles');
    const count = 25;

    for (let i = 0; i < count; i++) {
        const p = document.createElement('div');
        p.classList.add('particle');
        const size = Math.random() * 4 + 2;
        p.style.width = size + 'px';
        p.style.height = size + 'px';
        p.style.left = Math.random() * 100 + '%';
        p.style.animationDuration = (Math.random() * 15 + 10) + 's';
        p.style.animationDelay = (Math.random() * 10) + 's';

        // Random color variant
        const colors = ['#6366f1', '#06b6d4', '#8b5cf6', '#818cf8'];
        p.style.background = colors[Math.floor(Math.random() * colors.length)];

        container.appendChild(p);
    }
}


// ═══════════════════════════════════════
//  Input Listeners
// ═══════════════════════════════════════

function setupInputListeners() {
    // Show/hide clear button
    urlInput.addEventListener('input', () => {
        clearBtn.style.display = urlInput.value.length > 0 ? 'flex' : 'none';
        hideError();
    });

    // Clear button
    clearBtn.addEventListener('click', () => {
        urlInput.value = '';
        clearBtn.style.display = 'none';
        urlInput.focus();
        hideError();
    });

    // Enter key to scan
    urlInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            scanURL();
        }
    });
}


// ═══════════════════════════════════════
//  Set Example URL
// ═══════════════════════════════════════

function setExample(url) {
    urlInput.value = url;
    clearBtn.style.display = 'flex';
    urlInput.focus();
    hideError();

    // Subtle highlight animation
    urlInput.style.borderColor = '#6366f1';
    setTimeout(() => { urlInput.style.borderColor = ''; }, 600);
}


// ═══════════════════════════════════════
//  Main Scan Function
// ═══════════════════════════════════════

async function scanURL() {
    const url = urlInput.value.trim();

    // Validate input
    if (!url) {
        showError('Please enter a URL to scan.');
        urlInput.focus();
        return;
    }

    // Basic client-side validation
    if (url.length < 4) {
        showError('Please enter a valid URL (e.g., https://example.com).');
        return;
    }

    // Prepare UI for loading
    hideError();
    setLoadingState(true);
    showSection('loading');

    // Animate loading steps
    animateLoadingSteps();

    try {
        const response = await fetch(`${API_BASE}/scan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Scan failed. Please try again.');
        }

        // Wait for loading animation to finish (min 2s for UX)
        await delay(2000);

        // Render results
        renderResults(data);
        showSection('results');

    } catch (err) {
        showSection('scanner');
        if (err.message.includes('Failed to fetch') || err.message.includes('NetworkError')) {
            showError('Cannot reach the server. Make sure the backend is running on port 5000.');
        } else {
            showError(err.message);
        }
    } finally {
        setLoadingState(false);
    }
}


// ═══════════════════════════════════════
//  Loading Animation Steps
// ═══════════════════════════════════════

function animateLoadingSteps() {
    const steps = ['step1', 'step2', 'step3', 'step4'];
    const delays = [0, 500, 1000, 1500];

    steps.forEach((id, i) => {
        const el = document.getElementById(id);
        el.classList.remove('active', 'done');
    });

    steps.forEach((id, i) => {
        setTimeout(() => {
            const el = document.getElementById(id);
            // Mark previous steps as done
            for (let j = 0; j < i; j++) {
                document.getElementById(steps[j]).classList.remove('active');
                document.getElementById(steps[j]).classList.add('done');
            }
            el.classList.add('active');
        }, delays[i]);
    });

    // Mark all done at end
    setTimeout(() => {
        steps.forEach(id => {
            const el = document.getElementById(id);
            el.classList.remove('active');
            el.classList.add('done');
        });
    }, 2000);
}


// ═══════════════════════════════════════
//  Render Results
// ═══════════════════════════════════════

function renderResults(data) {
    const { url, risk, score, reasons, features, details } = data;

    // ── Risk Badge ──
    const riskCard = document.getElementById('riskCard');
    const riskBadge = document.getElementById('riskBadge');
    const badgeIcon = document.getElementById('badgeIcon');
    const badgeText = document.getElementById('badgeText');

    // Remove old classes
    riskCard.className = 'result-card risk-card';
    riskBadge.className = 'risk-badge';

    if (risk === 'LOW') {
        riskCard.classList.add('risk-low');
        riskBadge.classList.add('badge-low');
        badgeIcon.textContent = '🛡️';
        badgeText.textContent = 'Safe';
    } else if (risk === 'MEDIUM') {
        riskCard.classList.add('risk-medium');
        riskBadge.classList.add('badge-medium');
        badgeIcon.textContent = '⚠️';
        badgeText.textContent = 'Suspicious';
    } else {
        riskCard.classList.add('risk-high');
        riskBadge.classList.add('badge-high');
        badgeIcon.textContent = '🚨';
        badgeText.textContent = 'Dangerous';
    }

    // ── Scanned URL ──
    document.getElementById('scannedUrl').textContent = url;

    // ── Score Ring ──
    const scoreProgress = document.getElementById('scoreProgress');
    const scoreValue = document.getElementById('scoreValue');
    const circumference = 2 * Math.PI * 60; // r=60

    scoreProgress.className = 'score-progress';
    if (risk === 'LOW') scoreProgress.classList.add('low');
    if (risk === 'MEDIUM') scoreProgress.classList.add('medium');
    if (risk === 'HIGH') scoreProgress.classList.add('high');

    // Animate score
    const offset = circumference - (score / 100) * circumference;
    setTimeout(() => {
        scoreProgress.style.strokeDashoffset = offset;
    }, 100);

    animateCounter(scoreValue, 0, score, 1200);

    // Set score value text color
    if (risk === 'LOW') scoreValue.style.color = 'var(--risk-low)';
    if (risk === 'MEDIUM') scoreValue.style.color = 'var(--risk-medium)';
    if (risk === 'HIGH') scoreValue.style.color = 'var(--risk-high)';

    // ── Score Breakdown ──
    if (details) {
        const ruleScore = details.rule_based_score || 0;
        const mlScore = details.ml_score || 0;
        const mlProba = details.ml_probability || 0;

        document.getElementById('ruleScore').textContent = ruleScore;
        document.getElementById('mlScore').textContent = mlScore;
        document.getElementById('mlConf').textContent = (mlProba * 100).toFixed(1) + '%';

        setTimeout(() => {
            document.getElementById('ruleBarFill').style.width = Math.min(ruleScore, 100) + '%';
            document.getElementById('mlBarFill').style.width = mlScore + '%';
            document.getElementById('mlConfFill').style.width = (mlProba * 100) + '%';
        }, 200);
    }

    // ── Reasons ──
    const reasonsList = document.getElementById('reasonsList');
    reasonsList.innerHTML = '';

    reasons.forEach((reason, i) => {
        const li = document.createElement('li');
        li.className = 'reason-item';
        li.style.animationDelay = (i * 0.08) + 's';

        // Classify reason type
        if (reason.includes('✅') || reason.includes('safe') || reason.includes('Safe')) {
            li.classList.add('safe');
        } else if (reason.includes('🚨') || reason.includes('IP') || reason.includes('highly') || reason.includes('password') || reason.includes('@')) {
            li.classList.add('danger');
        } else if (reason.includes('⚠️') || reason.includes('🔑') || reason.includes('🔍') || reason.includes('🌐')) {
            li.classList.add('warning');
        }

        li.textContent = reason;
        reasonsList.appendChild(li);
    });

    // ── Features Grid ──
    const featuresGrid = document.getElementById('featuresGrid');
    featuresGrid.innerHTML = '';

    const featureLabels = {
        url_length: 'URL Length',
        has_https: 'HTTPS',
        num_hyphens: 'Hyphens',
        num_dots: 'Dots',
        has_ip: 'IP Address',
        has_suspicious_tld: 'Suspicious TLD',
        keyword_count: 'Keywords',
        special_chars: 'Special Chars',
        subdomain_count: 'Subdomains',
        path_depth: 'Path Depth',
        entropy: 'Entropy'
    };

    Object.entries(features).forEach(([key, val], i) => {
        const div = document.createElement('div');
        div.className = 'feature-item';
        div.style.animationDelay = (i * 0.05) + 's';

        const name = document.createElement('span');
        name.className = 'feature-name';
        name.textContent = featureLabels[key] || key;

        const value = document.createElement('span');
        value.className = 'feature-value';

        // Format boolean features
        if (key === 'has_https') {
            value.textContent = val === 1 ? '✓ Yes' : '✗ No';
            value.classList.add(val === 1 ? 'val-safe' : 'val-danger');
        } else if (key === 'has_ip') {
            value.textContent = val === 1 ? '⚠ Detected' : '✓ None';
            value.classList.add(val === 1 ? 'val-danger' : 'val-safe');
        } else if (key === 'has_suspicious_tld') {
            value.textContent = val === 1 ? '⚠ Yes' : '✓ No';
            value.classList.add(val === 1 ? 'val-warn' : 'val-safe');
        } else if (key === 'entropy') {
            value.textContent = val.toFixed(2);
            value.classList.add(val > 4.5 ? 'val-warn' : 'val-safe');
        } else if (key === 'keyword_count') {
            value.textContent = val;
            value.classList.add(val > 0 ? 'val-warn' : 'val-safe');
        } else if (key === 'url_length') {
            value.textContent = val;
            value.classList.add(val > 50 ? 'val-warn' : 'val-safe');
        } else {
            value.textContent = val;
        }

        div.appendChild(name);
        div.appendChild(value);
        featuresGrid.appendChild(div);
    });
}


// ═══════════════════════════════════════
//  Animated Counter
// ═══════════════════════════════════════

function animateCounter(element, start, end, duration) {
    const range = end - start;
    const startTime = performance.now();

    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);

        // Ease out cubic
        const eased = 1 - Math.pow(1 - progress, 3);
        const value = Math.round(start + range * eased);

        element.textContent = value;

        if (progress < 1) {
            requestAnimationFrame(update);
        }
    }

    requestAnimationFrame(update);
}


// ═══════════════════════════════════════
//  Section Management
// ═══════════════════════════════════════

function showSection(name) {
    scannerSection.style.display = name === 'scanner' ? 'block' : 'none';
    loadingSection.style.display = name === 'loading' ? 'block' : 'none';
    resultsSection.style.display = name === 'results' ? 'block' : 'none';
}

function resetScanner() {
    // Reset score ring
    const scoreProgress = document.getElementById('scoreProgress');
    scoreProgress.style.strokeDashoffset = 377;

    // Reset breakdown bars
    document.getElementById('ruleBarFill').style.width = '0%';
    document.getElementById('mlBarFill').style.width = '0%';
    document.getElementById('mlConfFill').style.width = '0%';

    // Show scanner
    showSection('scanner');
    urlInput.focus();
}


// ═══════════════════════════════════════
//  UI Helpers
// ═══════════════════════════════════════

function setLoadingState(isLoading) {
    const btnText = scanBtn.querySelector('.btn-text');
    const btnIcon = scanBtn.querySelector('.scan-icon');
    const btnLoader = scanBtn.querySelector('.btn-loader');

    scanBtn.disabled = isLoading;
    btnText.style.display = isLoading ? 'none' : 'inline';
    btnIcon.style.display = isLoading ? 'none' : 'inline';
    btnLoader.style.display = isLoading ? 'flex' : 'none';
}

function showError(msg) {
    errorMsg.textContent = msg;
    errorMsg.style.display = 'block';
}

function hideError() {
    errorMsg.style.display = 'none';
}

function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}