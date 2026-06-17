# ============================================================
# Phishing URL Detector
# Author: Sourabh (s0xandrew)
# Detects suspicious/phishing URLs using heuristic analysis
# Ethical Use: Analyze URLs for security research only
# ============================================================

import re
import urllib.parse
import datetime

# ── KNOWN PHISHING KEYWORDS ──────────────────────────────────
# Words commonly found in phishing URLs
PHISHING_KEYWORDS = [
    "login", "signin", "verify", "secure", "account",
    "update", "confirm", "banking", "paypal", "amazon",
    "microsoft", "apple", "google", "netflix", "ebay",
    "password", "credential", "wallet", "crypto", "bitcoin",
    "urgent", "suspended", "locked", "validate", "authenticate",
]

# ── SUSPICIOUS TLDs ──────────────────────────────────────────
# Top level domains commonly abused for phishing
SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq",   # Free domains — frequently abused
    ".xyz", ".top", ".click", ".link",
    ".online", ".site", ".info", ".biz",
]

# ── LEGITIMATE BRANDS BEING SPOOFED ─────────────────────────
# If URL contains brand name but NOT the real domain = spoofing
BRAND_DOMAINS = {
    "paypal":     "paypal.com",
    "amazon":     "amazon.com",
    "microsoft":  "microsoft.com",
    "apple":      "apple.com",
    "google":     "google.com",
    "netflix":    "netflix.com",
    "facebook":   "facebook.com",
    "instagram":  "instagram.com",
    "twitter":    "twitter.com",
    "ebay":       "ebay.com",
    "sbi":        "sbi.co.in",
    "hdfc":       "hdfcbank.com",
    "icici":      "icicibank.com",
}

# ── RESULTS ──────────────────────────────────────────────────
findings = []

def log(msg):
    print(msg)
    findings.append(msg)


# ── DETECTION MODULES ────────────────────────────────────────

def check_ip_url(url):
    """
    Check if URL uses raw IP instead of domain name.
    Legitimate sites use domain names.
    Phishing sites often use IPs to avoid domain blacklists.
    Example: http://192.168.1.1/login → suspicious
    """
    ip_pattern = r'https?://(\d{1,3}\.){3}\d{1,3}'
    if re.match(ip_pattern, url):
        return (True, "URL uses IP address instead of domain name")
    return (False, "")


def check_url_length(url):
    """
    Phishing URLs are often very long to hide the real domain.
    They add legitimate-looking paths after the fake domain.
    Example: http://paypal-secure-login.tk/paypal.com/login/verify
    Threshold: 75 characters (industry standard heuristic)
    """
    if len(url) > 75:
        return (True, f"URL is suspiciously long ({len(url)} characters)")
    return (False, "")


def check_https(url):
    """
    Check if URL uses HTTPS.
    Note: HTTPS does NOT mean safe — phishing sites use HTTPS too.
    But HTTP in 2026 for a login page is a red flag.
    """
    if url.startswith("http://"):
        return (True, "URL uses HTTP not HTTPS — insecure")
    return (False, "")


def check_suspicious_keywords(url):
    """
    Check URL for phishing-related keywords.
    Attackers use words like 'secure', 'login', 'verify'
    to make URLs look legitimate.
    """
    url_lower = url.lower()
    found = []
    for keyword in PHISHING_KEYWORDS:
        if keyword in url_lower:
            found.append(keyword)
    if found:
        return (True, f"Suspicious keywords found: {', '.join(found)}")
    return (False, "")


def check_suspicious_tld(url):
    """
    Check if URL uses a suspicious top-level domain.
    Free TLDs (.tk, .ml, .ga) are heavily abused for phishing
    because they cost nothing and are hard to track.
    """
    url_lower = url.lower()
    for tld in SUSPICIOUS_TLDS:
        if tld in url_lower:
            return (True, f"Suspicious TLD detected: {tld}")
    return (False, "")


def check_multiple_subdomains(url):
    """
    Count subdomains in the URL.
    Phishers use deep subdomains to hide the real domain:
    Example: paypal.com.login.verify.evil-site.tk
    The real domain here is evil-site.tk, not paypal.com
    """
    try:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname or ""
        parts = hostname.split(".")
        # More than 3 parts = multiple subdomains
        if len(parts) > 3:
            return (True, f"Multiple subdomains detected: {hostname}")
    except Exception:
        pass
    return (False, "")


def check_brand_spoofing(url):
    """
    Brand Spoofing Detection:
    Check if URL mentions a brand name but isn't the real domain.
    Example: 'paypal' in URL but domain isn't paypal.com = spoofing
    This is the most common phishing technique.
    """
    url_lower = url.lower()
    try:
        parsed = urllib.parse.urlparse(url)
        hostname = (parsed.hostname or "").lower()

        for brand, real_domain in BRAND_DOMAINS.items():
            # Brand name appears in URL
            if brand in url_lower:
                # But the real domain is NOT the hostname
                if real_domain not in hostname:
                    return (True, f"Brand spoofing detected: '{brand}' in URL but domain is '{hostname}' not '{real_domain}'")
    except Exception:
        pass
    return (False, "")


def check_special_characters(url):
    """
    Check for suspicious special characters in URL.
    @ symbol: http://google.com@evil.com → goes to evil.com
    Multiple dashes: paypal-secure-login-verify.com
    Encoded characters used to bypass filters.
    """
    flags = []

    if "@" in url:
        flags.append("'@' symbol found — may redirect to different host")

    # Count hyphens in domain
    try:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname or ""
        if hostname.count("-") >= 3:
            flags.append(f"Excessive hyphens in domain ({hostname.count('-')} found)")
    except Exception:
        pass

    if "%20" in url or "%2F" in url or "%3A" in url:
        flags.append("URL-encoded characters detected — possible obfuscation")

    if flags:
        return (True, " | ".join(flags))
    return (False, "")


def analyze_url(url):
    """
    Run all detection checks on a URL.
    Calculate risk score and final verdict.
    """
    log(f"\n{'='*60}")
    log(f"[ANALYZING] {url}")
    log(f"{'='*60}")

    # All detection checks
    checks = [
        ("IP-based URL",          check_ip_url(url)),
        ("URL Length",            check_url_length(url)),
        ("HTTPS Check",           check_https(url)),
        ("Phishing Keywords",     check_suspicious_keywords(url)),
        ("Suspicious TLD",        check_suspicious_tld(url)),
        ("Multiple Subdomains",   check_multiple_subdomains(url)),
        ("Brand Spoofing",        check_brand_spoofing(url)),
        ("Special Characters",    check_special_characters(url)),
    ]

    risk_score = 0
    triggered = []

    for check_name, (is_suspicious, reason) in checks:
        if is_suspicious:
            risk_score += 1
            triggered.append((check_name, reason))
            log(f"  [⚠ FLAG] {check_name}: {reason}")
        else:
            log(f"  [✓ PASS] {check_name}")

    # Risk verdict
    log(f"\n  Risk Score: {risk_score}/{len(checks)}")

    if risk_score == 0:
        verdict = "✅ LIKELY SAFE"
    elif risk_score <= 2:
        verdict = "🟡 LOW RISK — Proceed with caution"
    elif risk_score <= 4:
        verdict = "🟠 MEDIUM RISK — Likely suspicious"
    else:
        verdict = "🔴 HIGH RISK — Likely phishing!"

    log(f"  Verdict: {verdict}")
    return risk_score, verdict


def save_report():
    with open("phishing_report.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(findings))
    print("\n[REPORT] Saved to phishing_report.txt")


# ── TEST URLs ────────────────────────────────────────────────
TEST_URLS = [
    # Clearly safe
    "https://www.google.com",
    "https://github.com/s0xandrew",

    # Suspicious
    "http://paypal-secure-login.tk/verify/account",
    "http://192.168.1.1/login",
    "https://microsoft.com.login.verify.evil-site.xyz/signin",
    "http://www.amazon-account-update.com/login?redirect=verify",
    "https://sbi.co.in.secure-login.tk/banking/login",

    # Indian banking phishing pattern
    "http://hdfcbank-secure.ml/login/verify?session=abc123",
]


def main():
    print("=" * 60)
    print("   PHISHING URL DETECTOR")
    print("   By Sourabh (s0xandrew) | Ethical Use Only")
    print("=" * 60)

    log(f"\n[INFO] Scan started: {datetime.datetime.now()}")
    log(f"[INFO] Analyzing {len(TEST_URLS)} URLs\n")

    results = []
    for url in TEST_URLS:
        score, verdict = analyze_url(url)
        results.append((url, score, verdict))

    # Summary table
    log(f"\n{'='*60}")
    log("[SUMMARY TABLE]")
    log(f"{'='*60}")
    log(f"{'URL':<50} {'SCORE':<8} {'VERDICT'}")
    log(f"{'-'*50} {'-'*8} {'-'*20}")

    for url, score, verdict in results:
        short_url = url[:48] + ".." if len(url) > 48 else url
        log(f"{short_url:<50} {score:<8} {verdict}")

    log(f"\n[INFO] Scan completed: {datetime.datetime.now()}")
    save_report()


if __name__ == "__main__":
    main()