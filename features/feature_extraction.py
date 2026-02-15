import re
from urllib.parse import urlparse

SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly"]
PUBLIC_DOMAINS = ["gmail.com", "yahoo.com", "outlook.com"]

def extract_features(url):
    features = {}
    url = url.strip()

    # ✅ NEW: Proper domain parsing (fixes plain text input issue)
    parsed = urlparse(url)

    # ✅ NEW: If no scheme (http/https), add https automatically
    if not parsed.netloc:
        parsed = urlparse("https://" + url)

    domain = parsed.netloc.lower()

    features["length"] = len(url)
    features["domain"] = domain
    features["has_https"] = url.lower().startswith("https")

    # --- Obfuscation Checks ---
    features["has_at_symbol"] = "@" in url
    features["has_hyphen"] = "-" in domain
    features["has_punycode"] = domain.startswith("xn--")
    features["has_numbers_in_domain"] = bool(re.search(r"[0-9]", domain))

    # ✅ FIXED: Exact Cloudflare tunnel detection (prevents false positives)
    features["cloudflare_tunnel"] = domain.endswith("trycloudflare.com")

    # ✅ FIXED: Safer long subdomain detection
    if domain:
        first_label = domain.split(".")[0]
        features["long_subdomain"] = len(first_label) > 25
    else:
        features["long_subdomain"] = False


    # --- IP Address Detection ---
    features["has_ip"] = bool(
        re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", domain)
    )

    # --- Fake Subdomain Detection ---
    features["subdomain_count"] = domain.count(".")
    features["suspicious_subdomain"] = features["subdomain_count"] > 3

    # ✅ FIXED: Exact public domain misuse check
    features["public_domain_abuse"] = any(
        domain == pub or domain.endswith("." + pub)
        for pub in PUBLIC_DOMAINS
    )

    # ✅ FIXED: Exact shortener detection (no substring matching)
    features["shortened_url"] = any(
        domain == short or domain.endswith("." + short)
        for short in SHORTENERS
    )

    # --- Redirect Patterns ---
    features["redirect_pattern"] = (
        "redirect" in url.lower() or "?url=" in url.lower()
    )

    # --- Typosquatting Indicators ---
    features["possible_typosquat"] = bool(
        re.search(r"(paypa1|faceb00k|micros0ft|amaz0n)", domain)
    )

    return features
