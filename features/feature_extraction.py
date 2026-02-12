import re
from urllib.parse import urlparse

SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly"]
PUBLIC_DOMAINS = ["gmail.com", "yahoo.com", "outlook.com"]

def extract_features(url):
    features = {}
    url = url.strip()
    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    features["length"] = len(url)
    features["domain"] = domain
    features["has_https"] = url.lower().startswith("https")

    # --- Obfuscation Checks ---
    features["has_at_symbol"] = "@" in url
    features["has_hyphen"] = "-" in domain
    features["has_punycode"] = domain.startswith("xn--")
    features["has_numbers_in_domain"] = bool(re.search(r"[0-9]", domain))
    features["cloudflare_tunnel"] = "trycloudflare.com" in domain
    features["long_subdomain"] = len(domain.split(".")[0]) > 20



    # --- IP Address Detection ---
    features["has_ip"] = bool(
        re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", domain)
    )

    # --- Fake Subdomain Detection ---
    features["subdomain_count"] = domain.count(".")
    features["suspicious_subdomain"] = features["subdomain_count"] > 3

    # --- Public Domain Misuse ---
    features["public_domain_abuse"] = any(
        pub in domain for pub in PUBLIC_DOMAINS
    )

    # --- URL Shortener Detection ---
    features["shortened_url"] = any(
        short in domain for short in SHORTENERS
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
