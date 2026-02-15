import re
import os
from urllib.parse import urlparse

SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly"]
PUBLIC_DOMAINS = ["gmail.com", "yahoo.com", "outlook.com"]


# ✅ Load Known Brands (Professional Absolute Path)
def load_known_brands():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(base_dir, "data", "known_brands.txt")

    if not os.path.exists(path):
        return []

    with open(path, "r") as f:
        return [line.strip().lower() for line in f if line.strip()]


# ✅ Levenshtein Distance Function
def levenshtein_distance(a, b):
    if len(a) < len(b):
        return levenshtein_distance(b, a)

    if len(b) == 0:
        return len(a)

    previous_row = range(len(b) + 1)

    for i, c1 in enumerate(a):
        current_row = [i + 1]
        for j, c2 in enumerate(b):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def extract_features(url):
    features = {}
    url = url.strip()

    parsed = urlparse(url)

    # Add https automatically if missing
    if not parsed.netloc:
        parsed = urlparse("https://" + url)

    domain = parsed.netloc.lower().replace("www.", "")

    features["length"] = len(url)
    features["domain"] = domain
    features["has_https"] = url.lower().startswith("https")

    # --- Obfuscation Checks ---
    features["has_at_symbol"] = "@" in url
    features["has_hyphen"] = "-" in domain
    features["has_punycode"] = domain.startswith("xn--")
    features["has_numbers_in_domain"] = bool(re.search(r"[0-9]", domain))

    # --- Cloudflare Tunnel ---
    features["cloudflare_tunnel"] = domain.endswith("trycloudflare.com")

    # --- Long Subdomain ---
    first_label = domain.split(".")[0] if domain else ""
    features["long_subdomain"] = len(first_label) > 25

    # --- IP Address Detection ---
    features["has_ip"] = bool(
        re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", domain)
    )

    # --- Subdomain Count ---
    features["subdomain_count"] = domain.count(".")
    features["suspicious_subdomain"] = features["subdomain_count"] > 3

    # --- Public Domain Abuse ---
    features["public_domain_abuse"] = any(
        domain == pub or domain.endswith("." + pub)
        for pub in PUBLIC_DOMAINS
    )

    # --- Shortened URL Detection ---
    features["shortened_url"] = any(
        domain == short or domain.endswith("." + short)
        for short in SHORTENERS
    )

    # --- Redirect Patterns ---
    features["redirect_pattern"] = (
        "redirect" in url.lower() or "?url=" in url.lower()
    )

    # ✅ Advanced Typosquatting Detection (Root Comparison)
    brands = load_known_brands()
    features["possible_typosquat"] = False

    domain_root = domain.split(".")[0]

    for brand in brands:
        brand_root = brand.split(".")[0]

        distance = levenshtein_distance(domain_root, brand_root)

        # Flag if 1–2 character difference only
        if 0 < distance <= 2:
            features["possible_typosquat"] = True
            break

    return features
