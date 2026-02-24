import re
from urllib.parse import urlparse

SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly"]
PUBLIC_DOMAINS = ["gmail.com", "yahoo.com", "outlook.com"]

# Strict domain validation pattern
DOMAIN_REGEX = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.[A-Za-z]{2,})+$"
)

def is_valid_ipv4(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        num = int(part)
        if num < 0 or num > 255:
            return False
    return True


def extract_features(url):
    features = {}
    url = url.strip()

    # ------------------------------------------------
    # Handle missing scheme (http/https)
    # ------------------------------------------------
    parsed = urlparse(url)

    if not parsed.netloc:
        parsed = urlparse("https://" + url)

    domain = parsed.netloc.lower()

    # ------------------------------------------------
    # Basic Features
    # ------------------------------------------------
    features["length"] = len(url)
    features["domain"] = domain
    features["has_https"] = url.lower().startswith("https")

    # ------------------------------------------------
    # Malformed & Invalid Structure Checks
    # ------------------------------------------------
    features["has_comma"] = "," in url
    features["has_space"] = " " in url
    features["valid_domain_format"] = bool(DOMAIN_REGEX.match(domain))

    # ------------------------------------------------
    # Obfuscation Checks
    # ------------------------------------------------
    features["has_at_symbol"] = "@" in url
    features["has_hyphen"] = "-" in domain
    features["has_punycode"] = domain.startswith("xn--")
    features["has_numbers_in_domain"] = bool(re.search(r"[0-9]", domain))

    # Cloudflare tunnel detection
    features["cloudflare_tunnel"] = domain.endswith("trycloudflare.com")

    # Long subdomain detection
    if domain:
        first_label = domain.split(".")[0]
        features["long_subdomain"] = len(first_label) > 25
    else:
        features["long_subdomain"] = False

    # ------------------------------------------------
    # IP Address Detection
    # ------------------------------------------------
    features["has_ip"] = is_valid_ipv4(domain)

    # ------------------------------------------------
    # Subdomain Checks
    # ------------------------------------------------
    features["subdomain_count"] = domain.count(".")
    features["suspicious_subdomain"] = features["subdomain_count"] > 3

    # ------------------------------------------------
    # Public Domain Abuse
    # ------------------------------------------------
    features["public_domain_abuse"] = any(
        domain == pub or domain.endswith("." + pub)
        for pub in PUBLIC_DOMAINS
    )

    # ------------------------------------------------
    # URL Shorteners
    # ------------------------------------------------
    features["shortened_url"] = any(
        domain == short or domain.endswith("." + short)
        for short in SHORTENERS
    )

    # ------------------------------------------------
    # Redirect Patterns
    # ------------------------------------------------
    features["redirect_pattern"] = (
        "redirect" in url.lower() or "?url=" in url.lower()
    )

    # ------------------------------------------------
    # Typosquatting Detection (Improved)
    # ------------------------------------------------
    common_brands = [
        "paypal", "facebook", "microsoft",
        "amazon", "google", "apple"
    ]

    features["possible_typosquat"] = any(
        re.search(
            brand.replace("o", "[o0]").replace("l", "[l1]"),
            domain
        )
        for brand in common_brands
    )

    # ------------------------------------------------
    # Final Structural Red Flag
    # ------------------------------------------------
    features["structural_anomaly"] = (
        features["has_comma"]
        or features["has_space"]
        or not features["valid_domain_format"]
    )

    return features
