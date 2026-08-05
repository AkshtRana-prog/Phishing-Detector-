import re
from urllib.parse import urlparse

SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly"]
PUBLIC_DOMAINS = ["gmail.com", "yahoo.com", "outlook.com"]
BRANDS = ["paypal", "facebook", "instagram", "amazon", "microsoft", "google"]

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

def edit_distance(s1, s2):
    if len(s1) > len(s2):
        s1, s2 = s2, s1
    distances = range(len(s1) + 1)
    for i2, c2 in enumerate(s2):
        distances_ = [i2+1]
        for i1, c1 in enumerate(s1):
            if c1 == c2:
                distances_.append(distances[i1])
            else:
                distances_.append(1 + min((distances[i1], distances[i1 + 1], distances_[-1])))
        distances = distances_
    return distances[-1]

def extract_features(url):
    features = {}
    url = url.strip()

    parsed = urlparse(url)
    if not parsed.netloc:
        parsed = urlparse("https://" + url)

    domain = parsed.netloc.lower()

    features["length"] = len(url)
    features["domain"] = domain
    features["has_https"] = url.lower().startswith("https")

    features["has_comma"] = "," in url
    features["has_space"] = " " in url
    features["valid_domain_format"] = bool(DOMAIN_REGEX.match(domain))

    features["has_at_symbol"] = "@" in url
    features["has_hyphen"] = "-" in domain
    features["has_punycode"] = domain.startswith("xn--")
    features["has_numbers_in_domain"] = bool(re.search(r"[0-9]", domain))

    features["cloudflare_tunnel"] = domain.endswith("trycloudflare.com")

    if domain:
        first_label = domain.split(".")[0]
        features["long_subdomain"] = len(first_label) > 25
    else:
        features["long_subdomain"] = False

    features["has_ip"] = is_valid_ipv4(domain)
    features["subdomain_count"] = domain.count(".")
    features["suspicious_subdomain"] = features["subdomain_count"] > 3

    features["public_domain_abuse"] = any(
        domain == pub or domain.endswith("." + pub)
        for pub in PUBLIC_DOMAINS
    )

    features["shortened_url"] = any(
        domain == short or domain.endswith("." + short)
        for short in SHORTENERS
    )

    features["redirect_pattern"] = (
        "redirect" in url.lower() or "?url=" in url.lower()
    )

    common_brands = ["paypal", "facebook", "microsoft", "amazon", "google", "apple", "instagram"]
    features["possible_typosquat"] = False
    features["typosquat_target"] = None
    
    if domain:
        labels = domain.split(".")
        if len(labels) > 1:
            labels = labels[:-1]
        for label in labels:
            for brand in common_brands:
                if label == brand:
                    continue
                dist = edit_distance(label, brand)
                if dist <= 2 and abs(len(label) - len(brand)) <= 1:
                    features["possible_typosquat"] = True
                    features["typosquat_target"] = brand
                    break
            if features["possible_typosquat"]:
                break

    features["structural_anomaly"] = (
        features["has_comma"]
        or features["has_space"]
        or not features["valid_domain_format"]
    )

    return features

def check_phishing(features):
    score = 0
    reasons = []

    domain = features.get("domain", "").lower()

    # 🚨 HTTPS Rule (added as per specification)
    if not features.get("has_https"):
        score += 1
        reasons.append("Website is not using secure HTTPS encryption")

    # 🚨 CRITICAL STRUCTURAL ISSUES
    if features.get("structural_anomaly"):
        score += 4
        reasons.append("Malformed or invalid domain structure")

    if features.get("has_comma"):
        score += 3
        reasons.append("Invalid separator used (comma)")

    if not features.get("valid_domain_format"):
        score += 3
        reasons.append("Domain format validation failed")

    # 🔥 HIGH RISK INDICATORS
    if features.get("has_at_symbol"):
        score += 3
        reasons.append("@ symbol misuse")

    if features.get("has_punycode"):
        score += 3
        reasons.append("Punycode domain detected")

    if features.get("has_ip"):
        score += 3
        reasons.append("Numeric IP address used")

    if features.get("cloudflare_tunnel"):
        score += 3
        reasons.append("Cloudflare tunnel domain detected")

    if features.get("possible_typosquat"):
        score += 8
        target = features.get("typosquat_target")
        if target:
            reasons.append(f"Possible typosquatting targeting brand: {target}")
        else:
            reasons.append("Possible typosquatting detected")

    # ⚠ MEDIUM RISK INDICATORS
    if features.get("shortened_url"):
        score += 2
        reasons.append("URL shortener detected")

    if features.get("redirect_pattern"):
        score += 2
        reasons.append("Redirect pattern detected")

    if features.get("public_domain_abuse"):
        score += 2
        reasons.append("Public domain misuse")

    if features.get("suspicious_subdomain"):
        score += 2
        reasons.append("Suspicious deep subdomain")

    if features.get("long_subdomain"):
        score += 2
        reasons.append("Unusually long subdomain")

    # 🟡 LOW RISK INDICATORS
    if features.get("has_hyphen"):
        score += 1
        reasons.append("Hyphen used in domain")

    if features.get("has_numbers_in_domain"):
        score += 1
        reasons.append("Numbers in domain")

    # 🏷 BRAND IMPERSONATION DETECTION
    for brand in BRANDS:
        if brand in domain:
            if not (domain == f"{brand}.com" or domain.endswith(f".{brand}.com")):
                score += 4
                reasons.append(f"Brand impersonation attempt: {brand}")
                break

    # 🎯 FINAL CLASSIFICATION (Enterprise Scaled)
    # Thresholds: Low (0-3), Medium (4-7), High (8-11), Critical (12+)
    if score >= 12:
        status = "PHISHING"
        severity = "CRITICAL"
    elif score >= 8:
        status = "PHISHING"
        severity = "HIGH"
    elif score >= 4:
        status = "SUSPICIOUS"
        severity = "MEDIUM"
    else:
        status = "LEGITIMATE"
        severity = "LOW"

    return status, reasons if reasons else ["No suspicious indicators found."], severity, score
