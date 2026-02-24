BRANDS = ["paypal", "facebook", "instagram", "amazon", "microsoft", "google"]


def check_phishing(features):
    score = 0
    reasons = []

    domain = features.get("domain", "").lower()

    # --------------------------------------------------
    # 🚨 CRITICAL STRUCTURAL ISSUES
    # --------------------------------------------------

    if features.get("structural_anomaly"):
        score += 4
        reasons.append("Malformed or invalid domain structure")

    if features.get("has_comma"):
        score += 3
        reasons.append("Invalid separator used (comma)")

    if not features.get("valid_domain_format"):
        score += 3
        reasons.append("Domain format validation failed")

    # --------------------------------------------------
    # 🔥 HIGH RISK INDICATORS
    # --------------------------------------------------

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
        score += 3
        reasons.append("Possible typosquatting")

    # --------------------------------------------------
    # ⚠ MEDIUM RISK INDICATORS
    # --------------------------------------------------

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

    # --------------------------------------------------
    # 🟡 LOW RISK INDICATORS
    # --------------------------------------------------

    if features.get("has_hyphen"):
        score += 1
        reasons.append("Hyphen used in domain")

    if features.get("has_numbers_in_domain"):
        score += 1
        reasons.append("Numbers in domain")

    # --------------------------------------------------
    # 🏷 BRAND IMPERSONATION DETECTION
    # --------------------------------------------------

    for brand in BRANDS:
        if brand in domain:
            # Allow official domains
            if not (
                domain == f"{brand}.com"
                or domain.endswith(f".{brand}.com")
            ):
                score += 4
                reasons.append(f"Brand impersonation attempt: {brand}")
                break

    # --------------------------------------------------
    # 🎯 FINAL CLASSIFICATION
    # --------------------------------------------------

    if score >= 8:
        status = "PHISHING"
        severity = "HIGH"
    elif score >= 4:
        status = "SUSPICIOUS"
        severity = "MEDIUM"
    else:
        status = "LEGITIMATE"
        severity = "LOW"

    return status, reasons if reasons else ["No suspicious indicators found."], severity
