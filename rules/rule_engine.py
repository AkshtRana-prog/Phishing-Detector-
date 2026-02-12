def check_phishing(features):
    score = 0
    reasons = []

    # High Risk Indicators
    if features.get("has_at_symbol", False):
        score += 3
        reasons.append("@ symbol misuse")

    if features.get("has_punycode", False):
        score += 3
        reasons.append("Punycode domain detected")

    if features.get("has_ip", False):
        score += 3
        reasons.append("Numeric IP address used")

    if features.get("shortened_url", False):
        score += 2
        reasons.append("URL shortener detected")

    if features.get("redirect_pattern", False):
        score += 2
        reasons.append("Redirect pattern detected")

    if features.get("possible_typosquat", False):
        score += 3
        reasons.append("Possible typosquatting")

    if features.get("public_domain_abuse", False):
        score += 2
        reasons.append("Public domain misuse")

    if features.get("suspicious_subdomain", False):
        score += 2
        reasons.append("Suspicious deep subdomain")

    if features.get("has_hyphen", False):
        score += 1
        reasons.append("Hyphen in domain")

    if features.get("has_numbers_in_domain", False):
        score += 1
        reasons.append("Numbers in domain")
    if features.get("cloudflare_tunnel", False):
     score += 3
    reasons.append("Cloudflare tunnel domain detected")

    if features.get("long_subdomain", False):
     score += 2
    reasons.append("Unusually long subdomain")


    # Final Severity
    if score >= 6:
        return "PHISHING", reasons, "HIGH"
    elif score >= 3:
        return "SUSPICIOUS", reasons, "MEDIUM"
    else:
        return "LEGITIMATE", reasons, "LOW"
