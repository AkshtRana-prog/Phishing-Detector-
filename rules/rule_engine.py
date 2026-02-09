def check_phishing(features):
    score = 0
    reasons = []

    if features["length"] > 75:
        score += 1
        reasons.append("Unusually long input")

    if features["has_ip"]:
        score += 2
        reasons.append("IP address detected in URL")

    if not features["has_https"]:
        score += 1
        reasons.append("No HTTPS detected")

    if features["has_urgent_words"]:
        score += 2
        reasons.append("Urgent phishing keywords detected")

    if features["has_special_chars"]:
        score += 1
        reasons.append("Suspicious characters detected")

    if score >= 4:
        return "PHISHING", reasons, "HIGH"
    elif score >= 2:
        return "SUSPICIOUS", reasons, "MEDIUM"
    else:
        return "LEGITIMATE", reasons, "LOW"
