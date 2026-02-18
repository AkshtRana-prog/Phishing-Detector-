from features.feature_extraction import extract_features
from alerts.alert_manager import generate_alert, Colors


BRANDS = ["paypal", "facebook", "instagram", "amazon", "microsoft", "google"]


def check_phishing(features):
    score = 0
    reasons = []

    domain = features.get("domain", "").lower()

    # -------------------------------------------------
    # 🔥 CRITICAL: Brand Impersonation (Direct Match)
    # -------------------------------------------------
    for brand in BRANDS:
        if brand in domain:
            # Allow official domains like paypal.com or mail.paypal.com
            if not (domain == f"{brand}.com" or domain.endswith(f".{brand}.com")):
                reasons.append(f"Brand impersonation detected: {brand}")
                return "PHISHING", reasons, "HIGH"

    # -------------------------------------------------
    # 🔥 CRITICAL: Typosquatting
    # -------------------------------------------------
    if features.get("possible_typosquat"):
        reasons.append("Brand impersonation detected (typosquatting attack)")
        return "PHISHING", reasons, "HIGH"

    # -------------------------------------------------
    # HIGH RISK
    # -------------------------------------------------
    if features.get("has_ip"):
        score += 5
        reasons.append("IP address used instead of domain")

    if features.get("has_punycode"):
        score += 5
        reasons.append("Punycode detected")

    # -------------------------------------------------
    # MEDIUM RISK
    # -------------------------------------------------
    if features.get("has_at_symbol"):
        score += 3
        reasons.append("Contains '@' symbol")

    if features.get("shortened_url"):
        score += 3
        reasons.append("Shortened URL detected")

    if features.get("suspicious_subdomain"):
        score += 3
        reasons.append("Suspicious subdomain detected")

    if features.get("redirect_pattern"):
        score += 3
        reasons.append("Multiple redirect patterns detected")

    # -------------------------------------------------
    # LOW RISK
    # -------------------------------------------------
    if features.get("has_hyphen"):
        score += 1
        reasons.append("Hyphen used in domain")

    if features.get("has_numbers_in_domain"):
        score += 1
        reasons.append("Numbers used in domain")

    if features.get("long_subdomain"):
        score += 1
        reasons.append("Long subdomain detected")

    # -------------------------------------------------
    # Severity Logic
    # -------------------------------------------------
    if score >= 6:
        return "PHISHING", reasons, "HIGH"
    elif score >= 3:
        return "SUSPICIOUS", reasons, "MEDIUM"
    elif score >= 1:
        return "LOW RISK", reasons, "LOW"
    else:
        return "LEGITIMATE", reasons, "LOW"


def main():
    print(f"{Colors.CYAN}=== Phishing Detection System ==={Colors.RESET}")
    print(f"{Colors.BLUE}Type 'exit' or 'quit' to stop.{Colors.RESET}\n")

    try:
        while True:
            user_input = input(
                f"{Colors.BLUE}Enter URL or Email text:{Colors.RESET} "
            ).strip()

            if user_input.lower() in ["exit", "quit"]:
                print(f"\n{Colors.CYAN}Exiting Phishing Detection System...{Colors.RESET}")
                break

            if not user_input:
                print(f"{Colors.YELLOW}Input cannot be empty.{Colors.RESET}\n")
                continue

            features = extract_features(user_input)
            result, reasons, severity = check_phishing(features)

            generate_alert(user_input, result, reasons, severity)

    except KeyboardInterrupt:
        print(f"\n\n{Colors.CYAN}Exiting Phishing Detection System...{Colors.RESET}")


if __name__ == "__main__":
    main()
