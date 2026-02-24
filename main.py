import time
from datetime import datetime

from features.feature_extraction import extract_features
from alerts.alert_manager import generate_alert, Colors


BRANDS = ["paypal", "facebook", "instagram", "amazon", "microsoft", "google"]


# ======================================================
# 🔥 COOL BOOT SEQUENCE
# ======================================================

def boot_sequence():
    print(f"{Colors.GREEN}")
    steps = [
        "[+] Initializing Phishing Detector...",
        "[+] Loading threat intelligence rules...",
        "[+] Verifying brand protection module...",
        "[+] Starting analysis engine...",
        "[✓] System Ready."
    ]

    for step in steps:
        print(step)
        time.sleep(0.5)

    print(f"{Colors.RESET}")
    time.sleep(0.5)


# ======================================================
# 🔥 PROFESSIONAL BANNER
# ======================================================

def show_banner():
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"{Colors.CYAN}")
    print("██████╗ ██╗  ██╗██╗███████╗██╗  ██╗")
    print("██╔══██╗██║  ██║██║██╔════╝██║  ██║")
    print("██████╔╝███████║██║███████╗███████║")
    print("██╔═══╝ ██╔══██║██║╚════██║██╔══██║")
    print("██║     ██║  ██║██║███████║██║  ██║")
    print("╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝")
    print("")
    print("           REAL-TIME PHISHING DETECTOR")
    print("                 Version 2.0")
    print("")
    print("           Developed by Aksht Rana")
    print(f"{Colors.RESET}")

    print(f"{Colors.BLUE}{'='*65}{Colors.RESET}")
    print(f"{Colors.YELLOW}System Time : {now}{Colors.RESET}")
    print(f"{Colors.BLUE}{'='*65}{Colors.RESET}\n")


# ======================================================
# 🔥 RULE-BASED PHISHING ENGINE
# ======================================================

def check_phishing(features):
    score = 0
    reasons = []
    domain = features.get("domain", "").lower()

    # 🚨 CRITICAL: Brand Impersonation
    for brand in BRANDS:
        if brand in domain:
            if not (domain == f"{brand}.com" or domain.endswith(f".{brand}.com")):
                reasons.append(f"Brand impersonation detected: {brand}")
                return "PHISHING", reasons, "HIGH"

    # 🚨 Typosquatting
    if features.get("possible_typosquat"):
        reasons.append("Brand impersonation (typosquatting attack)")
        return "PHISHING", reasons, "HIGH"

    # 🔥 High Risk
    if features.get("structural_anomaly"):
        score += 5
        reasons.append("Malformed domain structure")

    if features.get("has_ip"):
        score += 5
        reasons.append("IP address used instead of domain")

    if features.get("has_punycode"):
        score += 5
        reasons.append("Punycode domain detected")

    # ⚠ Medium Risk
    if features.get("has_at_symbol"):
        score += 3
        reasons.append("@ symbol misuse")

    if features.get("shortened_url"):
        score += 3
        reasons.append("Shortened URL detected")

    if features.get("suspicious_subdomain"):
        score += 3
        reasons.append("Suspicious subdomain detected")

    if features.get("redirect_pattern"):
        score += 3
        reasons.append("Redirect pattern detected")

    # 🟡 Low Risk
    if features.get("has_hyphen"):
        score += 1
        reasons.append("Hyphen used in domain")

    if features.get("has_numbers_in_domain"):
        score += 1
        reasons.append("Numbers used in domain")

    if features.get("long_subdomain"):
        score += 1
        reasons.append("Unusually long subdomain")

    # 🎯 Final Classification
    if score >= 6:
        return "PHISHING", reasons, "HIGH"
    elif score >= 3:
        return "SUSPICIOUS", reasons, "MEDIUM"
    elif score >= 1:
        return "LOW RISK", reasons, "LOW"
    else:
        return "LEGITIMATE", ["No suspicious indicators found."], "LOW"


# ======================================================
# 🔥 MAIN LOOP
# ======================================================

def main():
    boot_sequence()
    show_banner()

    print(f"{Colors.BLUE}Type 'exit' or 'quit' to stop.\n{Colors.RESET}")

    try:
        while True:
            user_input = input(
                f"{Colors.BLUE}➤ Enter URL or Email to scan:{Colors.RESET} "
            ).strip()

            if user_input.lower() in ["exit", "quit"]:
                print(f"\n{Colors.CYAN}Shutting down Phishing Detector...{Colors.RESET}")
                time.sleep(0.5)
                break

            if not user_input:
                print(f"{Colors.YELLOW}Input cannot be empty.\n{Colors.RESET}")
                continue

            print(f"{Colors.YELLOW}Scanning...{Colors.RESET}")
            time.sleep(0.7)

            features = extract_features(user_input)
            result, reasons, severity = check_phishing(features)

            generate_alert(user_input, result, reasons, severity)

            print("\n" + "="*65 + "\n")

    except KeyboardInterrupt:
        print(f"\n\n{Colors.CYAN}Detector terminated by user.{Colors.RESET}")


if __name__ == "__main__":
    main()
