import logging
import os

# ==============================
# 🎨 Terminal Colors
# ==============================

class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    RESET = "\033[0m"

# ==============================
# Logging Setup
# ==============================

os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    filename="logs/phishing.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# ==============================
# Alert Generator
# ==============================

def generate_alert(user_input, result, reasons, severity):
    print(f"\n{Colors.CYAN}=== Detection Result ==={Colors.RESET}")

    # 🚨 HIGH ALERT BANNER
    if severity.upper() == "HIGH":
        print(f"{Colors.RED} CRITICAL PHISHING ALERT {Colors.RESET}")

    # Status Color
    if result.upper() == "PHISHING":
        status_color = Colors.RED
    elif result.upper() == "SUSPICIOUS":
        status_color = Colors.YELLOW
    else:
        status_color = Colors.GREEN

    # Severity Color
    if severity.upper() == "HIGH":
        severity_color = Colors.RED
    elif severity.upper() == "MEDIUM":
        severity_color = Colors.YELLOW
    else:
        severity_color = Colors.GREEN

    print(f"Status   : {status_color}{result}{Colors.RESET}")
    print(f"Severity : {severity_color}{severity}{Colors.RESET}")

    if reasons:
        print(f"\n{Colors.BLUE}Reasons:{Colors.RESET}")
        for reason in reasons:
            print(f"{Colors.YELLOW}- {reason}{Colors.RESET}")
    else:
        print(f"{Colors.GREEN}No suspicious indicators found.{Colors.RESET}")

    print(f"\n{Colors.CYAN}{'-'*40}{Colors.RESET}\n")

    # Logging (no color in logs)
    reason_text = " | ".join(reasons) if reasons else "None"
    log_message = (
        f"Input='{user_input}' | "
        f"Status={result} | "
        f"Severity={severity} | "
        f"Reasons={reason_text}"
    )

    if severity.upper() == "HIGH":
        logging.warning(log_message)
    else:
        logging.info(log_message)
