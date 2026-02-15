from features.feature_extraction import extract_features
from rules.rule_engine import check_phishing


# 🎨 Terminal Colors
class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    RESET = "\033[0m"


def main():
    print(f"{Colors.CYAN}=== Phishing Detection System ==={Colors.RESET}")
    print("Type 'exit' or 'quit' to stop.\n")

    while True:
        user_input = input(f"{Colors.BLUE}Enter URL or Email text: {Colors.RESET}").strip()

        # Exit condition
        if user_input.lower() in ["exit", "quit"]:
            print(f"\n{Colors.CYAN}Exiting Phishing Detection System...{Colors.RESET}")
            break

        if not user_input:
            print(f"{Colors.YELLOW}Input cannot be empty.{Colors.RESET}\n")
            continue

        features = extract_features(user_input)
        result, reasons, severity = check_phishing(features)

        print(f"\n{Colors.CYAN}=== Detection Result ==={Colors.RESET}")

        # 🎯 Status Color
        if result.upper() == "PHISHING":
            status_color = Colors.RED
        else:
            status_color = Colors.GREEN

        # 🎯 Severity Color
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

        print(f"\n{Colors.CYAN}{'-' * 40}{Colors.RESET}\n")


if __name__ == "__main__":
    main()
