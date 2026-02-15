from features.feature_extraction import extract_features
from rules.rule_engine import check_phishing


def main():
    print("=== Phishing Detection System ===")
    print("Type 'exit' or 'quit' to stop.\n")

    while True:
        user_input = input("Enter URL or Email text: ").strip()

        # Exit condition
        if user_input.lower() in ["exit", "quit"]:
            print("\nExiting Phishing Detection System...")
            break

        if not user_input:
            print("Input cannot be empty.\n")
            continue

        features = extract_features(user_input)
        result, reasons, severity = check_phishing(features)

        print("\n=== Detection Result ===")
        print(f"Status   : {result}")
        print(f"Severity : {severity}")

        if reasons:
            print("Reasons:")
            for reason in reasons:
                print(f"- {reason}")
        else:
            print("No suspicious indicators found.")

        print("\n" + "-" * 40 + "\n")


if __name__ == "__main__":
    main()
