from features.feature_extraction import extract_features
from rules.rule_engine import check_phishing
from alerts.alert_manager import generate_alert

def main():
    print("=== Phishing Detection System ===")

    user_input = input("Enter URL or Email text: ")

    features = extract_features(user_input)
    result, reasons, severity = check_phishing(features)

    generate_alert(result, reasons, severity)

if __name__ == "__main__":
    main()
