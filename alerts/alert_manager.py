import logging
from datetime import datetime

logging.basicConfig(
    filename="logs/phishing.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

def generate_alert(result, reasons, severity):
    print("\n=== Detection Result ===")
    print(f"Status   : {result}")
    print(f"Severity : {severity}")

    if reasons:
        print("Reasons:")
        for reason in reasons:
            print(f"- {reason}")

    log_message = f"Status={result}, Severity={severity}, Reasons={reasons}"
    logging.info(log_message)
