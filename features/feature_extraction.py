import re

def extract_features(text):
    features = {}

    features["length"] = len(text)
    features["has_ip"] = bool(re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", text))
    features["has_https"] = "https" in text.lower()
    features["has_urgent_words"] = any(
        word in text.lower()
        for word in ["verify", "urgent", "account", "login", "password"]
    )
    features["has_special_chars"] = any(char in text for char in ["@", "-", "//"])

    return features
