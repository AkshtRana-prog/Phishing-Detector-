import re

# Simple list of high-risk keywords commonly used in email phishing
PHISHING_KEYWORDS = [
    "verify", "update", "account", "login", "password", "security", "alert", "suspend",
    "unauthorized", "billing", "invoice", "payment", "bank", "credit", "card", "expire",
    "urgent", "action required", "immediate", "restricted", "winner", "prize", "gift card"
]

class PhishingNLPClassifier:
    def __init__(self):
        self.model = None
        self.is_ml_active = False

        # Attempt to load Hugging Face pipeline
        try:
            from transformers import pipeline
            # DistilRoBERTa-base fine-tuned on phishing email text
            self.model = pipeline(
                "text-classification",
                model="mrm8488/distilroberta-finetuned-phishing",
                device=-1 # Default to CPU to save memory
            )
            self.is_ml_active = True
            print("[✓] Loaded Hugging Face Phishing NLP Model successfully.")
        except Exception as e:
            print(f"[!] NLP Model loading skipped (Using Heuristic Fallback). Reason: {e}")

    def predict(self, text):
        if not text:
            return {"label": "SAFE", "confidence": 1.0, "is_ml": False}

        # 1. Try ML model prediction if active
        if self.is_ml_active and self.model:
            try:
                result = self.model(text[:512])[0]  # Truncate to avoid context window limit
                # Hugging Face output format: {'label': 'LABEL_X', 'score': 0.99} or similar
                # Let's map label output
                label = result["label"].upper()
                score = result["score"]

                # Convert model-specific label output
                is_phish = "LABEL_1" in label or "PHISHING" in label or "BAD" in label
                return {
                    "label": "PHISHING" if is_phish else "SAFE",
                    "confidence": float(score),
                    "is_ml": True
                }
            except Exception as e:
                print(f"[!] ML prediction failed, falling back to heuristics: {e}")

        # 2. Heuristic Fallback Scan
        text_lower = text.lower()
        score = 0
        matched_words = []

        for word in PHISHING_KEYWORDS:
            if word in text_lower:
                score += 1
                matched_words.append(word)

        # Urgent urgency triggers
        urgency_match = re.search(r"\b(urgent|immediate|within \d+ hours|days)\b", text_lower)
        if urgency_match:
            score += 2

        # Link mismatch/link prompt triggers
        if "click here" in text_lower or "link below" in text_lower:
            score += 2

        # Calculate a realistic mock confidence
        if score >= 5:
            label = "PHISHING"
            confidence = min(0.6 + (score * 0.05), 0.99)
        elif score >= 2:
            label = "SUSPICIOUS"
            confidence = 0.5 + (score * 0.05)
        else:
            label = "SAFE"
            confidence = 0.95 - (score * 0.05)

        return {
            "label": label,
            "confidence": float(confidence),
            "is_ml": False,
            "matched_indicators": matched_words
        }

# Singleton instance
classifier = PhishingNLPClassifier()
