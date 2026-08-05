import os
import json
import re

MODEL_FILE = os.path.join(os.path.dirname(__file__), "self_learning_model.json")

class SelfLearningClassifier:
    def __init__(self):
        self.classes = ["PHISHING", "SAFE"]
        self.class_counts = {"PHISHING": 0, "SAFE": 0}
        self.token_counts = {}
        self.vocab = set()
        self.load_model()

    def load_model(self):
        if os.path.exists(MODEL_FILE):
            try:
                with open(MODEL_FILE, "r") as f:
                    data = json.load(f)
                    self.class_counts = data.get("class_counts", {"PHISHING": 0, "SAFE": 0})
                    self.token_counts = data.get("token_counts", {})
                    self.vocab = set(self.token_counts.keys())
            except Exception as e:
                print(f"[SelfLearning] Failed to load model: {e}")
                self.initialize_defaults()
        else:
            self.initialize_defaults()

    def save_model(self):
        try:
            with open(MODEL_FILE, "w") as f:
                json.dump({
                    "class_counts": self.class_counts,
                    "token_counts": self.token_counts
                }, f, indent=2)
        except Exception as e:
            print(f"[SelfLearning] Failed to save model: {e}")

    def initialize_defaults(self):
        self.class_counts = {"PHISHING": 0, "SAFE": 0}
        self.token_counts = {}
        self.vocab = set()

        # Seed initial training datasets for auto-bootstrapping
        phish_samples = [
            "paypal-security-update.com", "login-microsoft-auth.net", "amazox.com",
            "verify-google-identity.org", "goog1e.com", "faceb00k-login.com",
            "urgent account suspended verification required immediate action",
            "you won a gift card login to claim billing info required link",
            "brute force sql injection privilege escalation root exploit malware run"
        ]
        safe_samples = [
            "paypal.com", "microsoft.com", "amazon.com", "google.com", "facebook.com",
            "weekly project status report update from manager meeting tomorrow",
            "invoice for recent purchase confirmed delivery updates",
            "normal system startup logging nominal database connections active"
        ]
        
        for text in phish_samples:
            self.learn(text, "PHISHING", save=False)
        for text in safe_samples:
            self.learn(text, "SAFE", save=False)
        
        self.save_model()

    def tokenize(self, text):
        if not text:
            return []
        text = text.lower()
        # Extract words/tokens
        tokens = re.findall(r"\b[a-z0-9-]{2,25}\b", text)
        
        # Extract features/patterns as tokens
        if "trycloudflare" in text:
            tokens.append("cloudflare-tunnel")
        if "@" in text:
            tokens.append("has-at-symbol")
        if "http:" in text and "https:" not in text:
            tokens.append("insecure-ssl")
        return tokens

    def learn(self, text, label, save=True):
        if label not in ("PHISHING", "SUSPICIOUS", "SAFE"):
            return
        
        # Map SUSPICIOUS to PHISHING for binary classification counts
        mapped_label = "PHISHING" if label in ("PHISHING", "SUSPICIOUS") else "SAFE"
        
        tokens = self.tokenize(text)
        if not tokens:
            return
        
        self.class_counts[mapped_label] += 1
        for token in tokens:
            if token not in self.token_counts:
                self.token_counts[token] = {"PHISHING": 0, "SAFE": 0}
            self.token_counts[token][mapped_label] += 1
            self.vocab.add(token)
            
        if save:
            self.save_model()

    def predict(self, text):
        tokens = self.tokenize(text)
        if not tokens:
            return "SAFE", 0.5

        total_docs = sum(self.class_counts.values())
        if total_docs == 0:
            return "SAFE", 0.5

        # Prior probabilities
        prob_phish = self.class_counts["PHISHING"] / total_docs
        prob_safe = self.class_counts["SAFE"] / total_docs

        # Count total tokens in each class
        total_tokens_phish = sum(tc["PHISHING"] for tc in self.token_counts.values())
        total_tokens_safe = sum(tc["SAFE"] for tc in self.token_counts.values())

        vocab_size = len(self.vocab)

        # Naive Bayes probabilities with Laplace smoothing
        for token in tokens:
            if token in self.token_counts:
                count_phish = self.token_counts[token]["PHISHING"]
                count_safe = self.token_counts[token]["SAFE"]
            else:
                count_phish = 0
                count_safe = 0

            prob_phish *= (count_phish + 1) / (total_tokens_phish + vocab_size)
            prob_safe *= (count_safe + 1) / (total_tokens_safe + vocab_size)

        total_prob = prob_phish + prob_safe
        if total_prob == 0:
            return "SAFE", 0.5

        confidence_phish = prob_phish / total_prob
        
        if confidence_phish >= 0.5:
            return "PHISHING", confidence_phish
        else:
            return "SAFE", 1.0 - confidence_phish

# Singleton instance
self_learning_classifier = SelfLearningClassifier()
