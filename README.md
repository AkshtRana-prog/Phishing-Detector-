# 🛡️ Phishing Detection System

A modular, rule-based phishing detection engine built in Python that simulates how a SOC (Security Operations Center) detects phishing URLs using weighted scoring and alert generation.

---

## 📌 Overview

Phishing attacks are one of the most common cybersecurity threats.  
This project demonstrates how detection systems:

- Extract URL-based features
- Detect brand impersonation (typosquatting)
- Apply weighted rule-based scoring
- Classify severity levels
- Generate alerts
- Log detection activity

This project is designed for cybersecurity learners, SOC aspirants, and Blue Team enthusiasts.

---

## 🎯 Key Features

- 🔍 Suspicious keyword detection (login, verify, update, secure, etc.)
- 🏷️ Brand impersonation detection
- ⚖️ Weighted rule-based scoring system
- 🚨 Severity classification (LOW / MEDIUM / HIGH)
- 🎨 Colored terminal alerts
- 📝 Structured logging system
- 📂 Modular and scalable architecture

---

## ⚙️ How It Works

1. A URL is provided inside `main.py`.
2. Features are extracted from the URL.
3. Detection rules are applied.
4. A weighted score is calculated.
5. Severity level is determined.
6. An alert is generated.
7. The result is logged inside `/logs`.

---

## 📂 Project Structure

```
phishing-detector/
│
├── alerts/                # Alert generation system
│   ├── __init__.py
│   └── alert_manager.py
│
├── features/              # Feature extraction logic
│   ├── __init__.py
│   └── feature_extraction.py
│
├── rules/                 # Rule engine & scoring logic
│   ├── __init__.py
│   └── rule_engine.py
│
├── data/                  # Known brand lists
│   └── known_brands.txt
│
├── logs/                  # Detection logs
│   └── phishing.log
│
├── models/                # Future ML integration
│   └── ml_model.py
│
├── main.py                # Entry point
├── requirements.txt
├── README.md
└── .gitignore
```

---

# 🚀 Installation

## 1️⃣ Clone the Repository

```bash
git clone https://github.com/yourusername/phishing-detector.git
cd phishing-detector
```

---

## 2️⃣ Create Virtual Environment (Recommended)

```bash
python3 -m venv .venv
```

Activate it:

### Linux / Mac:
```bash
source .venv/bin/activate
```

### Windows:
```bash
.venv\Scripts\activate
```

---

## 3️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

If using colored output:
```bash
pip install colorama
```

---

# ▶️ How To Run

From the project root (where `main.py` exists):

```bash
python3 main.py
```

---

# 🧑‍💻 How To Use

## Step 1: Open `main.py`

Find the URL variable:

```python
url = "http://example.com"
```

Replace it with the URL you want to scan.

### Example – Suspicious URL:

```python
url = "http://paypa1-login-secure.com"
```

### Example – Legitimate URL:

```python
url = "https://google.com"
```

---

## Step 2: Run the Program

```bash
python3 main.py
```

---

# 📊 Output Explanation

The system calculates a score based on detected phishing indicators.

| Score | Severity |
|-------|----------|
| 0 – 2 | LOW      |
| 3 – 5 | MEDIUM   |
| 6+    | HIGH     |

---

## 🟢 LOW
Minimal suspicious activity detected.

Example:
```
[✓] LOW RISK
No major phishing indicators found.
```

---

## 🟡 MEDIUM
Some suspicious patterns detected.

Example:
```
[!] MEDIUM RISK DETECTED
Suspicious keyword: login
Unusual domain structure
```

---

## 🔴 HIGH
Strong phishing indicators detected.

Example:
```
[!] HIGH SEVERITY PHISHING DETECTED
Brand impersonation detected
Typosquatting identified
Multiple suspicious keywords
```

---

# 📝 Logs

All scan results are stored in:

```
logs/phishing.log
```

This simulates SOC-style logging for monitoring suspicious events.

---

# 🛠️ Customization

You can improve or modify detection logic:

- Edit `rules/rule_engine.py` → Change scoring weights
- Edit `features/feature_extraction.py` → Add new detection features
- Update `data/known_brands.txt` → Add more brands

---

# 🧠 Skills Demonstrated

- Cybersecurity fundamentals
- Phishing detection techniques
- Rule-based detection systems
- Feature engineering
- Modular Python architecture
- Logging systems
- CLI tool development

---

# 🔮 Future Improvements

- Levenshtein distance similarity scoring
- Machine Learning classifier
- Real-time URL scanning
- REST API integration
- Web dashboard (Flask)
- CSV/JSON export
- Email phishing detection module

---

# 🏷️ Tags

Cybersecurity • Phishing Detection • SOC Tool • Python Security • Blue Team • Threat Detection • Rule Engine • CLI Tool

---

## 👨‍💻 Author

**Aksht Rana**  
Cybersecurity Enthusiast
