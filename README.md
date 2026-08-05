# 🛡️ Phishing & Deepfake Threat Detection SOC Platform

An enterprise-grade, asynchronous Security Operations Center (SOC) triage dashboard designed to detect multi-vector phishing attempts and deepfake media (audio/video cloning) using heuristic scanners, edit-distance typosquatting checks, and adaptive machine learning models.

---

## 🚀 Key Features

* **🛡️ Asynchronous Operational Triage Queue**: Real-time threat feed updating dynamically via Celery worker background tasks as audits complete.
* **🧠 Continuous Self-Learning ML Core**: Custom-built Naive Bayes classifier that dynamically learns from every scanned result and manual user override, storing updated weights in a local JSON model file.
* **🌐 Levenshtein Edit-Distance Typosquatting Checker**: Scans URL domains and subdomains against top global brands to immediately identify spoofed names (e.g. `amazox.com` targeting `amazon`).
* **🎙️ Deepfake Media Analyzer**: Audits `.wav` and `.mp4` files to detect voice-cloning pitch anomalies and synthetic frame transitions.
* **📧 EML Parsing Engine**: Automatically parses raw `.eml` files, checking SPF/DKIM/DMARC server validation, display name spoofing, and file attachments.
* **📊 Tactical Analytics Panel**: Renders dynamic Recharts metrics to track scan distributions, threat severity trends, and vector volumes.
* **🗑️ Feeds Management & Manual override**: Analysts can delete scans from the queue to clean feeds, and use the **Train ML** dropdown to manually override and train the classifier on specific content.
* **📬 Dual-Verification email dispatch**: Verifies registers via both public tunnel redirects and local network interface IPs (allowing direct verification from phones/other devices on the same Wi-Fi).
* **🔑 Pre-seeded Analyst Accounts**: Seeds standard analyst test accounts at startup (`admin@orion.com`, `admin@admin.com`, `admin` - passwords: `admin`).
* **🖥️ HUD scrolling IDS stream**: Renders a live scrolling network intrusion detection log terminal simulating SSH probes, Redis traffic, and firewall anomalies on the dashboard.

---

## 🧠 Machine Learning Models Used

The platform utilizes a dual ML analysis architecture consisting of deep learning transformers and a local self-learning classifier:

### 1. Self-Learning Classifier (`SelfLearningClassifier`)
* **Status**: **FULLY FUNCTIONAL & OPERATIONAL**
* **Location**: [self_learning.py](file:///home/aksht/Phishing-Detector-/backend/app/ml/self_learning.py)
* **Architecture**: A custom Multinomial Naive Bayes classifier built in pure Python. It extracts tokenized words, symbols (like `@`, `http://`), and infrastructure patterns (like `trycloudflare`).
* **How it trains/learns**:
  * **Auto-bootstrap**: Seeds itself with baseline phishing and safe URL/Email/Log samples on startup.
  * **Dynamic Feedback Loop**: With every scan, it predicts threat probability. When the scan status is finalized, it immediately runs `learn(sample, status)` and persists its state to [self_learning_model.json](file:///home/aksht/Phishing-Detector-/backend/app/ml/self_learning_model.json).
  * **User Overrides**: When an analyst manually changes a classification via the **Train ML** UI dropdown, the model immediately retrains on the scan's content with the corrected label.

### 2. Fine-Tuned NLP Phishing Transformer (`DistilRoBERTa-base-phishing`)
* **Status**: **FULLY FUNCTIONAL (with Heuristic Fallback)**
* **Location**: [phishing_nlp.py](file:///home/aksht/Phishing-Detector-/backend/app/ml/phishing_nlp.py)
* **Architecture**: Fine-tuned `mrm8488/distilroberta-finetuned-phishing` model from Hugging Face.
* **Behavior**: Evaluates raw body text and subject lines. If the local system has the `transformers` library installed, it loads the model on CPU to run deep learning classification. If libraries are missing, it safely falls back to a high-fidelity keyword and urgency heuristics engine.

### 3. Voice Spoofing & Deepfake Media Scanner (`DeepfakeMediaClassifier`)
* **Status**: **FULLY FUNCTIONAL (with Heuristic Fallback)**
* **Location**: [deepfake_media.py](file:///home/aksht/Phishing-Detector-/backend/app/ml/deepfake_media.py)
* **Architecture**: Fine-tuned `Wav2Vec 2.0` model.
* **Behavior**: Scans media payloads. If deep learning libraries are not on path, it falls back to a structural metadata audio pitch fluctuation and frame transition analyzer.

---

## 📂 Project Structure

```
Phishing-Detector-
├── backend/
│   └── app/
│       ├── ml/
│       │   ├── self_learning.py       # Adaptive online Naive Bayes classifier
│       │   ├── self_learning_model.json # Persisted ML model weights
│       │   ├── phishing_nlp.py        # Hugging Face NLP phishing model
│       │   └── deepfake_media.py      # Audio Wav2Vec 2.0 deepfake model
│       ├── rules.py                   # Heuristic checks & edit-distance typosquatting
│       ├── utils/
│       │   ├── eml_parser.py          # EML parser (SPF/DKIM/DMARC extraction)
│       │   └── pdf_generator.py       # PDF triage report generator
│       ├── database.py                # PostgreSQL schemas and models
│       ├── main.py                    # FastAPI routes (incidents, train, delete)
│       └── tasks.py                   # Celery worker threat analysis tasks
├── frontend/
│   ├── src/
│   │   └── app/
│   │       ├── page.tsx               # Command Center Dashboard & Canvas UI
│   │       └── layout.tsx             # Smooth-scroll container config
│   └── package.json
└── README.md
```

---

## ⚙️ Installation & Setup

### 1️⃣ Configure Environment
Create a `.env` file in the project root:
```ini
SMTP_USER=align.akshtrana@gmail.com
SMTP_PASS=elpk zczf odld yvmo
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
PUBLIC_URL=http://localhost:8000
```

### 2️⃣ Start with Unified VS Code Task (Recommended)
1. Open the project root in VS Code.
2. Open the Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`).
3. Select **`Tasks: Run Task`** $\rightarrow$ **`Start Threat Platform`**.
4. It will free up host database ports, start Docker databases, and run the backend, worker, and frontend dev servers.

### 3️⃣ Start Manually via Shell
Ensure PostgreSQL is running on port `5433` and Redis on port `6380`.
Then start the processes:
```bash
# Terminal 1: FastAPI Gateway
DATABASE_URL=postgresql://postgres:postgrespassword@localhost:5433/threat_detector REDIS_URL=redis://localhost:6380/0 ./venv/bin/uvicorn backend.app.main:app --host 0.0.0.0 --port 8000

# Terminal 2: Celery Worker
DATABASE_URL=postgresql://postgres:postgrespassword@localhost:5433/threat_detector REDIS_URL=redis://localhost:6380/0 ./venv/bin/celery -A backend.app.worker.celery_app worker --loglevel=info

# Terminal 3: Next.js Frontend
cd frontend
npm run dev
```

---

## 📄 API Interface & Local Testing

Once started, the backend is running on `http://localhost:8000` and the frontend dashboard on `http://localhost:3000`.

* **Admin Test Accounts**: Login immediately using `admin@orion.com` / `admin` (Password: `admin`).
* **Active Learning Loop**: Submit a scan (e.g. url `hxxps://amazox.com` or custom text), navigate to the triage list, and select `Train ML` options. You can immediately see the learning weights update in your terminal logs.
