# 🛡️ Phishing & Deepfake Threat Detection SOC Platform

An enterprise-grade, asynchronous security operations center (SOC) triage platform designed to detect phishing attempts and deepfake media (audio/video cloning) using multi-vector analysis, heuristic scanners, and machine learning models.

---

## 🚀 Key Features

* **🛡️ Asynchronous Security Triage Queue**: Dynamic, real-time threat feed updating immediately as Celery workers update incident records.
* **🎙️ Deepfake Media Analyzer**: Scans `.wav` and `.mp4` files for voice-cloning artifacts and facial blending border inconsistencies.
* **📧 EML Parsing Engine**: Extracts and audits raw `.eml` headers (SPF, DKIM, DMARC, Display Name Spoofing) and attachment file signatures.
* **📊 Live Threat Analytics**: Dynamic Recharts charts monitoring threat vectors, daily attack volumes, and severity distributions.
* **🔐 Analyst Data Isolation**: Session-level isolation ensuring security analysts can only view and query their own submitted scans.
* **📧 Self-Verification Email Flow**: Verification links sent directly to registering analyst addresses from `align.akshtrana@gmail.com` using local network interface IPs (supporting remote phone verification).
* **🖥️ Dynamic Authenticator**: High-performance HTML5 Canvas diagnostics loader simulating security handshakes, system scans, and laser sweeps.

---

## 🧠 Technologies Used

### Backend
* **Python (FastAPI)**: Asynchronous web backend gateway (port `8000`).
* **Celery + Redis**: Distributed message broker and background execution worker.
* **PostgreSQL (SQLAlchemy)**: Persistent relational database.
* **Transformers (Hugging Face)**:
  * **NLP**: `DistilRoBERTa-base` model fine-tuned on phishing email corpora.
  * **Audio**: `Wav2Vec 2.0` model fine-tuned on synthetic voice-spoofing datasets.

### Frontend
* **React / Next.js**: Asynchronous dashboard client (port `3000`).
* **Tailwind CSS**: Glassmorphic dark UI.
* **Recharts**: Telemetry data charts.
* **HTML5 Canvas**: Diagnostic authenticator loader.

---

## 📂 Project Structure

```
Phishing-Detector-
├── backend/
│   └── app/
│       ├── ml/             # NLP & deepfake media classifiers
│       ├── rules/          # Phishing heuristic scanner rules
│       ├── utils/          # Mail parser & report generator utilities
│       ├── database.py     # SQLAlchemy configuration and schemas
│       ├── main.py         # FastAPI application entrypoint & routers
│       ├── tasks.py        # Celery asynchronous threat scan tasks
│       └── worker.py       # Celery application initialization
├── frontend/
│   ├── src/
│   │   └── app/
│   │       ├── page.tsx    # SOC Dashboard user interface & canvas authenticator
│   │       └── layout.tsx  # Next.js main structure
│   └── package.json
├── .env                    # Environment variables (SMTP & Database configuration)
├── start_platform.sh       # Unified bash starter script
└── README.md
```

---

## ⚙️ Installation & Setup

### Prerequisites
* Python 3.10+
* Node.js 18+
* Docker & Docker Compose
* Redis Server

### 1️⃣ Configure Environment
Create a `.env` file in the project root:
```ini
SMTP_USER=example@gmail.com
SMTP_PASS=your_16_character_app_password
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
PUBLIC_URL=http://localhost:8000
```

### 2️⃣ Run with VS Code Task (Recommended)
1. Open the project root in VS Code.
2. Open the Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`).
3. Select **`Tasks: Run Task`** $\rightarrow$ **`Start Threat Detection Platform`**.
4. Enter your system password when prompted. It will free up host database ports, start the Docker databases, and launch the platform.

### 3️⃣ Run Manually via Shell
Free up host database ports, launch Postgres and Redis Docker containers, and run the startup script:
```bash
cd ~/Phishing-Detector-
./start_platform.sh
```

---

## 📄 API Interface & Local Testing
Once started, the backend is running on `http://localhost:8000` and the frontend dashboard on `http://localhost:3000`.

* **Local Verification Link Bypass**: While real SMTP credentials are not configured, the verification links are logged to your `backend.log` file in the project root. Simply paste the link in your browser tab to activate test accounts instantly!
* **Database Reset / Migration**: Schemas are initialized automatically. The server runs dynamic database migrations on startup to keep tables updated.
