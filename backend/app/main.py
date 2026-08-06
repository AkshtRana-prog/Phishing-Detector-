import os
import uuid
import shutil
from datetime import datetime
from io import BytesIO
from typing import Optional
from fastapi import FastAPI, Depends, UploadFile, File, Form, HTTPException, BackgroundTasks, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from backend.app.database import init_db, get_db, Incident, Evidence, Remediation, User
from backend.app.tasks import analyze_url_task, analyze_eml_task, analyze_deepfake_task, analyze_log_task
from backend.app.utils.pdf_generator import generate_pdf_report

app = FastAPI(title="Phishing & Deepfake Threat Detection Platform API")

# Configure CORS for local development (React/Next.js frontend)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Ensure folders exist
UPLOAD_DIR = "/tmp/threat_detector_uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

def load_env():
    possible_paths = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"),
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"),
        os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), ".env")
    ]
    for path in possible_paths:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        os.environ[k.strip()] = v.strip().strip('"').strip("'")
            break

@app.on_event("startup")
def on_startup():
    load_env()
    init_db()
    
    # Seed default admin accounts
    from backend.app.database import SessionLocal, User
    import hashlib
    db = SessionLocal()
    try:
        admin_pass_hash = hashlib.sha256("admin".encode()).hexdigest()
        
        # 1. admin@orion.com
        admin1 = db.query(User).filter(User.email == "admin@orion.com").first()
        if not admin1:
            admin1 = User(
                email="admin@orion.com",
                password_hash=admin_pass_hash,
                status="APPROVED"
            )
            db.add(admin1)
            
        # 2. admin@admin.com
        admin2 = db.query(User).filter(User.email == "admin@admin.com").first()
        if not admin2:
            admin2 = User(
                email="admin@admin.com",
                password_hash=admin_pass_hash,
                status="APPROVED"
            )
            db.add(admin2)
            
        # 3. admin
        admin3 = db.query(User).filter(User.email == "admin").first()
        if not admin3:
            admin3 = User(
                email="admin",
                password_hash=admin_pass_hash,
                status="APPROVED"
            )
            db.add(admin3)
            
        db.commit()
        print("[+] Default admin test accounts seeded successfully.")
    except Exception as e:
        print(f"[!] Seeding admin accounts failed: {e}")
        db.rollback()
    finally:
        db.close()

@app.get("/")
def read_root():
    return {
        "status": "healthy",
        "service": "Threat Detection Platform API Gateway",
        "timestamp": datetime.utcnow().isoformat()
    }

# Pydantic schema for URL scan requests
from pydantic import BaseModel
class URLScanRequest(BaseModel):
    url: str

@app.post("/analyze/url", status_code=202)
def analyze_url(req: URLScanRequest, x_user_email: Optional[str] = Header(None), db: Session = Depends(get_db)):
    url = req.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")

    incident_id = str(uuid.uuid4())
    
    # Create database entry
    incident = Incident(
        id=incident_id,
        vector_type="URL",
        status="PENDING",
        severity="LOW",
        threat_score=0,
        target_input=url,
        owner_email=x_user_email
    )
    db.add(incident)
    db.commit()

    # Trigger Celery Task
    analyze_url_task.delay(incident_id, url)

    return {"incident_id": incident_id, "status": "PENDING"}

@app.post("/analyze/eml", status_code=202)
def analyze_eml(file: UploadFile = File(...), x_user_email: Optional[str] = Header(None), db: Session = Depends(get_db)):
    if not file.filename.endswith(".eml"):
        raise HTTPException(status_code=400, detail="File must be an EML file (.eml)")

    incident_id = str(uuid.uuid4())
    temp_path = os.path.join(UPLOAD_DIR, f"{incident_id}.eml")

    # Save EML locally for worker
    with open(temp_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # Create DB entry
    incident = Incident(
        id=incident_id,
        vector_type="Email",
        status="PENDING",
        severity="LOW",
        threat_score=0,
        target_input=file.filename,
        owner_email=x_user_email
    )
    db.add(incident)
    db.commit()

    # Trigger Task
    analyze_eml_task.delay(incident_id, temp_path)

    return {"incident_id": incident_id, "status": "PENDING"}

@app.post("/analyze/deepfake", status_code=202)
def analyze_deepfake(
    media_type: str = Form(...), # "audio" or "video"
    file: UploadFile = File(...),
    x_user_email: Optional[str] = Header(None),
    db: Session = Depends(get_db)
):
    if media_type not in ["audio", "video"]:
        raise HTTPException(status_code=400, detail="media_type must be either 'audio' or 'video'")

    incident_id = str(uuid.uuid4())
    ext = file.filename.split(".")[-1]
    temp_path = os.path.join(UPLOAD_DIR, f"{incident_id}.{ext}")

    # Save media locally
    with open(temp_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # Create DB entry
    incident = Incident(
        id=incident_id,
        vector_type="Deepfake",
        status="PENDING",
        severity="LOW",
        threat_score=0,
        target_input=f"{file.filename} ({media_type})",
        owner_email=x_user_email
    )
    db.add(incident)
    db.commit()

    # Trigger Task
    analyze_deepfake_task.delay(incident_id, temp_path, media_type)

    return {"incident_id": incident_id, "status": "PENDING"}

@app.post("/analyze/log", status_code=202)
def analyze_log(file: UploadFile = File(...), x_user_email: Optional[str] = Header(None), db: Session = Depends(get_db)):
    allowed_exts = [".log", ".txt", ".json", ".pcap", ".csv"]
    if not any(file.filename.lower().endswith(ext) for ext in allowed_exts):
        raise HTTPException(status_code=400, detail="File must be a log/text file (.log, .txt, .json, .pcap, .csv)")

    incident_id = str(uuid.uuid4())
    temp_path = os.path.join(UPLOAD_DIR, f"{incident_id}_log.txt")

    # Save log file locally
    with open(temp_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # Create DB entry
    incident = Incident(
        id=incident_id,
        vector_type="Log",
        status="PENDING",
        severity="LOW",
        threat_score=0,
        target_input=file.filename,
        owner_email=x_user_email
    )
    db.add(incident)
    db.commit()

    # Trigger Task
    analyze_log_task.delay(incident_id, temp_path)

    return {"incident_id": incident_id, "status": "PENDING"}

@app.get("/incidents")
def list_incidents(x_user_email: Optional[str] = Header(None), db: Session = Depends(get_db)):
    if x_user_email:
        incidents = db.query(Incident).filter(Incident.owner_email == x_user_email).order_by(Incident.timestamp.desc()).all()
    else:
        incidents = db.query(Incident).filter(Incident.owner_email == "anonymous").order_by(Incident.timestamp.desc()).all()
    return incidents

@app.get("/incidents/{incident_id}")
def get_incident(incident_id: str, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    evidences = db.query(Evidence).filter(Evidence.incident_id == incident_id).all()
    remediations = db.query(Remediation).filter(Remediation.incident_id == incident_id).all()

    return {
        "id": incident.id,
        "timestamp": incident.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "vector_type": incident.vector_type,
        "status": incident.status,
        "severity": incident.severity,
        "threat_score": incident.threat_score,
        "target_input": incident.target_input,
        "evidences": [{"key": ev.key, "value": ev.value} for ev in evidences],
        "remediations": [rem.description for rem in remediations]
    }

@app.delete("/incidents/{incident_id}")
def delete_incident(incident_id: str, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    # Delete associated evidences & remediations first
    db.query(Evidence).filter(Evidence.incident_id == incident_id).delete()
    db.query(Remediation).filter(Remediation.incident_id == incident_id).delete()
    
    db.delete(incident)
    db.commit()
    return {"status": "success", "message": f"Incident {incident_id} deleted successfully"}

class TrainModelRequest(BaseModel):
    label: str

@app.post("/incidents/{incident_id}/train")
def train_model_from_scan(incident_id: str, req: TrainModelRequest, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    if incident.status == "PENDING":
        raise HTTPException(status_code=400, detail="Incident scan is still in progress")
        
    label = req.label.upper()
    if label not in ("PHISHING", "SAFE", "SUSPICIOUS"):
        raise HTTPException(status_code=400, detail="Invalid label. Must be PHISHING, SAFE, or SUSPICIOUS")
        
    from backend.app.ml.self_learning import self_learning_classifier
    
    # Extract content text based on vector type
    content_text = ""
    if incident.vector_type == "URL":
        content_text = incident.target_input
    elif incident.vector_type == "Email":
        evidences = db.query(Evidence).filter(Evidence.incident_id == incident_id).all()
        ev_text = " ".join([ev.value for ev in evidences])
        content_text = f"{incident.target_input} {ev_text}"
    elif incident.vector_type == "Log":
        content_text = incident.target_input
    elif incident.vector_type == "Deepfake":
        content_text = f"media deepfake analysis file: {incident.target_input}"
        
    if not content_text:
        content_text = incident.target_input
        
    # Teach the self-learning model
    self_learning_classifier.learn(content_text, label)
    
    # Update incident record classification
    incident.status = label
    if label == "PHISHING":
        incident.severity = "HIGH"
        incident.threat_score = max(incident.threat_score, 85)
    elif label == "SUSPICIOUS":
        incident.severity = "MEDIUM"
        incident.threat_score = max(incident.threat_score, 50)
    else:
        incident.severity = "LOW"
        incident.threat_score = min(incident.threat_score, 15)
        
    db.commit()
    
    return {
        "status": "success", 
        "message": f"Successfully trained model with sample from incident {incident_id} as {label}",
        "new_status": label
    }

@app.get("/incidents/{incident_id}/report")
def get_incident_report(incident_id: str, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    if incident.status == "PENDING":
        raise HTTPException(status_code=400, detail="Incident scan is still in progress")

    evidences = db.query(Evidence).filter(Evidence.incident_id == incident_id).all()
    remediations = db.query(Remediation).filter(Remediation.incident_id == incident_id).all()

    # Convert sqlalchemy objects to dictionaries for report generator
    inc_data = {
        "id": incident.id,
        "timestamp": incident.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "vector_type": incident.vector_type,
        "status": incident.status,
        "severity": incident.severity,
        "threat_score": incident.threat_score,
        "target_input": incident.target_input
    }
    ev_list = [{"key": ev.key, "value": ev.value} for ev in evidences]
    rem_list = [{"description": rem.description} for rem in remediations]

    buffer = BytesIO()
    generate_pdf_report(inc_data, ev_list, rem_list, buffer)
    buffer.seek(0)

    filename = f"INCIDENT_REPORT_{incident_id[:8]}.pdf"
    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@app.get("/analytics/summary/report")
def get_global_summary_report(x_user_email: Optional[str] = Header(None), db: Session = Depends(get_db)):
    if x_user_email:
        incidents = db.query(Incident).filter(Incident.owner_email == x_user_email).order_by(Incident.timestamp.desc()).all()
    else:
        incidents = db.query(Incident).filter(Incident.owner_email == "anonymous").order_by(Incident.timestamp.desc()).all()

    inc_list = []
    for inc in incidents:
        inc_list.append({
            "id": inc.id,
            "timestamp": inc.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "vector_type": inc.vector_type,
            "status": inc.status,
            "severity": inc.severity,
            "threat_score": inc.threat_score
        })

    buffer = BytesIO()
    from backend.app.utils.pdf_generator import generate_summary_report
    generate_summary_report(inc_list, buffer)
    buffer.seek(0)

    filename = "SOC_SCANS_SUMMARY_REPORT.pdf"
    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@app.get("/analytics")
def get_analytics(x_user_email: Optional[str] = Header(None), db: Session = Depends(get_db)):
    if x_user_email:
        incidents = db.query(Incident).filter(Incident.owner_email == x_user_email).all()
    else:
        incidents = db.query(Incident).filter(Incident.owner_email == "anonymous").all()
    
    total = len(incidents)
    
    # Severity distribution
    sev_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    # Vector distribution
    vec_counts = {"URL": 0, "Email": 0, "Deepfake": 0, "Log": 0}
    
    phishing_count = 0
    deepfake_count = 0
    suspicious_count = 0
    safe_count = 0

    for inc in incidents:
        # Status counts
        if inc.status == "PHISHING":
            phishing_count += 1
        elif inc.status == "DEEPFAKE":
            deepfake_count += 1
        elif inc.status == "SUSPICIOUS":
            suspicious_count += 1
        else:
            safe_count += 1

        # Severity
        sev = inc.severity.upper()
        if sev in sev_counts:
            sev_counts[sev] += 1
        # Vector
        vec = inc.vector_type
        if vec in vec_counts:
            vec_counts[vec] += 1

    # Format data for chart
    return {
        "total_scans": total,
        "status_distribution": {
            "PHISHING": phishing_count,
            "DEEPFAKE": deepfake_count,
            "SUSPICIOUS": suspicious_count,
            "SAFE": safe_count
        },
        "severity_distribution": sev_counts,
        "vector_distribution": vec_counts,
        "time_trends": [
            # Realistic data points for trends charts based on current counts
            {"date": "Day 1", "attacks": 2, "safes": 5},
            {"date": "Day 2", "attacks": 4, "safes": 8},
            {"date": "Day 3", "attacks": phishing_count, "safes": safe_count}
        ]
    }

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import hashlib
from fastapi.responses import HTMLResponse

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

import socket

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = 'localhost'
    finally:
        s.close()
    return IP

def send_verification_email(user_email: str):
    sender_email = "align.akshtrana@gmail.com"
    receiver_email = user_email
    
    local_ip = get_local_ip()
    local_link = f"http://{local_ip}:8000/auth/approve?email={user_email}"
    
    public_url = os.getenv("PUBLIC_URL")
    if public_url:
        public_link = f"{public_url.rstrip('/')}/auth/approve?email={user_email}"
    else:
        public_link = None
    
    subject = "[Threat Detector] Action Required: Verify your security account"
    
    # 1. Plain Text Body Fallback
    if public_link:
        body_text = f"""Dear Security Analyst,

A new user account request has been initiated on the Phishing & Deepfake Threat Detection Platform.

To verify your email address and activate your account, please click one of the secure links below:

Option 1: Verify via local network / Wi-Fi (Use if your device is on the same local Wi-Fi):
{local_link}

Option 2: Verify via internet tunnel:
{public_link}

Best regards,
Threat Detection System Gatekeeper
"""
    else:
        body_text = f"""Dear Security Analyst,

A new user account request has been initiated on the Phishing & Deepfake Threat Detection Platform.

To verify your email address and activate your account, please click the secure link below:
{local_link}

Best regards,
Threat Detection System Gatekeeper
"""

    # Generate Buttons HTML based on whether public link exists
    buttons_html = f"""
            <div class="button-wrapper">
                <a href="{local_link}" class="btn" style="color: #ffffff; background: linear-gradient(135deg, #1f6feb 0%, #10a37f 100%);">VERIFY VIA LOCAL WI-FI (IP)</a>
            </div>
            <p style="font-size: 13px; color: #8b949e; text-align: center; margin-bottom: 5px;">Local link: <a href="{local_link}" style="color: #58a6ff;">{local_link}</a></p>
    """
    
    if public_link:
        buttons_html += f"""
            <div style="text-align: center; margin: 15px 0; color: #8b949e; font-size: 13px; font-weight: bold; text-transform: uppercase; letter-spacing: 1px;">- OR -</div>
            <div class="button-wrapper" style="margin-top: 10px;">
                <a href="{public_link}" class="btn" style="color: #ffffff; background: linear-gradient(135deg, #8b5cf6 0%, #d946ef 100%);">VERIFY VIA PUBLIC TUNNEL</a>
            </div>
            <p style="font-size: 13px; color: #8b949e; text-align: center;">Tunnel link: <a href="{public_link}" style="color: #58a6ff;">{public_link}</a></p>
        """

    # 2. Eye-catching HTML Body
    body_html = f"""<!DOCTYPE html>
<html>
<head>
    <style>
        body {{
            background-color: #0b0f19;
            color: #c9d1d9;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 0;
        }}
        .container {{
            max-width: 600px;
            margin: 40px auto;
            background-color: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 4px 12px rgba(0,0,0,0.5);
        }}
        .header {{
            background: linear-gradient(135deg, #1f6feb 0%, #00f0ff 100%);
            padding: 30px;
            text-align: center;
        }}
        .header h1 {{
            color: #ffffff;
            font-size: 24px;
            margin: 0;
            text-transform: uppercase;
            letter-spacing: 2px;
            text-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }}
        .content {{
            padding: 40px 30px;
            line-height: 1.6;
        }}
        .content p {{
            margin-bottom: 20px;
            font-size: 16px;
            color: #c9d1d9;
        }}
        .button-wrapper {{
            text-align: center;
            margin: 25px 0;
        }}
        .btn {{
            display: inline-block;
            color: #ffffff !important;
            text-decoration: none;
            padding: 14px 28px;
            border-radius: 5px;
            font-weight: bold;
            font-size: 16px;
            letter-spacing: 1px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.2);
        }}
        .footer {{
            background-color: #0d1117;
            padding: 20px 30px;
            text-align: center;
            border-top: 1px solid #21262d;
            font-size: 12px;
            color: #8b949e;
        }}
        .footer a {{
            color: #58a6ff;
            text-decoration: none;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Threat Detector</h1>
        </div>
        <div class="content">
            <p>Dear Security Analyst,</p>
            <p>A new analyst account request has been initiated on the <strong>Phishing & Deepfake Threat Detection SOC Platform</strong>.</p>
            <p>Please click one of the options below to verify your email address and activate your account:</p>
            {buttons_html}
        </div>
        <div class="footer">
            <p>This is an automated security transmission. Please do not reply directly to this email.</p>
            <p>&copy; 2026 Threat Detection SOC. System Admin: Aksht Rana.</p>
        </div>
    </div>
</body>
</html>
"""
    
    msg = MIMEMultipart('alternative')
    msg['From'] = f"Threat Detector Gatekeeper <{sender_email}>"
    msg['To'] = receiver_email
    msg['Subject'] = subject
    
    msg.attach(MIMEText(body_text, 'plain'))
    msg.attach(MIMEText(body_html, 'html'))
    
    try:
        smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
        smtp_port = int(os.getenv("SMTP_PORT", 587))
        smtp_user = os.getenv("SMTP_USER", "align.akshtrana@gmail.com")
        smtp_pass = os.getenv("SMTP_PASS")
        if smtp_pass:
            smtp_pass = smtp_pass.replace(" ", "")
        
        if smtp_pass and smtp_pass != "your_gmail_app_password_here":
            if smtp_port == 465:
                with smtplib.SMTP_SSL(smtp_host, smtp_port) as server:
                    server.login(smtp_user, smtp_pass)
                    server.send_message(msg)
            else:
                with smtplib.SMTP(smtp_host, smtp_port) as server:
                    server.starttls()
                    server.login(smtp_user, smtp_pass)
                    server.send_message(msg)
            print(f"[+] Verification email sent successfully via SMTP to {receiver_email}")
            print(f"    Verification Link: {verification_link}")
        else:
            print("\n" + "="*80)
            print(f"!!! SMTP PASS NOT CONFIGURED. MOCKING EMAIL DISPATCH TO USER !!!")
            print(f"From: {smtp_user}")
            print(f"To: {receiver_email}")
            print(f"Subject: {subject}")
            print(f"Link: {verification_link}")
            print("="*80 + "\n")
    except Exception as err:
        print(f"[!] SMTP Transmission failed: {err}")
        print("\n" + "="*80)
        print(f"!!! FALLBACK MOCK EMAIL DISPATCH TO USER !!!")
        print(f"From: {sender_email}")
        print(f"To: {receiver_email}")
        print(f"Subject: {subject}")
        print(f"Link: {verification_link}")
        print("="*80 + "\n")

class AuthRequest(BaseModel):
    email: str
    password: str

@app.post("/auth/signup")
def signup(req: AuthRequest, db: Session = Depends(get_db)):
    email = req.email.strip().lower()
    password = req.password.strip()
    if not email or not password:
        raise HTTPException(status_code=400, detail="Email and password are required")
        
    existing = db.query(User).filter(User.email == email).first()
    if existing:
        raise HTTPException(status_code=400, detail="User already registered")
        
    user = User(
        email=email,
        password_hash=hash_password(password),
        status="PENDING"
    )
    db.add(user)
    db.commit()
    
    send_verification_email(email)
    
    return {"message": "Signup successful. Verification email dispatched."}

@app.post("/auth/login")
def login(req: AuthRequest, db: Session = Depends(get_db)):
    email = req.email.strip().lower()
    password = req.password.strip()
    
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
        
    if user.password_hash != hash_password(password):
        raise HTTPException(status_code=401, detail="Invalid email or password")
        
    if user.status != "APPROVED":
        raise HTTPException(status_code=403, detail=f"Account pending verification. Please check the verification link sent to {email}")
        
    return {"status": "SUCCESS", "email": email}

@app.get("/auth/approve", response_class=HTMLResponse)
def approve_user(email: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if not user:
        return HTMLResponse("<h3>User not found</h3>", status_code=404)
        
    user.status = "APPROVED"
    db.commit()
    
    return HTMLResponse(f"""
    <html>
        <head>
            <title>User Approved</title>
            <style>
                body {{
                    background-color: #020617;
                    color: #cbd5e1;
                    font-family: sans-serif;
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    justify-content: center;
                    height: 100vh;
                    margin: 0;
                }}
                .card {{
                    background-color: #0f172a;
                    border: 1px solid #1e293b;
                    padding: 2.5rem;
                    border-radius: 1rem;
                    text-align: center;
                    box-shadow: 0 4px 20px rgba(0,0,0,0.5);
                }}
                h1 {{ color: #10b981; margin-bottom: 1rem; }}
                p {{ color: #94a3b8; font-size: 0.95rem; }}
            </style>
        </head>
        <body>
            <div class="card">
                <h1>✓ Access Granted</h1>
                <p>User account for <strong>{email}</strong> has been successfully approved.</p>
                <p>They can now log in to the dashboard.</p>
            </div>
        </body>
    </html>
    """)
