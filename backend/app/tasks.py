import os
from datetime import datetime
from backend.app.worker import celery_app
from backend.app.database import SessionLocal, Incident, Evidence, Remediation
from backend.app.rules import extract_features, check_phishing
from backend.app.utils.eml_parser import parse_eml
from backend.app.ml.phishing_nlp import classifier as nlp_classifier
from backend.app.ml.deepfake_media import classifier as df_classifier

def get_db():
    db = SessionLocal()
    try:
        return db
    except Exception as e:
        print(f"Database session error: {e}")
        return None

@celery_app.task(name="backend.app.tasks.analyze_url_task")
def analyze_url_task(incident_id, url):
    db = get_db()
    if not db: return

    try:
        incident = db.query(Incident).filter(Incident.id == incident_id).first()
        if not incident: return

        # Extract features and scan URL
        features = extract_features(url)
        status, reasons, severity, score = check_phishing(features)

        # Scale threat score to out of 100
        # Check phishing max raw score is around 15-20. We will cap/scale it.
        scaled_score = min(int((score / 12) * 100), 100)

        incident.status = status
        incident.severity = severity
        incident.threat_score = score

        # Save evidences
        for reason in reasons:
            db.add(Evidence(
                incident_id=incident_id,
                key="URL Threat Indicator",
                value=reason
            ))

        # Add generic HTTPS status evidence if not checked
        db.add(Evidence(
            incident_id=incident_id,
            key="Connection Security",
            value="Secure HTTPS Connection" if features.get("has_https") else "Insecure HTTP Connection (No SSL)"
        ))

        # Remediation
        if severity == "LOW":
            db.add(Remediation(incident_id=incident_id, description="Always verify domain spelling before interacting."))
            db.add(Remediation(incident_id=incident_id, description="Ensure HTTPS is enabled on the browser address bar."))
        else:
            db.add(Remediation(incident_id=incident_id, description="Avoid entering credentials, OTPs, or financial information on this website."))
            db.add(Remediation(incident_id=incident_id, description="Submit this domain to public threat blacklists (e.g. Google Safe Browsing)."))
            db.add(Remediation(incident_id=incident_id, description="If you entered passwords, change them immediately on the authentic service."))

        db.commit()
    except Exception as e:
        print(f"Error in analyze_url_task: {e}")
        db.rollback()
    finally:
        db.close()

@celery_app.task(name="backend.app.tasks.analyze_eml_task")
def analyze_eml_task(incident_id, file_path):
    db = get_db()
    if not db: return

    try:
        incident = db.query(Incident).filter(Incident.id == incident_id).first()
        if not incident: return

        # Parse EML file
        email_data = parse_eml(file_path)

        # Base scoring
        score = 0
        evidences = []

        # 1. Header validations
        evidences.append(("SPF Verification", f"Result: {email_data['spf']}"))
        evidences.append(("DKIM Verification", f"Result: {email_data['dkim']}"))
        evidences.append(("DMARC Verification", f"Result: {email_data['dmarc']}"))

        if email_data["spf"] == "FAIL": score += 3
        if email_data["dkim"] == "FAIL": score += 3
        if email_data["dmarc"] == "FAIL": score += 3

        # Display name spoofing
        if email_data["display_name_spoofed"]:
            score += 4
            evidences.append(("Spoofing Detected", email_data["display_name_spoof_details"]))

        # 2. NLP Body Analysis
        nlp_res = nlp_classifier.predict(email_data["body_text"])
        evidences.append(("NLP Text Analysis", f"Classification: {nlp_res['label']} (Confidence: {nlp_res['confidence']:.2f})"))
        if nlp_res["label"] == "PHISHING":
            score += 4
        elif nlp_res["label"] == "SUSPICIOUS":
            score += 2

        # 3. Embedded URLs
        suspicious_urls = 0
        for url in email_data["urls"][:5]:  # Scan first 5 URLs to keep it quick
            url_features = extract_features(url)
            u_status, u_reasons, u_severity, u_score = check_phishing(url_features)
            if u_status != "LEGITIMATE":
                suspicious_urls += 1
                evidences.append(("Suspicious Embedded Link", f"URL '{url}' flagged: {', '.join(u_reasons)}"))
                score += 3

        # 4. Attachments
        for att in email_data["attachments"]:
            desc = f"File: {att['filename']} ({att['size']} bytes, Type: {att['content_type']})"
            if att["has_macros"]:
                score += 5
                evidences.append(("Dangerous Attachment", f"{desc} contains macro/executable scripts"))
            else:
                evidences.append(("Email Attachment", desc))

        # Classify overall EML threat
        scaled_score = min(int((score / 15) * 100), 100)

        if scaled_score >= 80:
            status = "PHISHING"
            severity = "CRITICAL"
        elif scaled_score >= 50:
            status = "PHISHING"
            severity = "HIGH"
        elif scaled_score >= 25:
            status = "SUSPICIOUS"
            severity = "MEDIUM"
        else:
            status = "SAFE"
            severity = "LOW"

        incident.status = status
        incident.severity = severity
        incident.threat_score = score

        # Save all evidence
        for key, val in evidences:
            db.add(Evidence(incident_id=incident_id, key=key, value=val))

        # Remediation
        if severity in ["HIGH", "CRITICAL"]:
            db.add(Remediation(incident_id=incident_id, description="Do NOT click any links or download attachments in this email."))
            db.add(Remediation(incident_id=incident_id, description="Quarantine or delete the email from the mailbox immediately."))
            db.add(Remediation(incident_id=incident_id, description="Revoke active sessions and enforce password reset if credentials were input."))
            db.add(Remediation(incident_id=incident_id, description="Report this sender to your IT security Operations Center."))
        elif severity == "MEDIUM":
            db.add(Remediation(incident_id=incident_id, description="Treat the sender with caution; verify sender address manually."))
            db.add(Remediation(incident_id=incident_id, description="Verify embedded links using a URL sandboxing scanner before opening."))
        else:
            db.add(Remediation(incident_id=incident_id, description="No critical threats identified; safe to read."))

        db.commit()
    except Exception as e:
        print(f"Error in analyze_eml_task: {e}")
        db.rollback()
    finally:
        db.close()
        # Clean up uploaded file
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except:
                pass

@celery_app.task(name="backend.app.tasks.analyze_deepfake_task")
def analyze_deepfake_task(incident_id, file_path, media_type):
    db = get_db()
    if not db: return

    try:
        incident = db.query(Incident).filter(Incident.id == incident_id).first()
        if not incident: return

        if media_type == "audio":
            res = df_classifier.analyze_audio(file_path)
        else:
            res = df_classifier.analyze_video(file_path)

        score = int(res["confidence"] * 100)
        label = res["label"]

        if label == "DEEPFAKE":
            status = "PHISHING"
            severity = "CRITICAL" if score >= 90 else "HIGH"
            threat_score = score
        elif label == "SUSPICIOUS":
            status = "SUSPICIOUS"
            severity = "MEDIUM"
            threat_score = score
        else:
            status = "SAFE"
            severity = "LOW"
            threat_score = 100 - score

        incident.status = status
        incident.severity = severity
        incident.threat_score = threat_score

        # Save Evidence
        db.add(Evidence(
            incident_id=incident_id,
            key="Deepfake Detection Method",
            value=res["method"]
        ))
        db.add(Evidence(
            incident_id=incident_id,
            key="Model Prediction",
            value=f"Label: {label} (Confidence: {res['confidence']:.2f}, ML: {res['is_ml']})"
        ))
        db.add(Evidence(
            incident_id=incident_id,
            key="File Integrity",
            value=f"File Name: {os.path.basename(file_path)}, Size: {os.path.getsize(file_path)} bytes"
        ))

        # Remediation
        if label == "DEEPFAKE":
            db.add(Remediation(incident_id=incident_id, description="Do NOT trust or disseminate this media file."))
            db.add(Remediation(incident_id=incident_id, description="Flag content as synthetic/manipulated on publication channels."))
            db.add(Remediation(incident_id=incident_id, description="Initiate incident response for potential executive spoofing or public relations threat."))
        elif label == "SUSPICIOUS":
            db.add(Remediation(incident_id=incident_id, description="Verify content through secondary authenticated channels."))
            db.add(Remediation(incident_id=incident_id, description="Inspect metadata signatures and watermark indicators manually."))
        else:
            db.add(Remediation(incident_id=incident_id, description="Media appears to be authentic with standard compression thresholds."))

        db.commit()
    except Exception as e:
        print(f"Error in analyze_deepfake_task: {e}")
        db.rollback()
    finally:
        db.close()
        # Clean up uploaded file
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except:
                pass

import re

@celery_app.task(name="backend.app.tasks.analyze_log_task")
def analyze_log_task(incident_id, file_path):
    db = get_db()
    if not db: return

    try:
        incident = db.query(Incident).filter(Incident.id == incident_id).first()
        if not incident: return

        # Read the file
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        score = 0
        evidences = []
        
        # 1. Attack Signature Detections
        signatures = {
            "SQL Injection (SQLi)": [r"(?i)UNION\s+SELECT", r"(?i)OR\s+1\s*=\s*1", r"(?i)UNION\s+ALL\s+SELECT"],
            "Directory Traversal": [r"\.\./", r"\.\.\\", r"(?i)%2f%2f"],
            "Command Injection": [r"(?i);\s*wget", r"(?i);\s*curl", r"(?i);\s*rm\s+-rf", r"(?i)cmd\.exe", r"(?i)/bin/sh"],
            "Cross-Site Scripting (XSS)": [r"(?i)<script>", r"(?i)javascript:", r"(?i)onerror\s*="]
        }

        flagged_signatures = {}
        for attack_type, patterns in signatures.items():
            for pattern in patterns:
                matches = re.findall(pattern, content)
                if matches:
                    flagged_signatures[attack_type] = flagged_signatures.get(attack_type, 0) + len(matches)

        for attack_type, count in flagged_signatures.items():
            score += min(count * 3, 10)
            evidences.append(("Attack Signature Detected", f"Found {count} instance(s) matching {attack_type} pattern."))

        # 2. Extract and Scan IPs
        ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
        ips = list(set(re.findall(ip_pattern, content)))
        if ips:
            # Check for suspicious external IPs (excluding private ones like 127.0.0.1, 10.*, 192.168.*)
            suspicious_ips = []
            for ip in ips:
                if not (ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16.") or ip.startswith("172.17.") or ip.startswith("172.18.") or ip.startswith("172.19.") or ip.startswith("172.2") or ip.startswith("172.3")):
                    suspicious_ips.append(ip)
            
            if suspicious_ips:
                evidences.append(("Network Indicators (IPs)", f"Extracted {len(suspicious_ips)} external IP(s): {', '.join(suspicious_ips[:5])}"))
                score += min(len(suspicious_ips), 5)

        # 3. Extract and Scan URLs
        url_pattern = r"https?://[^\s/$.?#].[^\s]*"
        urls = list(set(re.findall(url_pattern, content)))
        suspicious_urls = 0
        for url in urls[:5]:
            url_features = extract_features(url)
            u_status, u_reasons, u_severity, u_score = check_phishing(url_features)
            if u_status != "LEGITIMATE":
                suspicious_urls += 1
                evidences.append(("Suspicious URL in Log", f"URL '{url}' flagged: {', '.join(u_reasons)}"))
                score += 4

        # Compute overall metrics
        scaled_score = min(int((score / 15) * 100), 100)

        if scaled_score >= 70:
            status = "PHISHING"
            severity = "CRITICAL" if scaled_score >= 90 else "HIGH"
        elif scaled_score >= 35:
            status = "SUSPICIOUS"
            severity = "MEDIUM"
        else:
            status = "SAFE"
            severity = "LOW"

        incident.status = status
        incident.severity = severity
        incident.threat_score = min(score, 12)

        # Save all evidence
        for key, val in evidences:
            db.add(Evidence(incident_id=incident_id, key=key, value=val))

        # Add general stats evidence
        db.add(Evidence(
            incident_id=incident_id,
            key="Log Telemetry Stats",
            value=f"Log File: {os.path.basename(file_path)}, Total Size: {os.path.getsize(file_path)} bytes, Unique IPs: {len(ips)}, Unique URLs: {len(urls)}"
        ))

        # Remediations
        if status == "PHISHING":
            db.add(Remediation(incident_id=incident_id, description="Isolate compromised endpoints or source IPs from internal networks."))
            db.add(Remediation(incident_id=incident_id, description="Update firewall rule sets to drop inbound packets from the flagged external IPs."))
            db.add(Remediation(incident_id=incident_id, description="Audit server access logs to check for successful traversal or database breach indicators."))
        elif status == "SUSPICIOUS":
            db.add(Remediation(incident_id=incident_id, description="Monitor traffic from identified external IP addresses for unauthorized access attempts."))
            db.add(Remediation(incident_id=incident_id, description="Sanitize web forms or user inputs to defend against path traversal and SQL injection."))
        else:
            db.add(Remediation(incident_id=incident_id, description="Log file indicates normal system behavior. Continue standard log retention audits."))

        db.commit()
    except Exception as e:
        print(f"Error in analyze_log_task: {e}")
        db.rollback()
    finally:
        db.close()
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except:
                pass
