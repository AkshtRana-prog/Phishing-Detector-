import os
import struct
from datetime import datetime
from backend.app.worker import celery_app
from backend.app.database import SessionLocal, Incident, Evidence, Remediation
from backend.app.rules import extract_features, check_phishing
from backend.app.utils.eml_parser import parse_eml
from backend.app.ml.phishing_nlp import classifier as nlp_classifier
from backend.app.ml.deepfake_media import classifier as df_classifier
from backend.app.ml.self_learning import self_learning_classifier

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

        # Run self-learning model prediction
        ml_label, ml_confidence = self_learning_classifier.predict(url)
        if ml_label == "PHISHING" and ml_confidence > 0.85:
            if status != "PHISHING":
                status = "PHISHING"
                severity = "HIGH"
                score = max(score, 8)
                reasons.append(f"Self-Learning ML Core flagged URL (Confidence: {ml_confidence:.2f})")

        # Scale threat score to out of 100
        scaled_score = min(int((score / 12) * 100), 100)

        incident.status = status
        incident.severity = severity
        incident.threat_score = scaled_score

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

        # Autonomously learn from the response classification
        self_learning_classifier.learn(url, status)
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

        # 1. Header validations & email details
        evidences.append(("Email Sender", email_data["from"]))
        evidences.append(("Email Recipient", email_data["to"]))
        if email_data["cc"]:
            evidences.append(("Email CC", email_data["cc"]))
        evidences.append(("Email Date", email_data["date"]))
        if email_data["reply_to"]:
            evidences.append(("Email Reply-To", email_data["reply_to"]))
        if email_data["message_id"]:
            evidences.append(("Email Message-ID", email_data["message_id"]))
        evidences.append(("Email Subject", email_data["subject"]))
        
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

        # Run self-learning model prediction on combined subject and body
        combined_text = (email_data["subject"] or "") + " " + (email_data["body_text"] or "")
        ml_label, ml_confidence = self_learning_classifier.predict(combined_text)
        if ml_label == "PHISHING" and ml_confidence > 0.85:
            if scaled_score < 50:
                scaled_score = max(scaled_score, 55)
                evidences.append(("Self-Learning ML Core flag", f"Flagged suspicious content signatures (Confidence: {ml_confidence:.2f})"))

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
        incident.threat_score = scaled_score

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

        # Autonomously learn from EML scan response
        self_learning_classifier.learn(combined_text, status)
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
        elif media_type in ["photo", "image"]:
            res = df_classifier.analyze_photo(file_path)
        else:
            res = df_classifier.analyze_video(file_path)

        score = int(res["confidence"] * 100)
        label = res["label"]

        if label == "DEEPFAKE":
            status = "DEEPFAKE"
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
            key="AI Generation Status",
            value="CONFIRMED AI GENERATED" if res.get("ai_generated") else "ORGANIC / AUTHENTIC MEDIA"
        ))
        if res.get("detected_generator"):
            db.add(Evidence(
                incident_id=incident_id,
                key="Detected AI Generator",
                value=res["detected_generator"]
            ))
        db.add(Evidence(
            incident_id=incident_id,
            key="Deepfake Detection Method",
            value=res["method"]
        ))
        db.add(Evidence(
            incident_id=incident_id,
            key="Model Prediction",
            value=f"Label: {label} (Confidence: {res['confidence']:.2f}, ML: {res.get('is_ml', False)})"
        ))
        db.add(Evidence(
            incident_id=incident_id,
            key="File Integrity",
            value=f"File Name: {os.path.basename(file_path)}, Size: {os.path.getsize(file_path)} bytes"
        ))
        
        # Log specific forensic signatures/reasons
        for reason in res.get("reasons", []):
            db.add(Evidence(
                incident_id=incident_id,
                key="Deepfake Forensic Artifact",
                value=reason
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

        # Autonomously learn from Deepfake media scan response metadata
        self_learning_classifier.learn(f"media deepfake analysis file: {os.path.basename(file_path)} classification: {status}", status)
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

        # Check if it is a binary PCAP or PCAPNG file
        is_pcap = False
        magic = b""
        if os.path.exists(file_path):
            with open(file_path, "rb") as f:
                magic = f.read(4)
                if magic in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x0a\x0d\x0d\x0a'):
                    is_pcap = True

        score = 0
        evidences = []
        status = "SAFE"
        severity = "LOW"

        if is_pcap:
            # -------------------------------------------------------------
            # PCAP / PCAPNG Network Traffic Analysis
            # -------------------------------------------------------------
            packets = []
            try:
                with open(file_path, "rb") as f:
                    # Check magic
                    if magic in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'):
                        # Standard PCAP
                        f.read(20) # skip remaining global header
                        while len(packets) < 500: # Limit to 500 packets for performance
                            pkt_header = f.read(16)
                            if len(pkt_header) < 16:
                                break
                            if magic == b'\xd4\xc3\xb2\xa1':
                                ts_sec, ts_usec, incl_len, orig_len = struct.unpack("<IIII", pkt_header)
                            else:
                                ts_sec, ts_usec, incl_len, orig_len = struct.unpack(">IIII", pkt_header)
                            pkt_data = f.read(incl_len)
                            if len(pkt_data) < incl_len:
                                break
                            
                            # Parse Ethernet + IPv4 + TCP/UDP
                            if len(pkt_data) >= 14:
                                eth_type = struct.unpack(">H", pkt_data[12:14])[0]
                                if eth_type == 0x0800:
                                    ip_data = pkt_data[14:]
                                    if len(ip_data) >= 20:
                                        proto = ip_data[9]
                                        src_ip = ".".join(map(str, ip_data[12:16]))
                                        dest_ip = ".".join(map(str, ip_data[16:20]))
                                        src_port, dest_port = None, None
                                        payload_offset = (ip_data[0] & 0x0F) * 4
                                        transport_data = ip_data[payload_offset:]
                                        if proto == 6 and len(transport_data) >= 4:
                                            src_port, dest_port = struct.unpack(">HH", transport_data[:4])
                                        elif proto == 17 and len(transport_data) >= 4:
                                            src_port, dest_port = struct.unpack(">HH", transport_data[:4])
                                        packets.append({
                                            "proto": "TCP" if proto == 6 else ("UDP" if proto == 17 else "ICMP" if proto == 1 else "IPv4"),
                                            "src": src_ip, "dest": dest_ip, "sport": src_port, "dport": dest_port
                                        })
                    elif magic == b'\x0a\x0d\x0d\x0a':
                        # PCAPNG
                        f.seek(0)
                        while len(packets) < 500:
                            block_header = f.read(8)
                            if len(block_header) < 8:
                                break
                            block_type, block_len = struct.unpack("<II", block_header)
                            if block_len < 8:
                                break
                            block_data = f.read(block_len - 8)
                            if len(block_data) < (block_len - 8):
                                break
                            if block_type == 6: # Enhanced Packet Block
                                if len(block_data) >= 20:
                                    cap_len = struct.unpack("<I", block_data[12:16])[0]
                                    pkt_data = block_data[20:20+cap_len]
                                    if len(pkt_data) >= 14:
                                        eth_type = struct.unpack(">H", pkt_data[12:14])[0]
                                        if eth_type == 0x0800:
                                            ip_data = pkt_data[14:]
                                            if len(ip_data) >= 20:
                                                proto = ip_data[9]
                                                src_ip = ".".join(map(str, ip_data[12:16]))
                                                dest_ip = ".".join(map(str, ip_data[16:20]))
                                                src_port, dest_port = None, None
                                                payload_offset = (ip_data[0] & 0x0F) * 4
                                                transport_data = ip_data[payload_offset:]
                                                if proto == 6 and len(transport_data) >= 4:
                                                    src_port, dest_port = struct.unpack(">HH", transport_data[:4])
                                                elif proto == 17 and len(transport_data) >= 4:
                                                    src_port, dest_port = struct.unpack(">HH", transport_data[:4])
                                                packets.append({
                                                    "proto": "TCP" if proto == 6 else ("UDP" if proto == 17 else "ICMP" if proto == 1 else "IPv4"),
                                                    "src": src_ip, "dest": dest_ip, "sport": src_port, "dport": dest_port
                                                })
            except Exception as pe:
                print(f"Error parsing binary packet stream: {pe}")

            total_pkts = len(packets)
            if total_pkts > 0:
                # Group stats
                src_ips = [p["src"] for p in packets]
                dest_ports = [p["dport"] for p in packets if p["dport"] is not None]
                protocols = [p["proto"] for p in packets]

                unique_srcs = list(set(src_ips))
                unique_dports = list(set(dest_ports))
                
                # Check for flooding/DDoS trends
                src_counts = {ip: src_ips.count(ip) for ip in unique_srcs}
                flooding_ips = [ip for ip, count in src_counts.items() if count > 40]
                
                # Check for Port Scanning trends (connecting to 5+ distinct destination ports)
                scan_trends = []
                for s_ip in unique_srcs:
                    ports_accessed = list(set([p["dport"] for p in packets if p["src"] == s_ip and p["dport"] is not None]))
                    if len(ports_accessed) >= 5:
                        scan_trends.append((s_ip, len(ports_accessed)))

                evidences.append(("Wireshark Packet Analysis", f"Parsed {total_pkts} packets from binary capture file."))
                evidences.append(("Active Protocols", f"Detected traffic: " + ", ".join(f"{pr}: {protocols.count(pr)}" for pr in set(protocols))))
                
                if flooding_ips:
                    score += 8
                    evidences.append(("Volumetric Flood Threat", f"Potential DDoS/Flood trend detected from: {', '.join(flooding_ips[:3])} ({src_counts[flooding_ips[0]]} pkts)"))
                
                if scan_trends:
                    score += 8
                    evidences.append(("Port Scanning Trend", f"IP {scan_trends[0][0]} connected to {scan_trends[0][1]} distinct ports (Potential reconnaissance target scan)"))
                
                # Check for access to sensitive target ports
                sensitive_ports = {21: "FTP", 22: "SSH", 23: "Telnet", 445: "SMB", 3389: "RDP"}
                accessed_sensitive = []
                for p in packets:
                    if p["dport"] in sensitive_ports and p["dport"] not in accessed_sensitive:
                        accessed_sensitive.append(p["dport"])
                        score += 4
                        evidences.append(("Restricted Service Probe", f"Unauthorized connection attempt to {sensitive_ports[p['dport']]} (Port {p['dport']})"))
                
                # Calculate metrics
                scaled_score = min(int((score / 15) * 100), 100)
            else:
                evidences.append(("Empty Capture File", "No packets could be parsed from the binary pcap file."))
                scaled_score = 0
        else:
            # -------------------------------------------------------------
            # Text Log & Wireshark Text Dump Parsing
            # -------------------------------------------------------------
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            # Detect if it's a Wireshark plain text export log
            is_wireshark_text = False
            if "Frame " in content or "Transmission Control Protocol" in content or re.search(r"\bNo\.\s+Time\s+Source\s+Destination\s+Protocol\b", content):
                is_wireshark_text = True
                evidences.append(("Log File Type", "Wireshark Packet Export Log (Text Dump)"))
            else:
                evidences.append(("Log File Type", "Server System Log"))

            # 1. Login Brute-force Login scans
            brute_force_patterns = [
                r"(?i)failed password", r"(?i)login failed", r"(?i)authentication failed", 
                r"(?i)invalid user", r"(?i)unauthorized login", r"(?i)access denied for user"
            ]
            failed_logins = 0
            for pat in brute_force_patterns:
                failed_logins += len(re.findall(pat, content))
            
            if failed_logins >= 5:
                score += 8
                evidences.append(("Brute-force Login Trend", f"Detected {failed_logins} failed login attempts (Threshold exceeded: potential credential stuffing/brute force)."))
            elif failed_logins > 0:
                score += 3
                evidences.append(("Suspicious Login Activities", f"Found {failed_logins} failed login attempt(s)."))

            # 2. SQL Injection (SQLi)
            sqli_patterns = [
                r"(?i)UNION\s+SELECT", r"(?i)OR\s+1\s*=\s*1", r"(?i)UNION\s+ALL\s+SELECT",
                r"(?i)select\s+.*\s+from", r"(?i)insert\s+into", r"(?i)drop\s+table"
            ]
            sqli_matches = 0
            for pat in sqli_patterns:
                sqli_matches += len(re.findall(pat, content))
            if sqli_matches >= 3:
                score += 8
                evidences.append(("SQL Injection Attack Trend", f"Found {sqli_matches} SQL injection exploit signatures (Database extraction attempt)."))
            elif sqli_matches > 0:
                score += 4
                evidences.append(("SQL Injection Query Probe", f"Found {sqli_matches} SQL injection character signature(s)."))

            # 3. Privilege Escalation
            priv_esc_patterns = [
                r"(?i)sudo:\s+.*\s+:\s+TTY=", r"(?i)su:\s+auth\s+failed", r"(?i)privilege\s+escalation",
                r"(?i)pkexec", r"(?i)polkit", r"(?i)root\s+execution", r"(?i)escalated\s+to\s+root"
            ]
            priv_esc_matches = 0
            for pat in priv_esc_patterns:
                priv_esc_matches += len(re.findall(pat, content))
            if priv_esc_matches > 0:
                score += 8
                evidences.append(("Privilege Escalation Trend", f"Found {priv_esc_matches} privilege escalation log trace(s) (Active attempts to acquire administrative shell access)."))

            # 4. Malware Execution Indicators
            malware_patterns = [
                r"(?i)/tmp/.*\.sh", r"(?i)chmod\s+\+x\s+", r"(?i)curl\s+.*\s*\|\s*sh", 
                r"(?i)wget\s+.*\s*\|\s*sh", r"(?i)malware", r"(?i)trojan", r"(?i)backdoor\s+active"
            ]
            malware_matches = 0
            for pat in malware_patterns:
                malware_matches += len(re.findall(pat, content))
            if malware_matches > 0:
                score += 9
                evidences.append(("Malware Execution Indicator", f"Found {malware_matches} malware download/execution log signature(s) (Executable drop or system modification script detected)."))

            # 5. Unauthorized Access Attempts
            unauth_patterns = [
                r"\b401\b", r"\b403\b", r"(?i)permission denied", r"(?i)access denied", r"(?i)unauthorized access"
            ]
            unauth_matches = 0
            for pat in unauth_patterns:
                unauth_matches += len(re.findall(pat, content))
            if unauth_matches >= 5:
                score += 6
                evidences.append(("Unauthorized Access Trend", f"Detected {unauth_matches} restricted resource access attempts (Active directories/file path probing)."))
            elif unauth_matches > 0:
                score += 2
                evidences.append(("Unauthorized Probes", f"Detected {unauth_matches} unauthorized access attempt(s)."))

            # 6. Basic indicators from old code
            # Directory Traversal
            traversal_matches = len(re.findall(r"(?i)\.\./|\.\.\\|%2f%2f", content))
            if traversal_matches > 0:
                score += 5
                evidences.append(("Directory Traversal Attempt", f"Found {traversal_matches} path traversal pattern(s) (Directory listings exploration)."))

            # Command Injection
            cmd_matches = len(re.findall(r"(?i);\s*wget|;\s*curl|;\s*rm\s+-rf|cmd\.exe|/bin/sh", content))
            if cmd_matches > 0:
                score += 6
                evidences.append(("Command Injection Probe", f"Found {cmd_matches} command injection shell indicator(s)."))

            # Cross-Site Scripting (XSS)
            xss_matches = len(re.findall(r"(?i)<script>|javascript:|onerror\s*=", content))
            if xss_matches > 0:
                score += 4
                evidences.append(("Cross-Site Scripting (XSS) Attempt", f"Found {xss_matches} scripting tag signature(s)."))

            # Extract external IPs
            ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
            ips = list(set(re.findall(ip_pattern, content)))
            suspicious_ips = []
            for ip in ips:
                if not (ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16.") or ip.startswith("172.17.") or ip.startswith("172.18.") or ip.startswith("172.19.") or ip.startswith("172.2") or ip.startswith("172.3")):
                    suspicious_ips.append(ip)
            if suspicious_ips:
                evidences.append(("Network Indicators (IPs)", f"Extracted {len(suspicious_ips)} external IP(s): {', '.join(suspicious_ips[:5])}"))
                score += min(len(suspicious_ips), 5)

            # Compute overall metrics
            scaled_score = min(int((score / 18) * 100), 100)

        # Determine dominant attack type
        attack_type = "None (Authentic Logs)"
        abused_port = "N/A"
        protocol = "N/A"
        payload = "None"
        attacker_ip = "N/A"
        victim_ip = "172.25.113.214"  # Default local SOC node
        
        # Extract IPs
        if 'suspicious_ips' in locals() and suspicious_ips:
            attacker_ip = suspicious_ips[0]
        elif is_pcap and 'unique_srcs' in locals() and unique_srcs:
            attacker_ip = unique_srcs[0]
            if len(unique_srcs) > 1:
                victim_ip = unique_srcs[1]
        
        # Map PCAP anomalies
        if is_pcap:
            if 'flooding_ips' in locals() and flooding_ips:
                attack_type = "DDoS Volumetric Flood"
                abused_port = str(dest_ports[0]) if 'dest_ports' in locals() and dest_ports else "Generic"
                protocol = protocols[0] if 'protocols' in locals() and protocols else "UDP"
                payload = "High volume payload packet flooding"
            elif 'scan_trends' in locals() and scan_trends:
                attack_type = "Reconnaissance Port Scan"
                abused_port = "Multiple (Range)"
                protocol = "TCP"
                payload = "Service mapping ports lookup"
            elif 'accessed_sensitive' in locals() and accessed_sensitive:
                attack_type = "Restricted Service Probe"
                abused_port = str(accessed_sensitive[0])
                protocol = "TCP"
                payload = f"Connection probe targeting critical service"
        else:
            # Map text log anomalies
            if 'failed_logins' in locals() and failed_logins >= 5:
                attack_type = "Brute Force Credentials Attack"
                abused_port = "22"
                protocol = "SSH"
                payload = "Multiple password mismatch queries"
            elif 'sqli_matches' in locals() and sqli_matches >= 3:
                attack_type = "SQL Injection (SQLi) Web Exploit"
                abused_port = "80 / 443"
                protocol = "HTTP"
                payload = "Database bypass payload injection"
            elif 'cmd_matches' in locals() and cmd_matches > 0:
                attack_type = "Remote Command Execution (RCE)"
                abused_port = "80 / 443"
                protocol = "HTTP"
                payload = "Malicious shell download attempt"
            elif 'traversal_matches' in locals() and traversal_matches > 0:
                attack_type = "Directory Traversal Attack"
                abused_port = "80 / 443"
                protocol = "HTTP"
                payload = "System file path retrieval probe"
            elif 'malware_matches' in locals() and malware_matches > 0:
                attack_type = "Malware Shellcode Execution"
                abused_port = "Generic TCP"
                protocol = "TCP"
                payload = "Executable shell script drop"
            elif 'priv_esc_matches' in locals() and priv_esc_matches > 0:
                attack_type = "Local Privilege Escalation"
                abused_port = "Console"
                protocol = "Local TTY"
                payload = "Sudo access escalation probe"

        # Save specific network attack evidence keys
        evidences.append(("Attack Type", attack_type))
        evidences.append(("Attacker IP", attacker_ip))
        evidences.append(("Attacked Machine IP", victim_ip))
        evidences.append(("Abused Port", abused_port))
        evidences.append(("Abused Protocol", protocol))
        evidences.append(("Suspicious Payload", payload))

        # Run self-learning model prediction on log content sample or packet metadata
        log_sample = content[:4000] if not is_pcap else f"pcap packet count: {total_pkts} active hosts: {len(unique_srcs)}"
        ml_label, ml_confidence = self_learning_classifier.predict(log_sample)
        if ml_label == "PHISHING" and ml_confidence > 0.85:
            if scaled_score < 70:
                scaled_score = max(scaled_score, 75)
                evidences.append(("Self-Learning ML Core flag", f"Flagged suspicious exploit log trace patterns (Confidence: {ml_confidence:.2f})"))

        # Common Incident updates
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
        incident.threat_score = min(scaled_score, 100)

        # Save all evidence
        for key, val in evidences:
            db.add(Evidence(incident_id=incident_id, key=key, value=val))

        # Add general stats evidence
        db.add(Evidence(
            incident_id=incident_id,
            key="Log Telemetry Stats",
            value=f"Log File: {os.path.basename(file_path)}, Total Size: {os.path.getsize(file_path)} bytes, Format Checked: {'PCAP/PCAPNG' if is_pcap else 'Text Logs'}"
        ))

        # Remediations
        if status == "PHISHING":
            if is_pcap:
                db.add(Remediation(incident_id=incident_id, description="Deploy ACL rules on border routers to block identified port scanning/reconnaissance IP addresses."))
                db.add(Remediation(incident_id=incident_id, description="Rate limit packet flows to mitigate volumetric flood patterns on restricted ports."))
            else:
                db.add(Remediation(incident_id=incident_id, description="Block external attacker IPs attempting SQL Injection or Path Traversal at WAF layer."))
                db.add(Remediation(incident_id=incident_id, description="Enforce Multi-Factor Authentication (MFA) and lock accounts suffering brute-force attacks."))
                db.add(Remediation(incident_id=incident_id, description="Isolate hosts showing shell command executions, credential drops, or script runs from `/tmp`."))
            db.add(Remediation(incident_id=incident_id, description="Audit authentication tables and server files for post-exploit access shells or privileges escalation."))
        elif status == "SUSPICIOUS":
            db.add(Remediation(incident_id=incident_id, description="Monitor connection traffic from identified external IP addresses for further probe signatures."))
            db.add(Remediation(incident_id=incident_id, description="Sanitize web inputs and update vulnerable package binaries to mitigate SQLi and XSS exploits."))
        else:
            db.add(Remediation(incident_id=incident_id, description="Log file indicates normal system behavior. Continue standard log retention audits."))

        # Autonomously learn from Log/PCAP scan response
        self_learning_classifier.learn(log_sample, status)
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
