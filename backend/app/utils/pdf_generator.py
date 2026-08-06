import time
import random
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

def generate_unique_report_no(prefix=""):
    """
    Generates a unique audit reference number for each report download.
    """
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    rand = random.randint(1000, 9999)
    prefix_clean = prefix[:4].upper() if prefix else "SUM"
    return f"REP-{timestamp}-{prefix_clean}-{rand}"

def draw_header_footer(canvas, doc, is_summary=False):
    """
    Draws the premium Cobalt Blue header banner and bottom security footer on each page.
    """
    canvas.saveState()
    
    # 1. Cobalt Blue Top Banner (White Hack styling reference)
    canvas.setFillColor(colors.HexColor("#0052FF")) # Modern Cobalt Blue
    canvas.rect(0, 725, 612, 67, fill=True, stroke=False)
    
    # Accent cyan line
    canvas.setFillColor(colors.HexColor("#38BDF8")) # Sky Cyan
    canvas.rect(0, 721, 612, 4, fill=True, stroke=False)
    
    # Text on banner
    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica-Bold", 13)
    if is_summary:
        canvas.drawString(54, 755, "🛡️ ORION SOC THREAT INTELLIGENCE PORTAL")
        canvas.setFont("Helvetica", 9)
        canvas.drawString(54, 740, "GLOBAL SCAN TELEMETRY SUMMARY REPORT")
    else:
        canvas.drawString(54, 755, "🛡️ ORION SECURITY OPERATIONS CENTER")
        canvas.setFont("Helvetica", 9)
        canvas.drawString(54, 740, "AUTOMATED SECURE VECTOR AUDIT REPORT")
        
    # Security classification stamp on top right
    canvas.setFont("Helvetica-Bold", 8)
    canvas.drawRightString(612 - 54, 755, "CLASSIFIED / SYSTEM SECURE")
    canvas.setFont("Helvetica", 8)
    canvas.drawRightString(612 - 54, 740, "LEVEL 3 SECURITY TRIAGE")
    
    # 2. Bottom Footer
    canvas.setStrokeColor(colors.HexColor("#E2E8F0"))
    canvas.setLineWidth(0.75)
    canvas.line(54, 45, 612 - 54, 45)
    
    canvas.setFillColor(colors.HexColor("#64748B"))
    canvas.setFont("Helvetica", 8)
    canvas.drawString(54, 30, "WHITE HACK SOC CORE // CORE THREAT TRIAGE PLATFORM")
    canvas.drawRightString(612 - 54, 30, f"Page {doc.page} // Confidential Incident Log")
    
    canvas.restoreState()

def generate_pdf_report(incident, evidences, remediations, buffer):
    # Setup document with room for top banner and bottom footer
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=54,
        leftMargin=54,
        topMargin=95,
        bottomMargin=65
    )

    styles = getSampleStyleSheet()

    # Modify / Add custom styles
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=5
    )

    h1_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=15,
        textColor=colors.HexColor("#0052FF"), # Cobalt Blue
        spaceBefore=14,
        spaceAfter=8,
        keepWithNext=True
    )

    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9.5,
        leading=13.5,
        textColor=colors.HexColor("#334155")
    )

    body_bold_style = ParagraphStyle(
        "ReportBodyBold",
        parent=body_style,
        fontName="Helvetica-Bold"
    )

    bullet_style = ParagraphStyle(
        "ReportBullet",
        parent=body_style,
        leftIndent=15,
        firstLineIndent=-15,
        spaceAfter=8
    )

    footer_style = ParagraphStyle(
        "ReportFooter",
        parent=styles["Normal"],
        fontName="Helvetica-Oblique",
        fontSize=8.5,
        leading=11.5,
        alignment=1, # Centered
        textColor=colors.HexColor("#64748B")
    )

    # Severity Colors
    sev = incident["severity"].upper()
    if sev == "CRITICAL":
        sev_color = colors.HexColor("#9B2C2C")
    elif sev == "HIGH":
        sev_color = colors.HexColor("#C53030")
    elif sev == "MEDIUM":
        sev_color = colors.HexColor("#DD6B20")
    else:
        sev_color = colors.HexColor("#2F855A")

    elements = []

    # Dynamic Unique Report Number
    report_no = generate_unique_report_no(incident["id"])

    # 1. Title Header Block
    elements.append(Paragraph(f"AUDIT THREAT FORENSICS ASSESSMENT", title_style))
    elements.append(Paragraph("CRITICAL RISK METRICS AND SYSTEM RECOMMENDATIONS", ParagraphStyle("Sub", parent=body_style, fontName="Helvetica-Bold", textColor=colors.HexColor("#64748B"), spaceAfter=15)))

    # 2. Status Callout Card (Visual element styling popup reference)
    callout_bg = "#ECFDF5" # Emerald Green
    callout_border = "#10B981"
    callout_text_color = "#047857"
    callout_title = "SYSTEM SECURE // NO COMPROMISES DETECTED"
    callout_desc = "The analyzed threat vector did not trigger typosquatting, payload entropy, signature matches, or heuristic rule violations. No containment actions are required."
    
    if incident["status"] in ("PHISHING", "DEEPFAKE"):
        callout_bg = "#FEF2F2" # Rose Red
        callout_border = "#EF4444"
        callout_text_color = "#991B1B"
        if incident["status"] == "DEEPFAKE":
            callout_title = "ALERT // AUDIO/VIDEO DEEPFAKE SYNTHETIC CLONING DETECTED"
            callout_desc = "The audited binary media file contains low Shannon acoustic/visual entropy signatures and synthetic generative fingerprints, suggesting AI-cloned audio or deepfaked frames."
        else:
            callout_title = "ALERT // MALICIOUS PHISHING COMPROMISE IDENTIFIED"
            callout_desc = "Heuristic scanner analysis, edit-distance typosquatting checks, or self-learning ML classification detected active phishing traits, social engineering intent, or domain spoofing."
    elif incident["status"] == "SUSPICIOUS":
        callout_bg = "#FFFBEB" # Amber Yellow
        callout_border = "#F59E0B"
        callout_text_color = "#92400E"
        callout_title = "WARNING // SUSPICIOUS THREAT INDICATORS MONITORED"
        callout_desc = "The system monitored warning indicators (e.g. untrusted public email domains, elevated network port targets, or directory traversal strings) that require manual security triage."

    callout_data = [[
        Paragraph(f"<font color='{callout_text_color}'><b>{callout_title}</b><br/>{callout_desc}</font>", ParagraphStyle("CalloutStyle", parent=body_style, fontSize=9, leading=13))
    ]]
    callout_table = Table(callout_data, colWidths=[504])
    callout_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(callout_bg)),
        ("BOX", (0, 0), (-1, -1), 1.5, colors.HexColor(callout_border)),
        ("PADDING", (0, 0), (-1, -1), 10),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    elements.append(callout_table)
    elements.append(Spacer(1, 15))

    # 3. Incident Metadata Table
    metadata_data = [
        [
            Paragraph("<b>Report Number:</b>", body_style),
            Paragraph(f"<font color='#0052FF'><b>{report_no}</b></font>", body_bold_style),
            Paragraph("<b>Ingest Vector:</b>", body_style),
            Paragraph(incident["vector_type"].upper(), body_bold_style)
        ],
        [
            Paragraph("<b>Incident Target:</b>", body_style),
            Paragraph(incident["id"][:14] + "...", body_style),
            Paragraph("<b>Timestamp Audited:</b>", body_style),
            Paragraph(incident["timestamp"], body_style)
        ],
        [
            Paragraph("<b>Threat Severity:</b>", body_style),
            Paragraph(f"<font color='{sev_color}'><b>{sev}</b></font>", body_bold_style),
            Paragraph("<b>Threat Score:</b>", body_style),
            Paragraph(f"<b>{incident['threat_score']}% Rating</b>", body_style)
        ]
    ]

    metadata_table = Table(metadata_data, colWidths=[100, 152, 100, 152])
    metadata_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#E2E8F0")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#EDF2F7")),
        ("PADDING", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    elements.append(metadata_table)
    elements.append(Spacer(1, 15))

    # Target Input Section
    elements.append(Paragraph(f"<b>Analyzed Input Stream Target:</b> {incident['target_input']}", body_style))
    elements.append(Spacer(1, 15))

    # EML Envelope Analysis Table
    is_email = (incident["vector_type"].upper() == "EMAIL")
    if is_email:
        sender = next((ev["value"] for ev in evidences if ev["key"] == "Email Sender"), None)
        recipient = next((ev["value"] for ev in evidences if ev["key"] == "Email Recipient"), None)
        cc = next((ev["value"] for ev in evidences if ev["key"] == "Email CC"), None)
        date_header = next((ev["value"] for ev in evidences if ev["key"] == "Email Date"), None)
        reply_to = next((ev["value"] for ev in evidences if ev["key"] == "Email Reply-To"), None)
        msg_id = next((ev["value"] for ev in evidences if ev["key"] == "Email Message-ID"), None)
        subject = next((ev["value"] for ev in evidences if ev["key"] == "Email Subject"), None)

        elements.append(Paragraph("Email Envelope & Header Analysis", h1_style))
        elements.append(Paragraph("The parsed email file contained the following envelope headers and metadata:", body_style))
        elements.append(Spacer(1, 10))
        
        header_table_data = [
            [
                Paragraph("<b>HEADER METADATA FIELD</b>", ParagraphStyle("Hdr", parent=body_style, textColor=colors.white, fontName="Helvetica-Bold", fontSize=8)),
                Paragraph("<b>AUDITED TELEMETRY VALUE</b>", ParagraphStyle("Hdr", parent=body_style, textColor=colors.white, fontName="Helvetica-Bold", fontSize=8))
            ],
            [Paragraph("<b>From:</b>", body_style), Paragraph(sender or "N/A", body_style)],
            [Paragraph("<b>To:</b>", body_style), Paragraph(recipient or "N/A", body_style)],
        ]
        if cc:
            header_table_data.append([Paragraph("<b>Cc:</b>", body_style), Paragraph(cc, body_style)])
        header_table_data.append([Paragraph("<b>Subject:</b>", body_style), Paragraph(subject or "No Subject", body_style)])
        header_table_data.append([Paragraph("<b>Date:</b>", body_style), Paragraph(date_header or "N/A", body_style)])
        if reply_to:
            header_table_data.append([Paragraph("<b>Reply-To:</b>", body_style), Paragraph(reply_to, body_style)])
        if msg_id:
            header_table_data.append([Paragraph("<b>Message-ID:</b>", body_style), Paragraph(msg_id, body_style)])

        header_table = Table(header_table_data, colWidths=[130, 374])
        header_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0052FF")), # Cobalt Blue Header
            ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#F8FAFC")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#E2E8F0")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#EDF2F7")),
            ("PADDING", (0, 0), (-1, -1), 6),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        elements.append(header_table)
        elements.append(Spacer(1, 15))

    # Holographic Log/PCAP Network Forensic Analysis Table
    is_log = (incident["vector_type"].upper() == "LOG")
    if is_log:
        attack_type = next((ev["value"] for ev in evidences if ev["key"] == "Attack Type"), "Anomalous Probing")
        attacker_ip = next((ev["value"] for ev in evidences if ev["key"] == "Attacker IP"), "N/A")
        victim_ip = next((ev["value"] for ev in evidences if ev["key"] == "Attacked Machine IP"), "N/A")
        abused_port = next((ev["value"] for ev in evidences if ev["key"] == "Abused Port"), "N/A")
        protocol = next((ev["value"] for ev in evidences if ev["key"] == "Abused Protocol"), "N/A")
        payload = next((ev["value"] for ev in evidences if ev["key"] == "Suspicious Payload"), "N/A")
        log_stats = next((ev["value"] for ev in evidences if ev["key"] == "Log Telemetry Stats"), "N/A")

        elements.append(Paragraph("Network Forensics & Exploit Analysis", h1_style))
        elements.append(Paragraph("The forensic engine audited the uploaded log stream, extracting the following threat parameters:", body_style))
        elements.append(Spacer(1, 10))

        log_table_data = [
            [
                Paragraph("<b>EXPLOIT METADATA FIELD</b>", ParagraphStyle("Hdr", parent=body_style, textColor=colors.white, fontName="Helvetica-Bold", fontSize=8)),
                Paragraph("<b>AUDITED TELEMETRY VALUE</b>", ParagraphStyle("Hdr", parent=body_style, textColor=colors.white, fontName="Helvetica-Bold", fontSize=8))
            ],
            [Paragraph("<b>Monitored Attack:</b>", body_style), Paragraph(attack_type, body_bold_style)],
            [Paragraph("<b>Attacker IP (Source):</b>", body_style), Paragraph(attacker_ip, body_style)],
            [Paragraph("<b>Target IP (Destination):</b>", body_style), Paragraph(victim_ip, body_style)],
            [Paragraph("<b>Abused Port Number:</b>", body_style), Paragraph(abused_port, body_style)],
            [Paragraph("<b>Protocol Abused:</b>", body_style), Paragraph(protocol, body_bold_style)],
            [Paragraph("<b>Suspicious Attachment/Payload:</b>", body_style), Paragraph(payload, body_style)],
            [Paragraph("<b>Ingested File Details:</b>", body_style), Paragraph(log_stats, body_style)]
        ]

        log_table = Table(log_table_data, colWidths=[150, 354])
        log_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0052FF")), # Cobalt Blue Header
            ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#FFF5F5") if incident["severity"].upper() in ("HIGH", "CRITICAL") else colors.HexColor("#F8FAFC")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#FEB2B2") if incident["severity"].upper() in ("HIGH", "CRITICAL") else colors.HexColor("#E2E8F0")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#FEEBC8") if incident["severity"].upper() in ("HIGH", "CRITICAL") else colors.HexColor("#EDF2F7")),
            ("PADDING", (0, 0), (-1, -1), 6),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        elements.append(log_table)
        elements.append(Spacer(1, 15))

    # Filter out raw email and network metadata from general evidences list
    filter_keys = [
        "Email Sender", "Email Recipient", "Email CC", "Email Date", "Email Reply-To", "Email Message-ID", "Email Subject",
        "Attack Type", "Attacker IP", "Attacked Machine IP", "Abused Port", "Abused Protocol", "Suspicious Payload", "Log Telemetry Stats"
    ]
    general_evidences = [ev for ev in evidences if ev["key"] not in filter_keys]

    # 4. Evidence Breakdown Section
    elements.append(Paragraph("Evidence Breakdown (IoCs & Indicators)", h1_style))
    elements.append(Paragraph("The system identified the following threat indicators during analysis:", body_style))
    elements.append(Spacer(1, 10))

    def get_detailed_description(key, value):
        val_lower = value.lower()
        if "https" in val_lower or "insecure http" in val_lower:
            return ("Website is not using secure HTTPS encryption. Attackers commonly use such techniques "
                    "to manipulate users, steal credentials, distribute malware, or impersonate trusted services.")
        elif "malformed" in val_lower or "invalid domain structure" in val_lower:
            return ("The domain structure is malformed or invalid. Phishing campaigns often use badly formatted "
                    "domains or non-standard characters to bypass security filters and deceive web browsers.")
        elif "comma" in val_lower:
            return ("The URL contains an invalid comma separator. Attackers use commas or other unexpected symbols "
                    "to confuse security scanners and obscure the real destination of the link.")
        elif "format validation failed" in val_lower:
            return ("The domain name failed standard format validation. This usually indicates a syntactically "
                    "incorrect domain name designed to mimic legitimate domains while exploiting typos.")
        elif "@ symbol" in val_lower:
            return ("The URL contains an '@' symbol. In standard URLs, everything before the '@' is treated as user info, "
                    "which allows attackers to prepend a trusted domain name to hide the actual malicious destination domain.")
        elif "punycode" in val_lower:
            return ("A Punycode domain has been detected. Attackers use Punycode to represent internationalized domain "
                    "names (IDN) that look identical to legitimate brand domains (homograph attacks) but use visually similar characters.")
        elif "numeric ip" in val_lower or "ip address used" in val_lower:
            return ("The URL uses a numeric IP address instead of a domain name. Legitimate websites almost always use "
                    "domain names. Using raw IP addresses is a common tactic to hide the host identity and evade reputation checks.")
        elif "cloudflare tunnel" in val_lower:
            return ("A Cloudflare tunnel domain is used. Attackers frequently use free tunneling services to host temporary "
                    "phishing pages directly from local machines, bypassing traditional domain registration checks.")
        elif "typosquat" in val_lower:
            return ("The domain appears to be typosquatted. Attackers register domains that are common typos of popular brands "
                    "(e.g., swapping letters like 'l' for '1' or 'o' for '0') to trick users who miskey a URL.")
        elif "shortener" in val_lower:
            return ("The URL uses a shortening service. While shortened URLs are common, they are heavily abused by "
                    "cybercriminals to conceal the final destination of a malicious link and bypass filters.")
        elif "redirect" in val_lower:
            return ("The URL contains open redirection parameters. Phishing attacks use open redirect vulnerabilities on "
                    "legitimate sites to send users to malicious pages, making the initial link look safe.")
        elif "public domain" in val_lower:
            return ("The URL uses a public domain (like gmail.com or outlook.com) inappropriately. Attackers register accounts "
                    "on free services or use public email domain names in URLs to create a false sense of legitimacy.")
        elif "subdomain" in val_lower:
            return ("The URL contains an excessive number of subdomains or an unusually long subdomain. Phishing campaigns "
                    "often use deep subdomains to craft long URLs where the actual, malicious domain name is pushed off the screen.")
        elif "hyphen" in val_lower:
            return ("A hyphen is used in the domain name. Phishing sites frequently insert hyphens into brand names (e.g., "
                    "'secure-paypal.com') to create variations of official domains that look legitimate.")
        elif "numbers in domain" in val_lower or "numbers used in domain" in val_lower:
            return ("The domain name contains numbers. While some legitimate domains contain numbers, phishing domains often "
                    "include random digits or numeric sequences to create unique, automated domains for temporary campaigns.")
        elif "spoofing" in val_lower:
            return f"The email sender display name is spoofed: {value}. Attackers frequently spoof email headers to pretend to be a trusted corporate service."
        elif "nlp text analysis" in val_lower:
            return f"Deep NLP context evaluation: {value}. High semantic score suggests malicious social engineering intent."
        elif "deepfake" in val_lower:
            return f"Deep learning media classification results: {value}. Analyzed media characteristics show synthetic anomalies."
        elif "brute-force" in val_lower or "login activities" in val_lower:
            return f"Authentication Abuse Detected: {value}. Multiple invalid login queries suggest an active brute-forcing campaign."
        elif "sqli" in val_lower or "sql injection" in val_lower:
            return f"Database Exploit signature: {value}. Exploit patterns targeting backend database tables detected."
        elif "privilege escalation" in val_lower:
            return f"Privilege Escalation Trace: {value}. Administrative execute/su attempts detected in log logs."
        elif "malware execution" in val_lower:
            return f"Host Intrusion Alert: {value}. Remote payload download or direct script execution indicators detected."
        elif "unauthorized access" in val_lower or "unauthorized probes" in val_lower:
            return f"Access Control Threat: {value}. Requests hitting forbidden resource folders."
        elif "wireshark" in val_lower or "packet" in val_lower or "active protocols" in val_lower:
            return f"Network Packet telemetry: {value}"
        elif "flood" in val_lower:
            return f"Volumetric Flood Attack: {value}. Large influx of raw traffic indicating a potential denial of service attempt."
        elif "port scanning" in val_lower:
            return f"Network Reconnaissance: {value}. Attacker IP mapping ports to locate active network services."
        elif "probe" in val_lower or "sensitive" in val_lower:
            return f"Sensitive Service Target: {value}. Target port scan probes identified on critical system ports."
        return f"{key}: {value}"

    if general_evidences:
        for ev in general_evidences:
            desc = get_detailed_description(ev["key"], ev["value"])
            elements.append(Paragraph(f"• <b>{ev['key']}</b>: {desc}", bullet_style))
    else:
        elements.append(Paragraph("• No suspicious threat indicators or compromises detected.", bullet_style))

    elements.append(Spacer(1, 15))

    # 5. Remediation Recommendations Section
    elements.append(Paragraph("Actionable Remediation Recommendations", h1_style))
    elements.append(Paragraph("The Security Operations Center recommends taking the following containment and recovery actions immediately:", body_style))
    elements.append(Spacer(1, 10))

    if remediations:
        for rem in remediations:
            elements.append(Paragraph(f"• {rem['description']}", bullet_style))
    else:
        elements.append(Paragraph("• No remediation actions required. The target is classified as safe.", bullet_style))

    elements.append(Spacer(1, 20))

    # 6. Footer Signature
    elements.append(Paragraph("<b>THREAT COMMAND CENTER // MULTI-VECTOR SECURITY OPERATIONS CENTER</b><br/>"
                             "Incident Lead Architect: <i>Aksht Rana</i> // Email: align.akshtrana@gmail.com // LinkedIn: https://www.linkedin.com/in/aksht-rana-009515373/", footer_style))

    # Build the document, applying top banner on each page
    doc.build(elements, onFirstPage=lambda c, d: draw_header_footer(c, d, False), onLaterPages=lambda c, d: draw_header_footer(c, d, False))


def generate_summary_report(incidents, buffer):
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=54,
        leftMargin=54,
        topMargin=95,
        bottomMargin=65
    )

    styles = getSampleStyleSheet()

    # Modify / Add custom styles
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=5
    )

    h1_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=15,
        textColor=colors.HexColor("#0052FF"), # Cobalt Blue
        spaceBefore=14,
        spaceAfter=8,
        keepWithNext=True
    )

    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9.5,
        leading=13.5,
        textColor=colors.HexColor("#334155")
    )

    body_bold_style = ParagraphStyle(
        "ReportBodyBold",
        parent=body_style,
        fontName="Helvetica-Bold"
    )

    footer_style = ParagraphStyle(
        "ReportFooter",
        parent=styles["Normal"],
        fontName="Helvetica-Oblique",
        fontSize=8.5,
        leading=11.5,
        alignment=1, # Centered
        textColor=colors.HexColor("#64748B")
    )

    elements = []

    # Dynamic Unique Report Number
    report_no = generate_unique_report_no()

    # Title Header Block
    elements.append(Paragraph("GLOBAL SCANS SUMMARY REPORT", title_style))
    elements.append(Paragraph("THREAT OPERATIONS COMMAND TELEMETRY LOG OVERVIEW", ParagraphStyle("Sub", parent=body_style, fontName="Helvetica-Bold", textColor=colors.HexColor("#64748B"), spaceAfter=15)))

    # Calculate metrics
    total_scans = len(incidents)
    phishing_count = sum(1 for inc in incidents if inc["status"] in ("PHISHING", "DEEPFAKE"))
    suspicious_count = sum(1 for inc in incidents if inc["status"] == "SUSPICIOUS")
    safe_count = sum(1 for inc in incidents if inc["status"] == "SAFE")

    url_count = sum(1 for inc in incidents if inc["vector_type"] == "URL")
    eml_count = sum(1 for inc in incidents if inc["vector_type"] == "Email")
    log_count = sum(1 for inc in incidents if inc["vector_type"] == "Log")
    media_count = sum(1 for inc in incidents if inc["vector_type"] == "Deepfake")

    # Metrics Summary Box
    metrics_data = [
        [
            Paragraph("<b>SUMMARY REF NUMBER</b>", ParagraphStyle("Hdr", parent=body_style, textColor=colors.white, fontName="Helvetica-Bold", fontSize=8)),
            Paragraph(f"<font color='#ffffff'><b>{report_no}</b></font>", ParagraphStyle("HdrVal", parent=body_style, textColor=colors.white, fontName="Helvetica-Bold", fontSize=8)),
            Paragraph("<b>TOTAL AUDITED SCANS</b>", ParagraphStyle("Hdr", parent=body_style, textColor=colors.white, fontName="Helvetica-Bold", fontSize=8)),
            Paragraph(f"<font color='#ffffff'><b>{total_scans}</b></font>", ParagraphStyle("HdrVal", parent=body_style, textColor=colors.white, fontName="Helvetica-Bold", fontSize=8)),
        ],
        [
            Paragraph("<b>Phishing/Deepfakes:</b>", body_style), Paragraph(f"<font color='#C53030'><b>{phishing_count}</b></font>", body_bold_style),
            Paragraph("<b>Legitimate & Safe:</b>", body_style), Paragraph(f"<font color='#2F855A'><b>{safe_count}</b></font>", body_bold_style)
        ],
        [
            Paragraph("<b>Suspicious Alerts:</b>", body_style), Paragraph(f"<font color='#DD6B20'><b>{suspicious_count}</b></font>", body_style),
            Paragraph("<b>URL Vectors Audited:</b>", body_style), Paragraph(str(url_count), body_style)
        ],
        [
            Paragraph("<b>Email (EML) Audited:</b>", body_style), Paragraph(str(eml_count), body_style),
            Paragraph("<b>Server Logs Audited:</b>", body_style), Paragraph(str(log_count), body_style)
        ],
        [
            Paragraph("<b>Deepfake Media Audited:</b>", body_style), Paragraph(str(media_count), body_style),
            Paragraph("<b>SYSTEM STATUS:</b>", body_style), Paragraph("<b>NOMINAL CORE</b>", body_style)
        ]
    ]

    metrics_table = Table(metrics_data, colWidths=[130, 122, 130, 122])
    metrics_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0052FF")), # Cobalt blue title bar in table
        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#F8FAFC")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#E2E8F0")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#EDF2F7")),
        ("PADDING", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    elements.append(metrics_table)
    elements.append(Spacer(1, 20))

    # Scans List Section
    elements.append(Paragraph("Operational Triage Incident Feed Logs", h1_style))
    elements.append(Paragraph("Below is the complete historical log of threat incidents audited by the SOC pipeline:", body_style))
    elements.append(Spacer(1, 10))

    # Draw table of scans
    table_headers = [
        Paragraph("<b>INCIDENT ID</b>", ParagraphStyle("Hdr", parent=body_style, textColor=colors.white, fontName="Helvetica-Bold", fontSize=8)),
        Paragraph("<b>TIMESTAMP</b>", ParagraphStyle("Hdr", parent=body_style, textColor=colors.white, fontName="Helvetica-Bold", fontSize=8)),
        Paragraph("<b>VECTOR</b>", ParagraphStyle("Hdr", parent=body_style, textColor=colors.white, fontName="Helvetica-Bold", fontSize=8)),
        Paragraph("<b>SCORE</b>", ParagraphStyle("Hdr", parent=body_style, textColor=colors.white, fontName="Helvetica-Bold", fontSize=8)),
        Paragraph("<b>STATUS badge</b>", ParagraphStyle("Hdr", parent=body_style, textColor=colors.white, fontName="Helvetica-Bold", fontSize=8))
    ]
    scan_rows = [table_headers]

    for idx, inc in enumerate(incidents):
        status_color = "#C53030" if inc["status"] in ("PHISHING", "DEEPFAKE") else ("#DD6B20" if inc["status"] == "SUSPICIOUS" else "#2F855A")
        # Alternating row colors
        row_bg = "#FFFFFF" if idx % 2 == 0 else "#F8FAFC"
        scan_rows.append([
            Paragraph(inc["id"][:8] + "...", body_style),
            Paragraph(inc["timestamp"][:16], body_style),
            Paragraph(inc["vector_type"], body_style),
            Paragraph(f"<b>{inc['threat_score']}%</b>", body_style),
            Paragraph(f"<font color='{status_color}'><b>{inc['status']}</b></font>", body_bold_style)
        ])

    scans_table = Table(scan_rows, colWidths=[90, 120, 95, 75, 124])
    
    table_styles = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0052FF")), # Cobalt blue header
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ("PADDING", (0, 0), (-1, -1), 6),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]
    
    # Alternating row colors mapping
    for idx in range(1, len(scan_rows)):
        bg_col = "#FFFFFF" if idx % 2 == 1 else "#F8FAFC"
        table_styles.append(("BACKGROUND", (0, idx), (-1, idx), colors.HexColor(bg_col)))
        
    scans_table.setStyle(TableStyle(table_styles))
    elements.append(scans_table)

    # Spacer before footer
    elements.append(Spacer(1, 30))

    # Footer Signature
    elements.append(Paragraph("<b>THREAT COMMAND CENTER // MULTI-VECTOR SECURITY OPERATIONS CENTER</b><br/>"
                             "Incident Lead Architect: <i>Aksht Rana</i> // Email: align.akshtrana@gmail.com // LinkedIn: https://www.linkedin.com/in/aksht-rana-009515373/", footer_style))

    # Build the document, applying top banner on each page
    doc.build(elements, onFirstPage=lambda c, d: draw_header_footer(c, d, True), onLaterPages=lambda c, d: draw_header_footer(c, d, True))
