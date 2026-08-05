from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

def generate_pdf_report(incident, evidences, remediations, buffer):
    # Setup document with 54pt (0.75 in) margins
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=54,
        leftMargin=54,
        topMargin=54,
        bottomMargin=54
    )

    styles = getSampleStyleSheet()

    # Modify / Add custom styles
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=24,
        leading=28,
        textColor=colors.HexColor("#1A365D"),
        spaceAfter=15
    )

    h1_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=15,
        leading=18,
        textColor=colors.HexColor("#2B6CB0"),
        spaceBefore=15,
        spaceAfter=10,
        keepWithNext=True
    )

    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#2D3748")
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
        fontSize=9,
        leading=12,
        alignment=1, # Centered
        textColor=colors.HexColor("#718096")
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

    # 1. Title Page Header
    elements.append(Paragraph("SECURITY INCIDENT REPORT", title_style))
    elements.append(Paragraph("AUTOMATED MULTI-MODAL THREAT INTELLIGENCE ANALYSIS", ParagraphStyle("Sub", parent=body_style, fontName="Helvetica-Bold", textColor=colors.HexColor("#4A5568"), spaceAfter=15)))

    # Thin Divider Line
    divider = Table([[""]], colWidths=[504])
    divider.setStyle(TableStyle([
        ("LINEABOVE", (0, 0), (-1, -1), 2, colors.HexColor("#2B6CB0")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
    ]))
    elements.append(divider)
    elements.append(Spacer(1, 15))

    # 2. Incident Metadata Table
    metadata_data = [
        [
            Paragraph("<b>Incident ID:</b>", body_style),
            Paragraph(incident["id"], body_style),
            Paragraph("<b>Vector Type:</b>", body_style),
            Paragraph(incident["vector_type"].upper(), body_style)
        ],
        [
            Paragraph("<b>Timestamp:</b>", body_style),
            Paragraph(incident["timestamp"], body_style),
            Paragraph("<b>Threat Severity:</b>", body_style),
            Paragraph(f"<font color='{sev_color}'><b>{sev}</b></font>", body_style)
        ],
        [
            Paragraph("<b>Threat Score:</b>", body_style),
            Paragraph(f"<b>{incident['threat_score']}</b>", body_style),
            Paragraph("<b>Status:</b>", body_style),
            Paragraph(incident["status"], body_bold_style)
        ]
    ]

    metadata_table = Table(metadata_data, colWidths=[90, 162, 90, 162])
    metadata_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F7FAFC")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#E2E8F0")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#EDF2F7")),
        ("PADDING", (0, 0), (-1, -1), 10),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    elements.append(metadata_table)
    elements.append(Spacer(1, 15))

    # Target Input Section
    elements.append(Paragraph(f"<b>Target Analyzed:</b> {incident['target_input']}", body_style))
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

        header_table = Table(header_table_data, colWidths=[100, 404])
        header_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#E2E8F0")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#EDF2F7")),
            ("PADDING", (0, 0), (-1, -1), 6),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        elements.append(header_table)
        elements.append(Spacer(1, 15))

    # Filter out raw email metadata from general evidences list
    email_keys = ["Email Sender", "Email Recipient", "Email CC", "Email Date", "Email Reply-To", "Email Message-ID", "Email Subject"]
    general_evidences = [ev for ev in evidences if ev["key"] not in email_keys]

    # 3. Evidence Breakdown Section
    elements.append(Paragraph("Evidence Breakdown (IoCs & Indicators)", h1_style))
    elements.append(Paragraph("The system identified the following threat indicators during analysis:", body_style))
    elements.append(Spacer(1, 10))

    def get_detailed_description(key, value):
        val_lower = value.lower()
        key_lower = key.lower()
        
        if "https" in val_lower or "insecure http" in val_lower:
            return ("Website is not using secure HTTPS encryption. Attackers commonly use such techniques "
                    "to manipulate users, steal credentials, distribute malware, or impersonate trusted services. "
                    "URLs containing these indicators should always be treated with caution until verified manually.")
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
            elements.append(Paragraph(f"• {desc}", bullet_style))
    else:
        elements.append(Paragraph("• No suspicious threat indicators or compromises detected.", bullet_style))

    elements.append(Spacer(1, 15))

    # 4. Remediation Recommendations Section
    elements.append(Paragraph("Actionable Remediation Recommendations", h1_style))
    elements.append(Paragraph("The Security Operations Center recommends taking the following containment and recovery actions immediately:", body_style))
    elements.append(Spacer(1, 10))

    if remediations:
        for rem in remediations:
            elements.append(Paragraph(f"• {rem['description']}", bullet_style))
    else:
        elements.append(Paragraph("• No remediation actions required. The target is classified as safe.", bullet_style))

    # Page Break for footer spacing
    elements.append(Spacer(1, 30))

    # 5. Footer Signature
    elements.append(Paragraph("This report was generated automatically by the PHISHING & DEEPFAKE THREAT DETECTION platform.<br/>Developed by Aksht Rana", footer_style))

    doc.build(elements)
