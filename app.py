from flask import Flask, render_template, request, jsonify, send_file
import os
import logging
from datetime import datetime
from io import BytesIO

# =========================
# PDF IMPORTS
# =========================

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak
)

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet

# =========================
# CUSTOM MODULES
# =========================

from features.feature_extraction import extract_features
from rules.rule_engine import check_phishing
from alerts.alert_manager import generate_alert

# =========================
# FLASK APP
# =========================

app = Flask(__name__)

# =========================
# LOGGING SETUP
# =========================

os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    filename="logs/phishing.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# =========================
# HOME PAGE
# =========================

@app.route("/")
def home():
    return render_template("index.html")

# =========================
# ANALYZE URL
# =========================

@app.route("/analyze", methods=["POST"])
def analyze():

    try:

        data = request.get_json()

        if not data:
            return jsonify({
                "status": "error",
                "message": "No data received"
            }), 400

        url = data.get("url", "").strip()

        if not url:

            return jsonify({
                "status": "error",
                "message": "URL is required"
            }), 400

        # =========================
        # AUTO FIX URL
        # =========================

        if not url.startswith("http://") and not url.startswith("https://"):
            url = "https://" + url

        # =========================
        # FEATURE EXTRACTION
        # =========================

        features = extract_features(url)

        # =========================
        # RULE ENGINE DETECTION
        # =========================

        status, reasons, severity = check_phishing(features)

        # =========================
        # SCORE CALCULATION
        # =========================

        if severity.upper() == "HIGH":
            score = 85

        elif severity.upper() == "MEDIUM":
            score = 55

        else:
            score = 15

        # =========================
        # PREVENTION TIPS
        # =========================

        prevention = [

            "Verify domain spelling carefully",

            "Avoid clicking unknown email links",

            "Enable Multi-Factor Authentication",

            "Never enter passwords on suspicious websites",

            "Check HTTPS certificate validity",

            "Use antivirus and browser protection",

            "Keep browser updated regularly",

            "Avoid downloading unknown attachments"
        ]

        # =========================
        # TERMINAL ALERT
        # =========================

        try:

            generate_alert(
                url,
                status,
                reasons,
                severity
            )

        except Exception as alert_error:

            print("ALERT ERROR:", alert_error)

        # =========================
        # FILE LOGGING
        # =========================

        log_message = f"""
        URL: {url}
        STATUS: {status}
        SEVERITY: {severity}
        SCORE: {score}
        """

        logging.info(log_message)

        # =========================
        # SUCCESS RESPONSE
        # =========================

        return jsonify({

            "url": url,

            "status": status,

            "risk": severity,

            "score": score,

            "reasons": reasons,

            "prevention": prevention,

            "timestamp": datetime.now().strftime(
                "%d-%m-%Y %H:%M:%S"
            )

        })

    except Exception as e:

        logging.error(f"ANALYZE ERROR: {str(e)}")

        return jsonify({

            "status": "error",

            "message": str(e)

        }), 500


# =========================
# DOWNLOAD PDF REPORT
# =========================

@app.route("/download-report", methods=["POST"])
def download_report():

    try:

        data = request.get_json()

        buffer = BytesIO()

        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=40,
            leftMargin=40,
            topMargin=40,
            bottomMargin=40
        )

        styles = getSampleStyleSheet()

        elements = []

        # =========================================
        # COLORS
        # =========================================

        RED = colors.HexColor("#c40000")
        DARK = colors.HexColor("#121212")
        LIGHT = colors.HexColor("#f5f5f5")
        GOLD = colors.HexColor("#c28b00")
        GREEN = colors.HexColor("#0d7a3a")

        # =========================================
        # TITLE
        # =========================================

        title = Paragraph(
            """
            <font size=30 color='#c40000'>
            <b>PHISHING DETECTOR</b>
            </font>
            """,
            styles["Title"]
        )

        elements.append(title)

        elements.append(Spacer(1, 30))

        # =========================================
        # WARNING BOX
        # =========================================

        warning_table = Table(

            [

                [
                    Paragraph(
                        """
                        <font size=18 color='white'>
                        <b>⚠ CRITICAL CYBERSECURITY WARNING</b>
                        </font>
                        """,
                        styles["BodyText"]
                    )
                ],

                [
                    Paragraph(
                        """
                        <font size=12 color='white'>

                        Phishing attacks are responsible for credential theft,
                        financial fraud, ransomware infections,
                        identity compromise, and unauthorized access incidents globally.

                        Cybercriminals frequently impersonate trusted banking systems,
                        educational portals, government services,
                        and social media platforms to manipulate users into
                        revealing passwords, OTPs, financial information,
                        and confidential personal data.

                        These attacks continue to increase worldwide and remain
                        one of the most dangerous forms of cybercrime affecting
                        students, employees, institutions, and businesses.

                        </font>
                        """,
                        styles["BodyText"]
                    )
                ]

            ],

            colWidths=[520]

        )

        warning_table.setStyle(TableStyle([

            ("BACKGROUND", (0, 0), (-1, -1), colors.darkred),

            ("BOX", (0, 0), (-1, -1), 2, colors.red),

            ("INNERGRID", (0, 0), (-1, -1), 1, colors.red),

            ("LEFTPADDING", (0, 0), (-1, -1), 20),

            ("RIGHTPADDING", (0, 0), (-1, -1), 20),

            ("TOPPADDING", (0, 0), (-1, -1), 18),

            ("BOTTOMPADDING", (0, 0), (-1, -1), 18),

            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),

        ]))

        elements.append(warning_table)

        elements.append(Spacer(1, 40))

        # =========================================
        # INTRODUCTION
        # =========================================

        intro = f"""
        <font size=12>

        This AI powered phishing detection report was generated
        using cybersecurity analysis techniques including URL inspection,
        phishing heuristic evaluation, suspicious domain identification,
        redirection analysis, and behavioral security intelligence systems.

        <br/><br/>

        The submitted website was analyzed to determine whether
        it demonstrates characteristics commonly associated with
        phishing attacks, fake login systems, scam campaigns,
        impersonation portals, credential harvesting attempts,
        or malicious cyber activity.

        <br/><br/>

        Cybercriminals continuously evolve their techniques and create
        highly deceptive phishing pages that visually imitate trusted
        services in order to steal passwords, financial information,
        banking credentials, institutional access, and personal data.

        <br/><br/>

        <b>Generated By:</b> Aksht Rana

        <br/><br/>

        <b>Generated On:</b>
        {datetime.now().strftime("%d-%m-%Y %H:%M:%S")}

        </font>
        """

        elements.append(
            Paragraph(intro, styles["BodyText"])
        )

        elements.append(PageBreak())

        # =========================================
        # THREAT SUMMARY
        # =========================================

        heading = Paragraph(
            """
            <font size=24 color='#c40000'>
            <b>Executive Threat Summary</b>
            </font>
            """,
            styles["Heading1"]
        )

        elements.append(heading)

        elements.append(Spacer(1, 25))

        summary_text = f"""
        <font size=12>

        The analyzed resource:

        <br/><br/>

        <b>{data.get("url", "N/A")}</b>

        <br/><br/>

        was processed through multiple phishing detection mechanisms
        designed to identify suspicious indicators linked with
        malicious websites and online fraud campaigns.

        <br/><br/>

        Detection systems evaluated several parameters including:

        <br/><br/>

        • URL complexity  
        • Domain reputation  
        • HTTPS security indicators  
        • Suspicious redirects  
        • Phishing keywords  
        • Impersonation behavior  
        • Fake authentication systems  
        • Malicious formatting patterns  

        <br/><br/>

        <b>Status:</b> {data.get("status", "UNKNOWN")}

        <br/><br/>

        <b>Threat Severity:</b> {data.get("risk", "UNKNOWN")}

        <br/><br/>

        <b>Security Score:</b> {data.get("score", 0)}%

        <br/><br/>

        Users should avoid trusting websites that attempt
        to create urgency, request sensitive information unexpectedly,
        imitate trusted services, or manipulate users into bypassing
        standard security procedures.

        </font>
        """

        elements.append(
            Paragraph(summary_text, styles["BodyText"])
        )

        elements.append(Spacer(1, 35))

        # =========================================
        # TABLE
        # =========================================

        table_data = [

            ["Security Field", "Analysis Result"],

            ["Analyzed URL", data.get("url", "N/A")],

            ["Detection Status", data.get("status", "N/A")],

            ["Threat Severity", data.get("risk", "N/A")],

            ["Security Score", f"{data.get('score', 0)}%"],

            ["Generated Time", data.get("timestamp", "N/A")]

        ]

        table = Table(
            table_data,
            colWidths=[220, 280]
        )

        table.setStyle(TableStyle([

            ("BACKGROUND", (0, 0), (-1, 0), RED),

            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),

            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),

            ("BOTTOMPADDING", (0, 0), (-1, 0), 12),

            ("BACKGROUND", (0, 1), (-1, -1), LIGHT),

            ("GRID", (0, 0), (-1, -1), 1, colors.black),

            ("TEXTCOLOR", (0, 1), (-1, -1), DARK)

        ]))

        elements.append(table)

        elements.append(Spacer(1, 30))

        # =========================================
        # REASONS
        # =========================================

        reason_title = Paragraph(
            """
            <font size=20 color='#c28b00'>
            <b>Threat Indicators Detected</b>
            </font>
            """,
            styles["Heading2"]
        )

        elements.append(reason_title)

        elements.append(Spacer(1, 15))

        reasons = data.get("reasons", [])

        if not reasons:
            reasons = ["No suspicious indicators detected"]

        for reason in reasons:

            elements.append(
                Paragraph(
                    f"""
                    <font size=12>
                    • {reason}
                    </font>
                    """,
                    styles["BodyText"]
                )
            )

            elements.append(Spacer(1, 8))

        elements.append(PageBreak())

        # =========================================
        # PHISHING EDUCATION
        # =========================================

        edu_title = Paragraph(
            """
            <font size=24 color='#c40000'>
            <b>Understanding Modern Phishing Attacks</b>
            </font>
            """,
            styles["Heading1"]
        )

        elements.append(edu_title)

        elements.append(Spacer(1, 25))

        edu_text = """
        <font size=12>

        Phishing attacks are designed to deceive users into revealing
        confidential information by impersonating trusted organizations.

        <br/><br/>

        Modern attackers create fake login pages,
        fraudulent payment systems,
        counterfeit university portals,
        and cloned social media websites
        to manipulate victims.

        <br/><br/>

        Common phishing techniques include:

        <br/><br/>

        • Fake banking portals  
        • Credential harvesting forms  
        • Fraudulent email campaigns  
        • Scam advertisements  
        • OTP theft systems  
        • Malicious downloads  
        • Social engineering attacks  

        <br/><br/>

        Cybercriminals frequently exploit fear,
        urgency, and emotional pressure
        to force victims into making rushed decisions.

        Users should always verify URLs carefully before entering
        passwords, payment information, institutional credentials,
        or personal information online.

        </font>
        """

        elements.append(
            Paragraph(edu_text, styles["BodyText"])
        )

        elements.append(PageBreak())

        # =========================================
        # SAFETY SECTION
        # =========================================

        safety_heading = Paragraph(
            """
            <font size=24 color='#0d7a3a'>
            <b>Cybersecurity Prevention Guidelines</b>
            </font>
            """,
            styles["Heading1"]
        )

        elements.append(safety_heading)

        elements.append(Spacer(1, 20))

        safety_data = [

            ["Recommended Actions", "Unsafe Practices"],

            ["Enable MFA Authentication", "Click unknown links"],

            ["Verify domains carefully", "Share passwords online"],

            ["Use antivirus software", "Ignore browser warnings"],

            ["Update browsers regularly", "Download unknown files"],

            ["Check HTTPS security", "Trust random popups"],

            ["Monitor account activity", "Reuse weak passwords"]

        ]

        safety_table = Table(
            safety_data,
            colWidths=[250, 250]
        )

        safety_table.setStyle(TableStyle([

            ("BACKGROUND", (0, 0), (-1, 0), RED),

            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),

            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),

            ("BACKGROUND", (0, 1), (0, -1), colors.lightgreen),

            ("BACKGROUND", (1, 1), (1, -1), colors.pink),

            ("GRID", (0, 0), (-1, -1), 1, colors.black)

        ]))

        elements.append(safety_table)

        elements.append(Spacer(1, 40))

        final_note = Paragraph(
            """
            <font size=16 color='#c40000'>
            <b>
            Stay Alert. Stay Secure.
            Cyber Awareness Saves Digital Lives.
            </b>
            </font>
            """,
            styles["Heading2"]
        )

        elements.append(final_note)

        # =========================================
        # BUILD PDF
        # =========================================

        doc.build(elements)

        buffer.seek(0)

        return send_file(

            buffer,

            as_attachment=True,

            download_name="PHISHING_DETECTOR_REPORT.pdf",

            mimetype="application/pdf"

        )

    except Exception as e:

        logging.error(f"PDF ERROR: {str(e)}")

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


# =========================
# RUN SERVER
# =========================

if __name__ == "__main__":

    print("\n===================================")
    print("SCAMDETECT SERVER STARTED")
    print("OPEN IN BROWSER:")
    print("http://127.0.0.1:5050")
    print("===================================\n")

    app.run(
        host="127.0.0.1",
        port=5050,
        debug=True,
        threaded=True
    )