import re
import hashlib
from email import message_from_file
from email.utils import parseaddr

# Brands to check display-name spoofing against
BRANDS = ["paypal", "facebook", "instagram", "amazon", "microsoft", "google", "apple"]

def parse_eml(file_path):
    with open(file_path, "r", errors="ignore") as f:
        msg = message_from_file(f)

    # 1. Extract basic metadata
    subject = msg.get("Subject", "No Subject")
    from_header = msg.get("From", "")
    to_header = msg.get("To", "")
    cc_header = msg.get("Cc", "")
    date_header = msg.get("Date", "")
    reply_to_header = msg.get("Reply-To", "")
    message_id_header = msg.get("Message-ID", "")

    display_name, sender_email = parseaddr(from_header)
    sender_domain = sender_email.split("@")[-1].lower() if "@" in sender_email else ""

    # 2. Display name spoofing check
    is_spoofed = False
    spoof_details = ""
    display_name_lower = display_name.lower()
    for brand in BRANDS:
        if brand in display_name_lower:
            # If display name contains a brand, but the sender domain is not official
            if not (sender_domain == f"{brand}.com" or sender_domain.endswith(f".{brand}.com")):
                is_spoofed = True
                spoof_details = f"Display name '{display_name}' matches brand '{brand}', but domain '{sender_domain}' is unauthorized"
                break

    # 3. Authentication Header Checks (SPF, DKIM, DMARC)
    auth_results = msg.get_all("Authentication-Results", [])
    spf = "NONE"
    dkim = "NONE"
    dmarc = "NONE"

    auth_string = " ".join(auth_results).lower()
    if auth_results:
        # Simple regex matching for status
        spf_match = re.search(r"spf=(pass|fail|softfail|neutral|none)", auth_string)
        dkim_match = re.search(r"dkim=(pass|fail|none)", auth_string)
        dmarc_match = re.search(r"dmarc=(pass|fail|none)", auth_string)

        if spf_match: spf = spf_match.group(1).upper()
        if dkim_match: dkim = dkim_match.group(1).upper()
        if dmarc_match: dmarc = dmarc_match.group(1).upper()

    # 4. Extract Body & Embedded URLs
    body_text = ""
    body_html = ""
    urls = set()

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))

            if "attachment" not in content_disposition:
                payload = part.get_payload(decode=True)
                if payload:
                    decoded = payload.decode(errors="ignore")
                    if content_type == "text/plain":
                        body_text += decoded
                    elif content_type == "text/html":
                        body_html += decoded
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            body_text = payload.decode(errors="ignore")

    # Combine text for URL extraction
    combined_body = body_text + " " + body_html
    # URL extraction pattern
    url_pattern = re.compile(r'https?://[^\s<>"\']+')
    for match in url_pattern.findall(combined_body):
        # Clean trailing punctuation
        clean_url = match.rstrip(".,;:-?)!")
        urls.add(clean_url)

    # 5. Attachment inspection
    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            content_disposition = str(part.get("Content-Disposition"))
            if "attachment" in content_disposition:
                filename = part.get_filename() or "unknown_file"
                payload = part.get_payload(decode=True)
                if payload:
                    sha256 = hashlib.sha256(payload).hexdigest()
                    size = len(payload)
                    content_type = part.get_content_type()

                    # Macro indicators
                    file_ext = filename.split(".")[-1].lower() if "." in filename else ""
                    has_macros = file_ext in ["docm", "xlsm", "pptm", "dotm", "xltm"] or file_ext in ["vbs", "js", "bat", "ps1", "exe"]

                    attachments.append({
                        "filename": filename,
                        "size": size,
                        "sha256": sha256,
                        "content_type": content_type,
                        "has_macros": has_macros
                    })

    return {
        "subject": subject,
        "from": from_header,
        "to": to_header,
        "cc": cc_header,
        "date": date_header,
        "reply_to": reply_to_header,
        "message_id": message_id_header,
        "display_name": display_name,
        "sender_email": sender_email,
        "sender_domain": sender_domain,
        "display_name_spoofed": is_spoofed,
        "display_name_spoof_details": spoof_details,
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "body_text": body_text if body_text else body_html, # Fallback to HTML body
        "urls": list(urls),
        "attachments": attachments
    }
