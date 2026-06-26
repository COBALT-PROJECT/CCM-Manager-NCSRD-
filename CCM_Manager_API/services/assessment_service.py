import json
import logging
import math
import os
from datetime import datetime, timedelta
from uuid import uuid4

from jsonschema import validate
from reportlab.lib.colors import Color, HexColor, black, white
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm, mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from reportlab.platypus import Paragraph

# Assuming these are available in your environment
from db import certificates_col, collection, schemes_col, toes_col
from services.ledger import ledger_auth_context, send_to_ledger

# ── Configuration ───────────────────────────────────────────────────

SCHEMA_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "schemas",
    "ASSESSMENT_SCHEMA.json",
)

with open(SCHEMA_PATH) as schema_file:
    ASSESSMENT_SCHEMA = json.load(schema_file)

# Directory to save the generated PDFs
PDF_OUTPUT_DIR = os.getenv("PDF_OUTPUT_DIR", os.getcwd())

# ── Colour Palette ──────────────────────────────────────────────────

NAVY       = HexColor("#0B1D3A")
DARK_BLUE  = HexColor("#132D5E")
ACCENT     = HexColor("#1B6FEF")
GOLD       = HexColor("#C9A84C")
GOLD_LIGHT = HexColor("#E8D48B")
LIGHT_GREY = HexColor("#E8EDF3")
MID_GREY   = HexColor("#8899AA")
WHITE      = white
SEAL_RING  = HexColor("#1A4FA0")


# ── Certificate JSON Builder ────────────────────────────────────────

def _build_certificate(data, toe_record, toe_id, scheme_id):
    cert_uuid = str(uuid4())
    now = datetime.utcnow()
    valid_to = now + timedelta(days=365)

    return {
        "certification": {
            "certification_id": cert_uuid,
            "name": f"Certificate for {toe_record.get('name')}",
            "version": "1.0",
            "certification_scheme": scheme_id,
            "certifying_body": {
                "name": "COBALT Automated CA",
                "accreditation_id": "COBALT-ACC-001",
                "contact_info": {
                    "email": "ca@cobalt.eu",
                    "website": "https://cobalt.eu",
                },
            },
            "applicant": {
                "organization_name": "ToE Owner",
                "organization_id": "ORG-001",
                "contact_person": {"name": "Admin", "email": "admin@org.com"},
            },
            "target_of_evaluation": {
                "toe_name": toe_record.get("name"),
                "toe_uuid": toe_id,
                "description": "Automated Certification via CCM Manager",
            },
            "certification_scope": {
                "environment": "Cloud",
                "deployment_model": "SaaS",
                "services_included": ["Core Service"],
            },
            "assessment": {
                "assessment_id": data.get("id"),
                "assessment_date": now.strftime("%Y-%m-%d"),
                "assessment_result": "PASS",
                "evidence": [data.get("evidence_id")],
            },
            "certification_decision": {
                "decision_date": now.strftime("%Y-%m-%d"),
                "decision_status": "INITIATE",
                "certification_level": "Basic",
                "validity_period": {
                    "start_date": now.strftime("%Y-%m-%d"),
                    "end_date": valid_to.strftime("%Y-%m-%d"),
                },
            },
            "certificate_issuance": {
                "certificate_serial": str(uuid4().hex),
                "issue_date": now.strftime("%Y-%m-%d"),
                "issued_by": "COBALT Automated CA",
            },
            "history": [
                {
                    "event": "Certificate Automatically Generated with INITIATE status",
                    "date": now.strftime("%Y-%m-%d"),
                }
            ],
        }
    }


# ── PDF Drawing Helpers ─────────────────────────────────────────────

def draw_rounded_rect(c, x, y, w, h, r, fill=None, stroke=None, stroke_width=0.5):
    p = c.beginPath()
    p.roundRect(x, y, w, h, r)
    if fill:
        c.setFillColor(fill)
    if stroke:
        c.setStrokeColor(stroke)
        c.setLineWidth(stroke_width)
    if fill and stroke:
        c.drawPath(p, fill=1, stroke=1)
    elif fill:
        c.drawPath(p, fill=1, stroke=0)
    elif stroke:
        c.drawPath(p, fill=0, stroke=1)


def draw_shield_icon(c, cx, cy, size):
    s = size
    p = c.beginPath()
    p.moveTo(cx, cy + s * 0.55)
    p.curveTo(cx - s * 0.45, cy + s * 0.35, cx - s * 0.5, cy - s * 0.1, cx - s * 0.5, cy - s * 0.3)
    p.lineTo(cx, cy - s * 0.55)
    p.lineTo(cx + s * 0.5, cy - s * 0.3)
    p.curveTo(cx + s * 0.5, cy - s * 0.1, cx + s * 0.45, cy + s * 0.35, cx, cy + s * 0.55)
    p.close()
    c.setFillColor(ACCENT)
    c.drawPath(p, fill=1, stroke=0)
    
    # checkmark
    c.setStrokeColor(WHITE)
    c.setLineWidth(1.6)
    c.setLineCap(1)
    c.line(cx - s * 0.15, cy - s * 0.05, cx - s * 0.02, cy - s * 0.2)
    c.line(cx - s * 0.02, cy - s * 0.2, cx + s * 0.2, cy + s * 0.15)


def draw_seal(c, cx, cy, radius):
    n_points = 36
    c.saveState()
    c.setFillColor(GOLD)
    p = c.beginPath()
    for i in range(n_points * 2):
        angle = math.pi * i / n_points
        r = radius if i % 2 == 0 else radius * 0.88
        px = cx + r * math.cos(angle)
        py = cy + r * math.sin(angle)
        if i == 0:
            p.moveTo(px, py)
        else:
            p.lineTo(px, py)
    p.close()
    c.drawPath(p, fill=1, stroke=0)

    c.setFillColor(NAVY)
    c.circle(cx, cy, radius * 0.78, fill=1, stroke=0)
    
    c.setStrokeColor(GOLD)
    c.setLineWidth(1.2)
    c.circle(cx, cy, radius * 0.68, fill=0, stroke=1)
    c.circle(cx, cy, radius * 0.62, fill=0, stroke=1)

    c.setFillColor(GOLD_LIGHT)
    c.setFont("Helvetica-Bold", 5.8)
    ring_text_upper = "COBALT CERTIFICATION AUTHORITY"
    ring_r = radius * 0.65
    total_angle = len(ring_text_upper) * 0.105
    start = math.pi / 2 + total_angle / 2
    for i, ch in enumerate(ring_text_upper):
        a = start - i * 0.105
        tx = cx + ring_r * math.cos(a)
        ty = cy + ring_r * math.sin(a)
        c.saveState()
        c.translate(tx, ty)
        c.rotate(math.degrees(a) - 90)
        c.drawCentredString(0, 0, ch)
        c.restoreState()

    ring_text_lower = "AUTOMATED  ASSURANCE"
    start_low = -math.pi / 2 + len(ring_text_lower) * 0.105 / 2
    for i, ch in enumerate(ring_text_lower):
        a = start_low - i * 0.105
        tx = cx + ring_r * math.cos(a)
        ty = cy + ring_r * math.sin(a)
        c.saveState()
        c.translate(tx, ty)
        c.rotate(math.degrees(a) + 90)
        c.drawCentredString(0, 0, ch)
        c.restoreState()

    draw_shield_icon(c, cx, cy, radius * 0.35)
    c.restoreState()


def draw_decorative_border(c, width, height):
    margin = 18 * mm
    inner = 21 * mm

    c.setStrokeColor(GOLD)
    c.setLineWidth(2.0)
    c.rect(margin, margin, width - 2 * margin, height - 2 * margin)

    c.setStrokeColor(GOLD_LIGHT)
    c.setLineWidth(0.6)
    c.rect(inner, inner, width - 2 * inner, height - 2 * inner)

    diamond_size = 3.5 * mm
    corners = [
        (margin, margin),
        (margin, height - margin),
        (width - margin, margin),
        (width - margin, height - margin),
    ]

    for (ox, oy) in corners:
        p = c.beginPath()
        p.moveTo(ox, oy + diamond_size)
        p.lineTo(ox + diamond_size, oy)
        p.lineTo(ox, oy - diamond_size)
        p.lineTo(ox - diamond_size, oy)
        p.close()
        c.setFillColor(GOLD)
        c.drawPath(p, fill=1, stroke=0)


def draw_guilloche_band(c, x, y, w, h):
    c.saveState()
    c.setStrokeColor(Color(0.1, 0.35, 0.75, alpha=0.12))
    c.setLineWidth(0.4)
    for offset in range(0, 3):
        p = c.beginPath()
        for px in range(int(x), int(x + w), 2):
            py = y + h / 2 + math.sin((px + offset * 20) * 0.06) * (h * 0.35)
            if px == int(x):
                p.moveTo(px, py)
            else:
                p.lineTo(px, py)
        c.drawPath(p, fill=0, stroke=1)
    c.restoreState()


# ── PDF Generator ───────────────────────────────────────────────────

def generate_certificate(payload, output_path):
    cert = payload["certificate"]["certification"]
    toe = cert["target_of_evaluation"]
    applicant = cert["applicant"]
    decision = cert["certification_decision"]
    scope = cert["certification_scope"]
    issuance = cert["certificate_issuance"]
    body = cert["certifying_body"]
    assessment = cert["assessment"]

    width, height = A4
    c = canvas.Canvas(output_path, pagesize=A4)
    c.setTitle("COBALT Cybersecurity Certification")
    c.setAuthor("COBALT Automated CA")

    # ── PAGE 1: CERTIFICATE ─────────────────────────────────────────
    
    c.setFillColor(NAVY)
    c.rect(0, 0, width, height, fill=1, stroke=0)

    panel_m = 14 * mm
    draw_rounded_rect(
        c, panel_m, panel_m, width - 2 * panel_m, height - 2 * panel_m,
        4 * mm, fill=HexColor("#0E2349")
    )

    draw_decorative_border(c, width, height)
    draw_guilloche_band(c, 25 * mm, height - 38 * mm, width - 50 * mm, 8 * mm)
    draw_guilloche_band(c, 25 * mm, 28 * mm, width - 50 * mm, 8 * mm)

    y = height - 52 * mm
    c.setFillColor(GOLD)
    c.setFont("Helvetica-Bold", 32)
    c.drawCentredString(width / 2, y, "COBALT")
    y -= 9 * mm

    c.setFillColor(GOLD_LIGHT)
    c.setFont("Helvetica", 9)
    c.drawCentredString(width / 2, y, "CONTINUOUS  OBSERVATION  ·  BENCHMARKING  ·  AUDITING  ·  LEVERAGING  TRUST")
    y -= 14 * mm

    c.setStrokeColor(GOLD)
    c.setLineWidth(0.8)
    line_w = 100 * mm
    c.line(width / 2 - line_w / 2, y, width / 2 + line_w / 2, y)
    y -= 12 * mm

    c.setFillColor(WHITE)
    c.setFont("Helvetica-Bold", 22)
    c.drawCentredString(width / 2, y, "CERTIFICATE OF COMPLIANCE")
    y -= 8 * mm

    badge_w = 42 * mm
    badge_h = 8 * mm
    badge_x = width / 2 - badge_w / 2
    draw_rounded_rect(c, badge_x, y - badge_h + 1 * mm, badge_w, badge_h, 3 * mm, fill=ACCENT)
    
    c.setFillColor(WHITE)
    c.setFont("Helvetica-Bold", 10)
    c.drawCentredString(width / 2, y - badge_h + 3.5 * mm, f"LEVEL: {decision['certification_level'].upper()}")
    y -= 20 * mm

    c.setFillColor(LIGHT_GREY)
    c.setFont("Helvetica", 10)
    c.drawCentredString(width / 2, y, "This is to certify that the Target of Evaluation")
    y -= 14 * mm

    c.setFillColor(GOLD)
    c.setFont("Helvetica-Bold", 20)
    c.drawCentredString(width / 2, y, toe["toe_name"])
    y -= 8 * mm

    ul_w = 90 * mm
    c.setStrokeColor(GOLD_LIGHT)
    c.setLineWidth(0.5)
    c.line(width / 2 - ul_w / 2, y, width / 2 + ul_w / 2, y)
    y -= 10 * mm

    c.setFillColor(LIGHT_GREY)
    c.setFont("Helvetica", 10)
    c.drawCentredString(width / 2, y, f"operated by  {applicant['organization_name']}  (ID: {applicant['organization_id']})")
    y -= 8 * mm

    c.drawCentredString(width / 2, y, "has successfully completed assessment under scheme")
    y -= 8 * mm

    c.setFillColor(ACCENT)
    c.setFont("Helvetica-Bold", 9.5)
    c.drawCentredString(width / 2, y, cert["certification_scheme"])
    y -= 8 * mm

    c.setFillColor(LIGHT_GREY)
    c.setFont("Helvetica", 10)
    c.drawCentredString(width / 2, y, f"and is hereby granted  {decision['decision_status'].upper()}  certification status.")
    y -= 18 * mm

    box_w = 130 * mm
    box_h = 22 * mm
    box_x = width / 2 - box_w / 2
    draw_rounded_rect(
        c, box_x, y - box_h, box_w, box_h, 3 * mm,
        fill=HexColor("#0A1A35"), stroke=ACCENT, stroke_width=0.6
    )

    c.setFillColor(ACCENT)
    c.setFont("Helvetica-Bold", 8)
    c.drawString(box_x + 5 * mm, y - 5.5 * mm, "CERTIFICATION SCOPE")

    c.setFillColor(LIGHT_GREY)
    c.setFont("Helvetica", 8.5)
    details_y = y - 11 * mm
    c.drawString(box_x + 5 * mm, details_y, f"Environment: {scope['environment']}")
    c.drawString(box_x + 50 * mm, details_y, f"Deployment: {scope['deployment_model']}")
    c.drawString(box_x + 95 * mm, details_y, f"Services: {', '.join(scope['services_included'])}")
    details_y -= 5.5 * mm
    c.drawString(box_x + 5 * mm, details_y, f"Assessment Result: {assessment['assessment_result']}")
    c.drawString(box_x + 50 * mm, details_y, f"Assessment Date: {assessment['assessment_date']}")
    
    y -= box_h + 14 * mm

    c.setFillColor(WHITE)
    c.setFont("Helvetica-Bold", 10)
    c.drawCentredString(width / 2, y, "VALIDITY PERIOD")
    y -= 7 * mm

    vp = decision["validity_period"]
    c.setFillColor(GOLD_LIGHT)
    c.setFont("Helvetica", 11)
    c.drawCentredString(width / 2, y, f'{vp["start_date"]}   —   {vp["end_date"]}')
    y -= 18 * mm

    seal_cx = width / 2
    seal_cy = y - 5 * mm
    draw_seal(c, seal_cx, seal_cy, 22 * mm)
    y -= 52 * mm

    c.setFillColor(MID_GREY)
    c.setFont("Helvetica", 7.5)
    c.drawCentredString(width / 2, y, f"Issued by: {issuance['issued_by']}  |  Date: {issuance['issue_date']}  |  Serial: {issuance['certificate_serial']}")
    y -= 5 * mm
    c.drawCentredString(width / 2, y, f"Certification ID: {cert['certification_id']}")

    # ── PAGE 2: TECHNICAL ANNEX ─────────────────────────────────────
    
    c.showPage()
    
    c.setFillColor(HexColor("#F5F7FA"))
    c.rect(0, 0, width, height, fill=1, stroke=0)

    c.setFillColor(NAVY)
    c.rect(0, height - 32 * mm, width, 32 * mm, fill=1, stroke=0)

    c.setFillColor(GOLD)
    c.setFont("Helvetica-Bold", 18)
    c.drawCentredString(width / 2, height - 20 * mm, "TECHNICAL ANNEX")

    c.setFillColor(GOLD_LIGHT)
    c.setFont("Helvetica", 8)
    c.drawCentredString(width / 2, height - 26 * mm, cert["name"])

    y = height - 44 * mm
    left = 28 * mm
    right_col = 72 * mm
    col_w = width - left - 28 * mm

    def section_heading(label, yy):
        c.setFillColor(NAVY)
        c.setFont("Helvetica-Bold", 11)
        c.drawString(left, yy, label)
        c.setStrokeColor(ACCENT)
        c.setLineWidth(0.8)
        c.line(left, yy - 2 * mm, left + col_w, yy - 2 * mm)
        return yy - 8 * mm

    def field_row(label, value, yy):
        c.setFillColor(MID_GREY)
        c.setFont("Helvetica", 7.5)
        c.drawString(left, yy, label)
        c.setFillColor(DARK_BLUE)
        c.setFont("Helvetica", 8.5)
        
        max_w = width - right_col - 30 * mm
        text = str(value)
        c.drawString(right_col, yy, text[:90])
        if len(text) > 90:
            yy -= 4.5 * mm
            c.drawString(right_col, yy, text[90:])
        return yy - 5.5 * mm

    y = section_heading("Target of Evaluation", y)
    y = field_row("ToE Name", toe["toe_name"], y)
    y = field_row("ToE UUID", toe["toe_uuid"], y)
    y = field_row("Description", toe["description"], y)

    y -= 3 * mm
    y = section_heading("Applicant", y)
    y = field_row("Organisation", applicant["organization_name"], y)
    y = field_row("Organisation ID", applicant["organization_id"], y)
    y = field_row("Contact", f'{applicant["contact_person"]["name"]} ({applicant["contact_person"]["email"]})', y)

    y -= 3 * mm
    y = section_heading("Certification Decision", y)
    y = field_row("Certification ID", cert["certification_id"], y)
    y = field_row("Level", decision["certification_level"], y)
    y = field_row("Status", decision["decision_status"], y)
    y = field_row("Decision Date", decision["decision_date"], y)
    y = field_row("Valid From", vp["start_date"], y)
    y = field_row("Valid To", vp["end_date"], y)

    y -= 3 * mm
    y = section_heading("Assessment", y)
    y = field_row("Assessment ID", assessment["assessment_id"], y)
    y = field_row("Date", assessment["assessment_date"], y)
    y = field_row("Result", assessment["assessment_result"], y)
    y = field_row("Evidence Ref", assessment["evidence"][0], y)

    y -= 3 * mm
    y = section_heading("Certification Scope", y)
    y = field_row("Scheme", cert["certification_scheme"], y)
    y = field_row("Environment", scope["environment"], y)
    y = field_row("Deployment Model", scope["deployment_model"], y)
    y = field_row("Services", ", ".join(scope["services_included"]), y)

    y -= 3 * mm
    y = section_heading("Certificate Issuance", y)
    y = field_row("Serial", issuance["certificate_serial"], y)
    y = field_row("Issue Date", issuance["issue_date"], y)
    y = field_row("Issued By", issuance["issued_by"], y)
    y = field_row("Accreditation ID", body["accreditation_id"], y)

    y -= 3 * mm
    y = section_heading("Certifying Body", y)
    y = field_row("Name", body["name"], y)
    y = field_row("Email", body["contact_info"]["email"], y)
    y = field_row("Website", body["contact_info"]["website"], y)

    y -= 3 * mm
    y = section_heading("Integrity Verification", y)
    y = field_row("Assessment Hash", payload.get("assessment_hash", "N/A"), y)
    y = field_row("Ledger Hash", payload["certificate"].get("ledger_hash", "N/A"), y)
    y = field_row("Document ID", str(payload["certificate"].get("_id", "N/A")), y)

    c.setFillColor(MID_GREY)
    c.setFont("Helvetica", 6.5)
    c.drawCentredString(width / 2, 14 * mm, f"COBALT Automated Certification  ·  Version {cert['version']}  ·  {body['contact_info']['website']}")

    c.save()


# ── Assessment Processing Engine ────────────────────────────────────

def process_assessment_result(data):
    if not data:
        return {"error": "Bad Request"}, 400

    try:
        validate(instance=data, schema=ASSESSMENT_SCHEMA)

        toe_id = data.get("target_of_evaluation_id")
        if not toe_id:
            return {"error": "target_of_evaluation_id missing in assessment"}, 400

        toe_record = toes_col.find_one({"uuid": toe_id})
        if not toe_record:
            return {"error": f"ToE {toe_id} is not registered in CCM Manager"}, 404

        scheme_id = toe_record.get("linked_scheme_id")
        if not scheme_id:
            return {
                "error": "Configuration Error: This ToE is not linked to any Certification Scheme. Cannot issue certificate."
            }, 409

        scheme_record = schemes_col.find_one({"uuid": scheme_id})
        if not scheme_record:
            return {"error": "Linked Certification Scheme not found in database"}, 404

        try:
            assessment_hash = send_to_ledger("/v1/manufacturer/ass-results", data)
        except Exception as exc:
            logging.warning("Ledger unavailable for assessment result, using placeholder hash: %s", exc)
            assessment_hash = "TempHashDueToHotFix"
            
        data["ledger_hash"] = assessment_hash
        collection.insert_one({
            "type": "assessment_result",
            "data": data,
            "timestamp": datetime.utcnow().isoformat(),
        })

        from services import certificate_service

        certificate_payload, certificate_status = certificate_service.update_certificate_from_assessment_result(
            data,
            assessment_hash=assessment_hash,
        )
        if certificate_status != 200:
            return {
                "status": "processed",
                "message": "Assessment processed, but certificate state was not updated.",
                "assessment_hash": assessment_hash,
                "certificate_update": certificate_payload,
                "outbound_auth": [ledger_auth_context()],
            }, certificate_status

        return {
            "status": "success",
            "message": "Assessment processed and Certificate state updated.",
            "assessment_hash": assessment_hash,
            "certificate_update": certificate_payload,
            "certificate": certificate_payload.get("certificate"),
            "outbound_auth": [ledger_auth_context()],
        }, 200

    except Exception as exc:
        logging.error("Error: %s", exc)
        return {"error": str(exc)}, 500
