"""CSV export and PDF evidence reports."""
import csv
import io
from datetime import datetime

from fpdf import FPDF
from PIL import Image

CSV_FIELDS = ["id", "time_local", "timestamp", "camera_id", "person_count", "max_confidence",
              "evidence_hash", "chain_status", "chain_tx", "notified", "acknowledged_by", "acknowledged_at"]


def _local(ts):
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def incidents_csv(incidents):
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=CSV_FIELDS, extrasaction="ignore")
    w.writeheader()
    for inc in incidents:
        row = dict(inc, time_local=_local(inc["timestamp"]))
        # Neutralise spreadsheet formula injection in text cells
        for k, v in row.items():
            if isinstance(v, str) and v[:1] in ("=", "+", "-", "@"):
                row[k] = "'" + v
        w.writerow(row)
    return buf.getvalue()


class _Report(FPDF):
    def header(self):
        self.set_fill_color(23, 30, 41)
        self.rect(0, 0, 210, 18, "F")
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 13)
        self.set_xy(10, 5)
        self.cell(0, 8, "Intrusion Evidence Report")
        self.set_font("Helvetica", "", 8)
        self.set_xy(-70, 5)
        self.cell(60, 8, f"Generated {datetime.now():%Y-%m-%d %H:%M}", align="R")
        self.set_text_color(0, 0, 0)
        self.set_y(24)

    def footer(self):
        self.set_y(-12)
        self.set_font("Helvetica", "I", 7)
        self.set_text_color(120, 120, 120)
        self.cell(0, 6, "Confidential - evidence integrity anchored on blockchain (SHA-256). "
                        f"Page {self.page_no()}", align="C")


def _row(pdf, label, value, mono=False):
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(90, 90, 90)
    pdf.cell(42, 6, label)
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Courier" if mono else "Helvetica", "", 8 if mono else 9)
    pdf.multi_cell(0, 6, str(value), new_x="LMARGIN", new_y="NEXT")


def incident_pdf(inc, annotated_jpeg, verification, generated_by):
    pdf = _Report(format="A4")
    pdf.set_auto_page_break(True, margin=15)
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 9, inc["id"], new_x="LMARGIN", new_y="NEXT")

    ok = verification.get("verified")
    pdf.set_fill_color(*((43, 182, 115) if ok else (230, 57, 70)))
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(0, 8, f"  Integrity: {verification.get('status')} - {verification.get('message', '')}",
             fill=True, new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    pdf.ln(3)

    if annotated_jpeg:
        # Fit the image in a 190 x 92 mm box keeping its aspect ratio, centred,
        # then move the cursor below it (fpdf does not advance y for placed images).
        with Image.open(io.BytesIO(annotated_jpeg)) as im:
            iw, ih = im.size
        scale = min(190 / iw, 92 / ih)
        w, h = iw * scale, ih * scale
        y = pdf.get_y()
        pdf.image(io.BytesIO(annotated_jpeg), x=(210 - w) / 2, y=y, w=w, h=h)
        pdf.set_xy(10, y + h + 2)
        pdf.set_font("Helvetica", "I", 7)
        pdf.set_text_color(110, 110, 110)
        pdf.cell(0, 4, "Red = person inside restricted zone, green = outside, shaded polygon = zone.",
                 new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(0, 0, 0)
        pdf.ln(3)

    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 7, "Incident details", new_x="LMARGIN", new_y="NEXT")
    _row(pdf, "Captured", _local(inc["timestamp"]) + f"  (unix {inc['timestamp']})")
    _row(pdf, "Camera", inc["camera_id"])
    _row(pdf, "People in zone", inc["person_count"])
    _row(pdf, "Max confidence", f"{inc['max_confidence'] * 100:.0f}%")
    _row(pdf, "Notification", "sent" if inc["notified"] else "not sent")
    _row(pdf, "Acknowledged", f"{inc['acknowledged_by']} at {inc['acknowledged_at']}"
         if inc["acknowledged_by"] else "open")
    pdf.ln(2)

    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 7, "Integrity & blockchain proof", new_x="LMARGIN", new_y="NEXT")
    _row(pdf, "Blockchain status", inc["chain_status"])
    _row(pdf, "Transaction", inc["chain_tx"] or "-", mono=True)
    _row(pdf, "SHA-256 (file)", verification.get("file_hash") or "-", mono=True)
    _row(pdf, "SHA-256 (database)", verification.get("db_hash") or "-", mono=True)
    _row(pdf, "SHA-256 (chain)", verification.get("chain_hash") or "-", mono=True)
    chain = verification.get("chain") or {}
    if chain:
        _row(pdf, "Recorder account", chain.get("recorder", "-"), mono=True)
        _row(pdf, "Block time", _local(chain["block_time"]) if chain.get("block_time") else "-")
    pdf.ln(2)

    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 7, "Detections", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 9)
    for i, d in enumerate(inc["detections"], 1):
        where = "INSIDE zone" if d.get("in_zone") else "outside zone"
        box = ", ".join(f"{v:.0f}" for v in d["box"])
        pdf.cell(0, 5, f"{i}. person  conf {d['confidence']:.2f}  box [{box}]  {where}",
                 new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(110, 110, 110)
    pdf.multi_cell(0, 4, f"Report generated by {generated_by}. The original evidence image is stored "
                         "encrypted (AES-256-GCM). Its SHA-256 fingerprint was recorded on the "
                         "IncidentLedger smart contract at the time of the incident; a matching hash "
                         "proves the image has not been modified since.")
    return bytes(pdf.output())
