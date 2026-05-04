from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import os


def generate_report(filename, content):
    desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
    reports_dir = os.path.join(desktop_path, "CyberShield_Reports")

    os.makedirs(reports_dir, exist_ok=True)

    file_path = os.path.join(reports_dir, filename)

    c = canvas.Canvas(file_path, pagesize=letter)
    width, height = letter

    y = height - 40

    c.setFont("Helvetica-Bold", 16)
    c.drawString(40, y, "CyberShield AI Security Report")
    y -= 30

    c.setFont("Helvetica", 10)

    for line in content.split("\n"):
        if y < 40:
            c.showPage()
            c.setFont("Helvetica", 10)
            y = height - 40

        clean_line = (
            line.replace("•", "-")
                .replace("🛡", "")
                .replace("🚨", "")
                .replace("⚠", "")
                .replace("✅", "")
                .replace("🔍", "")
                .replace("📁", "")
                .replace("📄", "")
                .replace("🧠", "")
                .replace("📊", "")
                .replace("🔥", "")
                .replace("🌐", "")
                .replace("🔐", "")
                .replace("🔗", "")
                .replace("💥", "")
        )

        c.drawString(40, y, clean_line[:110])
        y -= 15

    c.save()

    return file_path