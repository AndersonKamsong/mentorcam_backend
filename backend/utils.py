# utils.py
from io import BytesIO
from django.core.files.base import ContentFile
from reportlab.pdfgen import canvas
from reportlab.graphics.barcode.qr import QrCodeWidget
from reportlab.graphics.shapes import Drawing
from reportlab.graphics import renderPDF
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
import os

def generate_pdf_receipt(booking):
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    # Header
    p.setFont("Helvetica-Bold", 18)
    p.drawString(50, height - 50, "Booking Confirmation Receipt")
    
    # Booking Details
    p.setFont("Helvetica", 12)
    y = height - 100
    details = [
        f"Booking Reference: {booking.payment_reference}",
        f"Date: {booking.booking_date.strftime('%Y-%m-%d %H:%M')}",
        f"Student Name: {booking.student_name}",
        f"Mentor Name: {booking.mentor_name}",
        f"Phone Number: {booking.phone_number}",
        f"Amount Paid: {booking.amount} XAF",
        f"Plan Type: {booking.plan_type}",
        f"Domain: {booking.domain}",
        f"Transaction ID: {booking.transaction_id}"
    ]

    for detail in details:
        p.drawString(50, y, detail)
        y -= 20

    # Subdomains
    if booking.subdomains:
        p.drawString(50, y, "Subdomains:")
        y -= 20
        for subdomain in booking.subdomains:
            p.drawString(70, y, f"• {subdomain}")
            y -= 20

    # QR Code
    qr_data = f"""
    Reference: {booking.payment_reference}
    Student: {booking.student_name}
    Mentor: {booking.mentor_name}
    Amount: {booking.amount} XAF
    """
    qr_code = QrCodeWidget(qr_data)
    bounds = qr_code.getBounds()
    qr_width = bounds[2] - bounds[0]
    qr_height = bounds[3] - bounds[1]
    d = Drawing(80, 80, transform=[80./qr_width, 0, 0, 80./qr_height, 0, 0])
    d.add(qr_code)
    renderPDF.draw(d, p, 50, 100)

    p.showPage()
    p.save()

    # Save PDF to booking model
    buffer.seek(0)
    pdf_file = ContentFile(buffer.getvalue())
    file_name = f'receipt_{booking.payment_reference}.pdf'
    return file_name, pdf_file