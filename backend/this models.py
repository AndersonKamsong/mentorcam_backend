this is my django backend 

utils.py(# utils.py
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
    return file_name, pdf_file)

models(
class Booking(models.Model):
    mentor = models.ForeignKey('ProfessionalCompleteProfile', on_delete=models.CASCADE)
    student = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    student_name = models.CharField(max_length=255, default='null')
    student_email = models.EmailField(max_length=255, default='null')  # Added email field
    mentor_name = models.CharField(max_length=255)
    booking_date = models.DateTimeField(auto_now_add=True)
    phone_number = models.CharField(max_length=15)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    transaction_id = models.CharField(max_length=100)
    plan_type = models.CharField(max_length=50)
    domain = models.CharField(max_length=100)
    subdomains = models.JSONField(default=list)
    status = models.CharField(
        max_length=20,
        choices=[
            ('pending', 'Pending'),
            ('confirmed', 'Confirmed'),
            ('completed', 'Completed'),
            ('cancelled', 'Cancelled')
        ],
        default='pending'
    )
    payment_reference = models.CharField(max_length=100, unique=True)
    pdf_receipt = models.FileField(upload_to='receipts/', null=True, blank=True)

    class Meta:
        ordering = ['-booking_date']
        # Add unique constraint to prevent multiple active bookings
        constraints = [
            models.UniqueConstraint(
                fields=['student', 'mentor'],
                condition=models.Q(status__in=['pending', 'confirmed']),
                name='unique_active_booking'
            )
        ]
)

serailizer(class BookingSerializer(serializers.ModelSerializer):
    class Meta:
        model = Booking
        fields = '__all__'
        read_only_fields = ('student', 'status', 'payment_reference', 'pdf_receipt'))

view(
    
from rest_framework import viewsets, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.decorators import action
from django.conf import settings
from django.db import transaction
from campay.sdk import Client as CamPayClient
import uuid
from .utils import generate_pdf_receipt
import json
from django.db.utils import IntegrityError

class BookingViewSet(viewsets.ModelViewSet):
    serializer_class = BookingSerializer
    permission_classes = [IsAuthenticated]
    
    campay = CamPayClient({
        "app_username": settings.CAMPAY_USERNAME,
        "app_password": settings.CAMPAY_PASSWORD,
        "environment": "PROD"
    })

    def get_queryset(self):
        user = self.request.user
        if hasattr(user, 'professional_profile'):
            return Booking.objects.filter(mentor__user=user)
        return Booking.objects.filter(student=user)

    @transaction.atomic
    def create(self, request, *args, **kwargs):
        data = request.data
        
        # Check if user already has an active booking with this mentor
        existing_booking = Booking.objects.filter(
            student=request.user,
            mentor_id=data['mentorId'],
            status__in=['pending', 'confirmed']
        ).first()

        if existing_booking:
            return Response({
                'error': 'You already have an ongoing session with this mentor',
                'booking_id': existing_booking.id
            }, status=status.HTTP_400_BAD_REQUEST)

        # Format phone number
        phone = data.get('phoneNumber', '')
        if not phone.startswith('237'):
            phone = '237' + phone

        # Generate payment reference
        payment_reference = str(uuid.uuid4())

        try:
            # Initialize CamPay payment
            payment_response = self.campay.collect({
                "amount": str(data['amount']),
                "currency": "XAF",
                "from": phone,
                "description": f"Booking with {data['mentorName']}",
                "external_reference": payment_reference
            })

            if payment_response.get('status') == 'SUCCESSFUL':
                # Create booking
                serializer = self.get_serializer(data={
                    'mentor_id': data['mentorId'],
                    'student': request.user.id,
                    'student_name': data['studentName'],
                    'student_email': data['studentEmail'],
                    'mentor_name': data['mentorName'],
                    'phone_number': phone,
                    'amount': data['amount'],
                    'transaction_id': payment_response['reference'],
                    'plan_type': data['planType'],
                    'domain': data['domain'],
                    'subdomains': json.dumps(data['subdomains']),
                    'status': 'confirmed',
                    'payment_reference': payment_reference
                })
                
                if serializer.is_valid():
                    booking = serializer.save()
                    
                    # Generate PDF receipt
                    file_name, pdf_file = generate_pdf_receipt(booking)
                    booking.pdf_receipt.save(file_name, pdf_file)

                    return Response({
                        'status': 'success',
                        'booking': serializer.data,
                        'receipt_url': booking.pdf_receipt.url if booking.pdf_receipt else None
                    }, status=status.HTTP_201_CREATED)
                
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
            return Response({
                'error': 'Payment failed',
                'details': payment_response.get('message', 'Unknown error')
            }, status=status.HTTP_400_BAD_REQUEST)

        except IntegrityError:
            return Response({
                'error': 'You already have an ongoing session with this mentor'
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                'error': 'Payment initialization failed',
                'details': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)
)

url(router.register(r'bookings', BookingViewSet, basename='booking')
)

this (([10/Feb/2025 09:54:13] "OPTIONS /api/bookings/check-active/1/ HTTP/1.1" 200 0
    Not Found: /api/bookings/check-active/1/
    [10/Feb/2025 09:54:13] "GET /api/bookings/check-active/1/ HTTP/1.1" 404 12873
    >>>>>>>>>>>>>>>>>>: Confirm on phone...
    Bad Request: /api/bookings/
    [10/Feb/2025 09:55:00] "POST /api/bookings/ HTTP/1.1" 400 38))
)