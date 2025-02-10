from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
from django.conf import settings


class CustomUser(AbstractUser):
    USER_TYPES = (
        ('amateur', 'Amateur'),
        ('professional', 'Professional'),
        ('institution', 'Institution'),
        ('admin', 'Admin'),
    )
    
    email = models.EmailField(unique=True)
    full_name = models.CharField(max_length=255)
    phone_number = models.CharField(max_length=20)
    user_type = models.CharField(max_length=20, choices=USER_TYPES, default='amateur')
    last_logout = models.DateTimeField(null=True, blank=True)
    profile_picture = models.ImageField(upload_to='profile_pictures/', null=True, blank=True)
    location = models.CharField(max_length=255, blank=True, null=True)
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'full_name']

def record_logout(self):
    self.last_logout = timezone.now()
    self.save(update_fields=['last_logout'])


class Contact(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField()
    subject = models.CharField(max_length=200)
    message = models.TextField()
    created_at = models.DateTimeField(default=timezone.now)
    
    def __str__(self):
        return f"{self.name} - {self.subject}"

class Newsletter(models.Model):
    email = models.EmailField(unique=True)
    subscribed_at = models.DateTimeField(default=timezone.now)
    is_active = models.BooleanField(default=True)
    
    def __str__(self):
        return self.email


from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()

class ProfessionalCompleteProfile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='professional_complete_profile')
    title = models.CharField(max_length=255, blank=True, null=True)
    biography = models.TextField(blank=True, null=True)
    hourly_rate = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)
    linkedin = models.URLField(blank=True, null=True)
    github = models.URLField(blank=True, null=True)
    twitter = models.URLField(blank=True, null=True)
    website = models.URLField(blank=True, null=True)
    
    # Education Fields
    degree = models.CharField(max_length=255, blank=True, null=True)
    institution = models.CharField(max_length=255, blank=True, null=True)
    education_year = models.CharField(max_length=4, blank=True, null=True)
    
    # Certification Fields
    certification_name = models.CharField(max_length=255, blank=True, null=True)
    certification_issuer = models.CharField(max_length=255, blank=True, null=True)
    certification_year = models.CharField(max_length=4, blank=True, null=True)
    certification_file = models.FileField(upload_to='certifications/', blank=True, null=True)
    diploma_file = models.FileField(upload_to='diplomas/', blank=True, null=True)
    
    # Mentorship Plan Fields
    PLAN_CHOICES = [
        ('monthly', 'Monthly'),
        ('trimester', 'Trimester'),
        ('semester', 'Semester'),
        ('yearly', 'Yearly'),
        ('annually', 'Annually'),
    ]
    plan_type = models.CharField(max_length=20, choices=PLAN_CHOICES, blank=True, null=True)
    plan_price = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)
    plan_description = models.TextField(blank=True, null=True)
    max_students = models.PositiveIntegerField(blank=True, null=True)
    
    # Domain Fields
    domain_name = models.CharField(max_length=255, blank=True, null=True)
    subdomains = models.JSONField(default=list, blank=True, null=True)
    
    # Price Tracking Field
    price_traffic = models.PositiveIntegerField(default=0, help_text="Track the number of views or changes on pricing")
    
    def __str__(self):
        return f"{self.user.username}'s Complete Professional Profile"


from django.core.validators import MinValueValidator, MaxValueValidator

class ProfessionalRating(models.Model):
    professional = models.ForeignKey('ProfessionalCompleteProfile', on_delete=models.CASCADE, related_name='ratings')
    rated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='ratings_given')
    rating = models.IntegerField(validators=[MinValueValidator(1), MaxValueValidator(5)])
    comment = models.TextField()
    experience_details = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    domain = models.CharField(max_length=255)
    subdomain = models.CharField(max_length=255)

    class Meta:
        unique_together = ('professional', 'rated_by')

from django.db import models
from django.conf import settings
from decimal import Decimal

from django.db import models
from django.conf import settings

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
