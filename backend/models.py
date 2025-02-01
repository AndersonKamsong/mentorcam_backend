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
    plan_type = models.CharField(max_length=20, choices=[('monthly', 'Monthly'), ('trimester', 'Trimester'), ('yearly', 'Yearly')], blank=True, null=True)
    plan_price = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)
    plan_description = models.TextField(blank=True, null=True)
    max_students = models.PositiveIntegerField(blank=True, null=True)
    
    # Domain Fields
    domain_name = models.CharField(max_length=255, blank=True, null=True)
    subdomains = models.JSONField(default=list, blank=True, null=True)

    def __str__(self):
        return f"{self.user.username}'s Complete Professional Profile"