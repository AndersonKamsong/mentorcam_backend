from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone


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
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'full_name']



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
