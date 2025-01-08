# models.py
from django.contrib.auth.models import AbstractUser
from django.db import models

class CustomUser(AbstractUser):
    USER_TYPES = (
        ('amateur', 'Amateur'),
        ('professional', 'Professional'),
        ('institution', 'Institution'),
        ('admin', 'Admin'),
    )
    
    user_type = models.CharField(max_length=20, choices=USER_TYPES, default='amateur')
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    
    class Meta:
        db_table = 'auth_user'