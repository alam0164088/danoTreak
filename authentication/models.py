from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from datetime import timedelta
import uuid

class User(AbstractUser):
    ROLE_CHOICES = (
        ('admin', 'Admin'),
        ('user', 'User'),
    )
    email = models.EmailField(_('email address'), unique=True)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='user')
    is_email_verified = models.BooleanField(default=False)
    email_verification_code = models.CharField(max_length=6, blank=True, null=True)
    password_reset_code = models.CharField(max_length=6, blank=True, null=True)
    password_reset_code_expires_at = models.DateTimeField(blank=True, null=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def __str__(self):
        return self.email

    def generate_password_reset_code(self):
        """Generate OTP for password reset and set expiration (10 minutes)."""
        from django.utils.crypto import get_random_string
        code = get_random_string(length=6, allowed_chars='0123456789')
        self.password_reset_code = code
        self.password_reset_code_expires_at = timezone.now() + timedelta(minutes=10)
        self.save(update_fields=['password_reset_code', 'password_reset_code_expires_at'])
        return code

class Token(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='tokens')
    email = models.EmailField()
    refresh_token = models.TextField()
    access_token = models.TextField()
    refresh_token_expires_at = models.DateTimeField()
    access_token_expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Token for {self.email}"

class PasswordResetSession(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.UUIDField(default=uuid.uuid4, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        return (timezone.now() - self.created_at) > timedelta(minutes=10)

    def __str__(self):
        return f"Password Reset Session for {self.user.email}"

class SubscriptionPlan(models.Model):
    name = models.CharField(max_length=100)
    price = models.DecimalField(max_digits=6, decimal_places=2)

    def __str__(self):
        return self.name

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    employee_id = models.CharField(max_length=20, unique=True, blank=True)
    full_name = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Profile for {self.user.email}"

    def save(self, *args, **kwargs):
        if not self.employee_id:
            last_count = Profile.objects.count() + 1
            self.employee_id = f"EMP{last_count:03d}"  # Generates EMP001, EMP002, etc.
        if not self.full_name:
            self.full_name = self.user.username  # Default to username
        super().save(*args, **kwargs)