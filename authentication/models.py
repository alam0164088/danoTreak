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
        ('vendor', 'Vendor'),
    )
    email = models.EmailField(_('email address'), unique=True)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='user')
    is_email_verified = models.BooleanField(default=False)
    email_verification_code = models.CharField(max_length=6, blank=True, null=True)
    email_verification_code_expires_at = models.DateTimeField(blank=True, null=True)
    password_reset_code = models.CharField(max_length=6, blank=True, null=True)
    password_reset_code_expires_at = models.DateTimeField(blank=True, null=True)
    full_name = models.CharField(max_length=255, blank=True)
    gender = models.CharField(max_length=10, blank=True, choices=[('male', 'Male'), ('female', 'Female'), ('other', 'Other')])
    is_2fa_enabled = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def __str__(self):
        return self.email

    def generate_email_verification_code(self):
        from .utils import generate_otp  # utils থেকে generate_otp ইমপোর্ট করুন
        code = generate_otp(self.email, save_raw=True, expiry_minutes=5)
        self.email_verification_code = code
        self.email_verification_code_expires_at = timezone.now() + timedelta(minutes=5)
        self.save(update_fields=['email_verification_code', 'email_verification_code_expires_at'])
        return code

    def generate_password_reset_code(self):
        from .utils import generate_otp
        code = generate_otp(self.email, save_raw=True, expiry_minutes=15)
        self.password_reset_code = code
        self.password_reset_code_expires_at = timezone.now() + timedelta(minutes=15)
        self.save(update_fields=['password_reset_code', 'password_reset_code_expires_at'])
        return code

class EmailOTP(models.Model):
    email = models.EmailField()
    otp_hash = models.CharField(max_length=64)
    raw_otp = models.CharField(max_length=6, null=True, blank=True)
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    used = models.BooleanField(default=False)  # নতুন ফিল্ড যোগ করুন
    attempts = models.PositiveIntegerField(default=0)  # নতুন ফিল্ড যোগ করুন

    def __str__(self):
        return f"OTP for {self.email}"

class Token(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    email = models.EmailField()
    access_token = models.CharField(max_length=255, blank=True, null=True)
    refresh_token = models.CharField(max_length=255, blank=True, null=True)
    access_token_expires_at = models.DateTimeField(blank=True, null=True)
    refresh_token_expires_at = models.DateTimeField(blank=True, null=True)
    revoked = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.email} - Token"

class PasswordResetSession(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.UUIDField(default=uuid.uuid4, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        return (timezone.now() - self.created_at) > timedelta(minutes=15)

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
    phone = models.CharField(max_length=20, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    image = models.ImageField(upload_to='profile_images/', default='profile_images/default_profile.png')

    def __str__(self):
        return f"Profile for {self.user.email}"

    def save(self, *args, **kwargs):
        if not self.employee_id:
            last_count = Profile.objects.count() + 1
            self.employee_id = f"EMP{last_count:03d}"
        super().save(*args, **kwargs)

class Vendor(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='vendor_profile')
    business_name = models.CharField(max_length=255)
    location = models.CharField(max_length=255)
    geofence_radius = models.FloatField(default=100.0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.business_name} ({self.user.email})"

class LoyaltyProgram(models.Model):
    vendor = models.ForeignKey(Vendor, on_delete=models.CASCADE, related_name='loyalty_programs')
    campaign_name = models.CharField(max_length=255)
    visits_required = models.PositiveIntegerField()
    reward_description = models.TextField()
    max_redemptions_per_day = models.PositiveIntegerField(default=20)
    valid_until = models.DateTimeField()
    cooldown_period = models.PositiveIntegerField(default=0)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.campaign_name} by {self.vendor.business_name}"

class Visit(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='visits')
    vendor = models.ForeignKey(Vendor, on_delete=models.CASCADE, related_name='visits')
    timestamp = models.DateTimeField(auto_now_add=True)
    duration = models.PositiveIntegerField()
    is_valid = models.BooleanField(default=False)

    def __str__(self):
        return f"Visit by {self.user.email} to {self.vendor.business_name} at {self.timestamp}"

class Redemption(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='redemptions')
    loyalty_program = models.ForeignKey(LoyaltyProgram, on_delete=models.CASCADE, related_name='redemptions')
    timestamp = models.DateTimeField(auto_now_add=True)
    location_verified = models.BooleanField(default=False)
    fraud_flagged = models.BooleanField(default=False)

    def __str__(self):
        return f"Redemption by {self.user.email} for {self.loyalty_program.campaign_name}"