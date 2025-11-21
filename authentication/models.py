from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from datetime import timedelta
import uuid
import random
import string

from django.contrib.auth.models import BaseUserManager


# --------------------------
# USER MANAGER
# --------------------------
class UserManager(BaseUserManager):
    def create_user(self, email, password=None, referral_code=None, **extra_fields):
        if not email:
            raise ValueError('The Email must be set')

        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)

        # Referral code handling
        if referral_code:
            try:
                referrer = User.objects.get(referral_code__iexact=referral_code.strip())
                user.referred_by = referrer
            except User.DoesNotExist:
                pass

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        return self.create_user(email, password, **extra_fields)


# --------------------------
# USER MODEL
# --------------------------
class User(AbstractUser):
    # এই লাইনটা যোগ করা হয়েছে — username ফিল্ড পুরোপুরি বন্ধ!
    username = None

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
    gender = models.CharField(
        max_length=10,
        blank=True,
        choices=[('male', 'Male'), ('female', 'Female'), ('other', 'Other')]
    )

    is_2fa_enabled = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    otp_attempts = models.PositiveIntegerField(default=0)

    # Referral System
    referral_code = models.CharField(max_length=20, unique=True, blank=True, null=True)
    referred_by = models.ForeignKey(
        "self",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="referrals"
    )

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = UserManager()

    def __str__(self):
        return self.email

    def generate_referral_code(self):
        while True:
            code = "REF" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
            if not User.objects.filter(referral_code=code).exists():
                return code

    def save(self, *args, **kwargs):
        if not self.referral_code:
            self.referral_code = self.generate_referral_code()
        super().save(*args, **kwargs)

    def generate_email_verification_code(self):
        from .utils import generate_otp
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

# --------------------------
# FINAL VENDOR MODEL (সব ফিচার সহ)
# --------------------------
class Vendor(models.Model):
    CATEGORY_CHOICES = [
        ('food', 'Food'),
        ('beverage', 'Beverage'),
        ('nightlife', 'Nightlife'),
        ('grocery', 'Grocery'),
        ('pharmacy', 'Pharmacy'),
        ('electronics', 'Electronics'),
        ('fashion', 'Fashion'),
        ('others', 'Others'),
    ]

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='vendor_profile')
    vendor_name = models.CharField(max_length=100, default="N/A")
    shop_name = models.CharField(max_length=150, default="N/A")
    phone_number = models.CharField(max_length=15, default="N/A")
    shop_address = models.TextField(default="N/A")
    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES, default='others')

    latitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    longitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    shop_images = models.JSONField(default=list, blank=True)
    is_profile_complete = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)



# --------------------------
# TOKEN MODEL
# --------------------------
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


# --------------------------
# PASSWORD RESET SESSION
# --------------------------
class PasswordResetSession(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.UUIDField(default=uuid.uuid4, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        return (timezone.now() - self.created_at) > timedelta(minutes=15)

    def __str__(self):
        return f"Password Reset Session for {self.user.email}"


# --------------------------
# PROFILE MODEL
# --------------------------
class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    employee_id = models.CharField(max_length=20, unique=True, blank=True)
    phone = models.CharField(max_length=20, blank=True)
    image = models.ImageField(upload_to='profile_images/', default='profile_images/default_profile.png')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Profile for {self.user.email}"

    def save(self, *args, **kwargs):
        if not self.employee_id:
            last_count = Profile.objects.count() + 1
            self.employee_id = f"EMP{last_count:03d}"
        super().save(*args, **kwargs)


# --------------------------
# EMAIL OTP
# --------------------------
class EmailOTP(models.Model):
    email = models.EmailField()
    otp_hash = models.CharField(max_length=64)
    raw_otp = models.CharField(max_length=6, null=True, blank=True)
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    used = models.BooleanField(default=False)
    attempts = models.PositiveIntegerField(default=0)

    def __str__(self):
        return f"OTP for {self.email}"