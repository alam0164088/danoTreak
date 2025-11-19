from django.db import models
from django.contrib.auth.models import AbstractUser , BaseUserManager
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from datetime import timedelta
import uuid

# --------------------------
# Custom User Model
# --------------------------
class UserManager(BaseUserManager):
    use_in_migrations = True

    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        if not user.username:
            user.username = str(uuid.uuid4())[:30]  # max_length 150 এর মধ্যে
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, password, **extra_fields)


# --------------------------
# Custom User Model
# --------------------------
class User(AbstractUser):
    ROLE_CHOICES = (
        ('admin', 'Admin'),
        ('user', 'User'),
        ('vendor', 'Vendor'),  # <-- এখানে vendor role যুক্ত
    )

    email = models.EmailField(unique=True)
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
    otp_attempts = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []  # username আর প্রয়োজন নেই

    objects = UserManager()  # <-- custom manager সেট করা

    def save(self, *args, **kwargs):
        if not self.username:
            self.username = str(uuid.uuid4())[:30]
        super().save(*args, **kwargs)

    def __str__(self):
        return self.email

    # --------------------------
    # Email verification & password reset
    # --------------------------
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
# Token Model
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
# Password Reset Session
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
# Profile Model
# --------------------------
class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    employee_id = models.CharField(max_length=20, unique=True, blank=True)
    phone = models.CharField(max_length=20, blank=True)
    image = models.ImageField(upload_to='profile_images/', default='profile_images/default_profile.png')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def save(self, *args, **kwargs):
        if not self.employee_id:
            last_count = Profile.objects.count() + 1
            self.employee_id = f"EMP{last_count:03d}"
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Profile for {self.user.email}"


# --------------------------
# Vendor Model
# --------------------------
class Vendor(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='vendor')
    business_name = models.CharField(max_length=255)
    location = models.CharField(max_length=255)
    geofence_radius = models.FloatField(default=100.0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.business_name} ({self.user.email})"


# --------------------------
# Email OTP Model
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
