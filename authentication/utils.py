from django.utils import timezone
import hashlib
from .models import EmailOTP
import random


def check_password(email, otp):
    """
    Email এবং OTP ভেরিফাই করে True/False রিটার্ন করে
    """
    otp_hash = hashlib.sha256(otp.encode()).hexdigest()
    try:
        otp_entry = EmailOTP.objects.get(email=email, otp_hash=otp_hash)
    except EmailOTP.DoesNotExist:
        return False

    # OTP মেয়াদ শেষ হয়ে গেছে কিনা চেক করা
    if otp_entry.expires_at < timezone.now():
        return False

    # OTP ঠিক থাকলে, DB থেকে ডিলিট করা যেতে পারে
    otp_entry.delete()
    return True



def generate_otp(email, save_raw=False, expiry_minutes=10):
    otp = str(random.randint(100000, 999999))
    otp_hash = hashlib.sha256(otp.encode()).hexdigest()
    expires_at = timezone.now() + timezone.timedelta(minutes=expiry_minutes)

    # DB তে save
    EmailOTP.objects.create(
        email=email,
        otp_hash=otp_hash,
        raw_otp=otp if save_raw else None,
        expires_at=expires_at
    )
    return otp