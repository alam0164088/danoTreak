import json
import os
import re
import uuid
import math
import logging
import hashlib
import requests
import time
from uuid import uuid4
from datetime import timedelta, datetime
from decimal import Decimal

from django.conf import settings
from django.core.mail import send_mail
from django.core.files.base import ContentFile, File
from django.core.files.storage import default_storage
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.utils.timezone import localtime
from django.http import HttpResponseRedirect, JsonResponse
from django.views.decorators.cache import never_cache
from django.utils.decorators import method_decorator
from django.contrib.auth import get_user_model
from django.core.exceptions import ObjectDoesNotExist
from django.db import transaction

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, serializers
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.decorators import api_view, permission_classes
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from django.conf import settings

from rest_framework_simplejwt.tokens import RefreshToken

from jose import jwt as jose_jwt
import jwt as pyjwt

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer

from authentication.models import (
    Token, Profile, PasswordResetSession, Vendor, VendorProfileUpdateRequest, Notification
)
from authentication.serializers import (
    RegisterSerializer, SendOTPSerializer, VerifyOTPSerializer, LoginSerializer,
    RefreshTokenSerializer, LogoutSerializer, ForgotPasswordSerializer,
    VerifyResetOTPSerializer, ResetPasswordSerializer, ChangePasswordSerializer,
    Enable2FASerializer, Verify2FASerializer, ResendOTPSerializer, UserProfileSerializer,
    ProfileUpdateSerializer, VendorSerializer, ReferralCodeSerializer
)
from authentication.permissions import IsAdmin, IsVendor
from authentication.consumers import ONLINE_USERS

from vendor.models import Visitor, Visit, Campaign, Redemption
from vendor.utils import generate_aliffited_id

logger = logging.getLogger('authentication')
User = get_user_model()

# Notification serializer + API (moved up; no duplicates)
class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = ["id", "title", "message", "aliffited_id", "shop_name", "reward_name", "is_read", "created_at"]

class NotificationListAPI(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        qs = Notification.objects.filter(user=request.user).order_by("-created_at")
        serializer = NotificationSerializer(qs, many=True)
        return Response({
            "success": True,
            "count": qs.count(),
            "notifications": serializer.data
        })

# ============= GOOGLE & APPLE LOGIN VIEWS (ফাইনাল ভার্সন – ইমেজ সমস্যা ১০০% ঠিক) =============
from urllib.parse import unquote
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils import timezone
from django.conf import settings
from django.core.files.base import ContentFile
from datetime import timedelta
import requests
import logging
import hashlib
import jwt

from django.contrib.auth import get_user_model
from .models import Token, Profile

User = get_user_model()
logger = logging.getLogger(__name__)

from .serializers import ReferralCodeSerializer
from django.conf import settings


# ============================
# VENDOR PROFILE COMPLETION
import uuid
import re
from decimal import Decimal
from django.core.files.storage import default_storage
from django.core.exceptions import ObjectDoesNotExist
from rest_framework.views import APIView
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status



from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import get_user_model
from rest_framework.permissions import AllowAny

User = get_user_model()
import os
import uuid
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated




from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone
from datetime import timedelta


from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.utils.timezone import localtime
from django.core.mail import send_mail
from django.conf import settings
from django.core.files import File
import os
import logging

from authentication.models import User, VendorProfileUpdateRequest

logger = logging.getLogger(__name__)



# views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated   # ← এই লাইনটা থাকতে হবে
from .models import Vendor
import math

import math
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from authentication.models import Vendor, Profile



import math
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from authentication.models import Vendor



from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .models import Vendor

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import serializers
from .models import Notification


# authentication/views.py
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from authentication.consumers import ONLINE_USERS
from authentication.models import Profile
from datetime import datetime

from datetime import timedelta
from django.http import HttpResponseRedirect, JsonResponse
from .models import Token, Profile, PasswordResetSession, Vendor
from .permissions import IsAdmin, IsVendor
from .serializers import (
    RegisterSerializer, SendOTPSerializer, VerifyOTPSerializer, LoginSerializer,
    RefreshTokenSerializer, LogoutSerializer, ForgotPasswordSerializer,
    VerifyResetOTPSerializer, ResetPasswordSerializer, ChangePasswordSerializer,
    Enable2FASerializer, Verify2FASerializer, ResendOTPSerializer, UserProfileSerializer,
    ProfileUpdateSerializer, VendorSerializer
)


logger = logging.getLogger('authentication')
User = get_user_model()

# Remove load_dotenv() from here; it should be in settings.py
# load_dotenv()


class RegisterView(APIView):
    
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            user = serializer.save()
            send_verification = request.data.get('send_verification_otp', True)

            if send_verification:
                # OTP generate & send
                code = user.generate_email_verification_code()
                send_mail(
                    'Verify Your Email',
                    f'Your OTP is {code}. Expires in 5 minutes.',
                    settings.DEFAULT_FROM_EMAIL,
                    [user.email],
                    fail_silently=False,
                )
                user.is_active = False
                user.save()
                logger.info(f"User registered: {user.email} (verification pending)")

                return Response({
                    "id": user.id,
                    "email": user.email,
                    "full_name": user.full_name,
                    "phone": user.phone,
                    "referral_code": user.referral_code,
                    "role": user.role,
                    "is_active": False,
                    "is_email_verified": user.is_email_verified,
                    "message": "User created. Verification OTP sent to email. OTP expires in 5 minutes."
                }, status=status.HTTP_201_CREATED)
            else:
                user.is_active = True
                user.is_email_verified = True
                user.save()
                logger.info(f"User registered: {user.email} (verification skipped)")

                return Response({
                    "id": user.id,
                    "email": user.email,
                    "full_name": user.full_name,
                    "phone": user.phone,
                    "referral_code": user.referral_code,
                    "role": user.role,
                    "is_active": True,
                    "is_email_verified": True,
                    "message": "User created successfully."
                }, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class VendorSignUpView(APIView):
   
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        password2 = request.data.get('password2')

        # বেসিক ভ্যালিডেশন
        if not email or not password:
            return Response({
                "success": False,
                "message": "ইমেইল এবং পাসওয়ার্ড দিতে হবে"
            }, status=status.HTTP_400_BAD_REQUEST)

        if password != password2:
            return Response({
                "success": False,
                "message": "দুইটা পাসওয়ার্ড মিলছে না"
            }, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(email__iexact=email).exists():
            return Response({
                "success": False,
                "message": "এই ইমেইল দিয়ে ইতিমধ্যে একাউন্ট আছে"
            }, status=status.HTTP_400_BAD_REQUEST)

        # ইউজার তৈরি করো (OTP ছাড়া)
        user = User.objects.create_user(
            email=email.lower().strip(),
            password=password,
            role='vendor',
            is_active=True,           # এডমিন approve করার আগে লগিন করতে পারবে না
            is_email_verified=True     # OTP নাই → তাই verified ধরে নিচ্ছি
        )

        # Vendor প্রোফাইল তৈরি করো
        vendor, created = Vendor.objects.get_or_create(user=user)
        vendor.plain_password = password   # এডমিন যাতে দেখতে পারে
        vendor.save()

        return Response({
            "success": True,
            "user": {
                "id": user.id,
                "email": user.email,
                "role": "vendor",
                "is_active": True
            }
        }, status=status.HTTP_201_CREATED)




class InitialAdminSignUpView(APIView):
    """Handle initial admin signup (only one admin allowed initially)."""
    permission_classes = [AllowAny]
    
    def post(self, request):
        # যদি ইতিমধ্যে কোনো এডমিন থাকে
        if User.objects.filter(role='admin').exists():
            return Response({
                "detail": "An admin already exists. Use regular login or contact support."
            }, status=status.HTTP_400_BAD_REQUEST)

        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            user.role = 'admin'
            user.is_email_verified = True
            user.is_active = True
            user.save()

            # ইমেইল পাঠাও (অপশনাল, কিন্তু ভালো)
            try:
                code = user.generate_email_verification_code()
                send_mail(
                    'Welcome Admin!',
                    f'আপনার এডমিন একাউন্ট তৈরি হয়েছে!\nইমেইল: {user.email}\nপাসওয়ার্ড: (যেটা দিয়েছেন)\n\nলগইন করুন: {settings.FRONTEND_URL}/admin/login',
                    settings.DEFAULT_FROM_EMAIL,
                    [user.email],
                    fail_silently=True,
                )
            except:
                pass  # ইমেইল না গেলেও সমস্যা নাই

            # JWT টোকেন তৈরি
            refresh = RefreshToken.for_user(user)
            refresh_token = str(refresh)
            access_token = str(refresh.access_token)

            # গুরুত্বপূর্ণ: পুরানো টোকেন মুছে নতুনটা দাও
            Token.objects.filter(user=user).delete()
            Token.objects.create(
                user=user,
                email=user.email,
                refresh_token=refresh_token,
                access_token=access_token,
                refresh_token_expires_at=timezone.now() + refresh.lifetime,
                access_token_expires_at=timezone.now() + timedelta(minutes=15),
            )

            logger.info(f"Initial admin created successfully: {user.email}")

            return Response({
                "success": True,
                "message": "প্রথম এডমিন একাউন্ট সফলভাবে তৈরি হয়েছে!",
                "admin": {
                    "id": user.id,
                    "email": user.email,
                    "access_token": access_token,
                    "refresh_token": refresh_token
                }
            }, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class AdminSignUpView(APIView):
    """Handle admin signup by an existing admin."""
    permission_classes = [IsAuthenticated, IsAdmin]
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            user.role = 'admin'
            user.is_active = False
            user.save()
            code = user.generate_email_verification_code()
            send_mail(
                'Verify Your Admin Email',
                f'Your verification code is {code}. Expires in 5 minutes.',
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )
            logger.info(f"Admin created by {request.user.email}: {user.email}")
            return Response({
                "id": user.id,
                "email": user.email,
                "message": "Admin created. Verification OTP sent to email."
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class AdminUserManagementView(APIView):
    """Manage users (view, update role, delete) by admins."""
    permission_classes = [IsAuthenticated, IsAdmin]
    def get(self, request, user_id=None):
        if user_id:
            try:
                user = User.objects.get(id=user_id)
                serializer = UserProfileSerializer(user, context={'request': request})
                logger.info(f"User {user.email} viewed by {request.user.email}")
                return Response(serializer.data, status=status.HTTP_200_OK)
            except User.DoesNotExist:
                return Response({"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND)
        else:
            users = User.objects.all()
            serializer = UserProfileSerializer(users, many=True, context={'request': request})
            logger.info(f"User list accessed by: {request.user.email}")
            return Response({"users": serializer.data}, status=status.HTTP_200_OK)
    def put(self, request, user_id):
        try:
            user = User.objects.get(id=user_id)
            role = request.data.get('role')
            if role not in ['admin', 'user', 'vendor']:
                return Response({"detail": "Invalid role. Must be 'admin', 'user', or 'vendor'."}, status=status.HTTP_400_BAD_REQUEST)
            user.role = role
            user.save()
            serializer = UserProfileSerializer(user, context={'request': request})
            logger.info(f"User {user.email} role updated to {role} by {request.user.email}")
            return Response({"message": "User role updated successfully.", "user": serializer.data}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND)
    def delete(self, request, user_id):
        try:
            user = User.objects.get(id=user_id)
            user_email = user.email
            user.delete()
            logger.info(f"User {user_email} deleted by {request.user.email}")
            return Response({"message": "User deleted successfully."}, status=status.HTTP_204_NO_CONTENT)
        except User.DoesNotExist:
            return Response({"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND)




class SendOTPView(APIView):
    """Send OTP for email verification, password reset, or 2FA."""
    permission_classes = [AllowAny]
    def post(self, request):
        serializer = SendOTPSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            purpose = serializer.validated_data['purpose']
            user = User.objects.filter(email=email).first()
            if not user:
                logger.info(f"OTP request for non-existent email: {email}")
                return Response({"detail": "If the email exists, an OTP has been sent."}, status=status.HTTP_200_OK)
            code = None
            if purpose == 'email_verification' and not user.is_email_verified:
                code = user.generate_email_verification_code()
            elif purpose == 'password_reset':
                code = user.generate_password_reset_code()
            elif purpose == 'two_factor' and user.is_2fa_enabled:
                code = user.generate_email_verification_code()
            else:
                logger.warning(f"Invalid OTP purpose: {purpose} for user: {email}")
                return Response({"detail": f"Invalid request for {purpose}."}, status=status.HTTP_400_BAD_REQUEST)
            if code:
                send_mail(
                    f'{purpose.replace("_", " ").title()} OTP',
                    f'Your OTP is {code}. Expires in {"5 minutes" if purpose != "password_reset" else "15 minutes"}.',
                    settings.DEFAULT_FROM_EMAIL,
                    [user.email],
                    fail_silently=False,
                )
                logger.info(f"OTP sent for {purpose}: {user.email}")
                return Response({"message": f"OTP sent to email. Expires in {'5 minutes' if purpose != 'password_reset' else '15 minutes'}."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class VerifyOTPView(APIView):
    """Verify OTP for email verification, password reset, or 2FA."""
    permission_classes = [AllowAny]
    def post(self, request):
        serializer = VerifyOTPSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp = serializer.validated_data['otp']
            purpose = serializer.validated_data['purpose']
            user = User.objects.filter(email=email).first()
            if not user:
                return Response({"ok": False, "error": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST)
            MAX_ATTEMPTS = 3
            if purpose == 'email_verification':
                if user.is_email_verified:
                    return Response({"ok": False, "error": "Email already verified."}, status=status.HTTP_400_BAD_REQUEST)
                if user.otp_attempts >= MAX_ATTEMPTS:
                    return Response({"ok": False, "error": "Too many attempts"}, status=status.HTTP_403_FORBIDDEN)
                if user.email_verification_code != otp or user.email_verification_code_expires_at < timezone.now():
                    user.otp_attempts += 1
                    user.save(update_fields=['otp_attempts'])
                    return Response({"ok": False, "error": "OTP expired or invalid.", "attempts_left": MAX_ATTEMPTS - user.otp_attempts}, status=status.HTTP_400_BAD_REQUEST)
                user.is_email_verified = True
                user.is_active = True
                user.email_verification_code = None
                user.email_verification_code_expires_at = None
                user.otp_attempts = 0
                user.save()
                logger.info(f"Email verified for: {user.email}")
                return Response({"ok": True, "message": "OTP verified"}, status=status.HTTP_200_OK)
            elif purpose == 'password_reset':
                if user.otp_attempts >= MAX_ATTEMPTS:
                    return Response({"ok": False, "error": "Too many attempts"}, status=status.HTTP_403_FORBIDDEN)
                if user.password_reset_code != otp or user.password_reset_code_expires_at < timezone.now():
                    user.otp_attempts += 1
                    user.save(update_fields=['otp_attempts'])
                    return Response({"ok": False, "error": "OTP expired or invalid.", "attempts_left": MAX_ATTEMPTS - user.otp_attempts}, status=status.HTTP_400_BAD_REQUEST)
                reset_token = str(uuid4())
                PasswordResetSession.objects.create(user=user, token=reset_token)
                user.password_reset_code = None
                user.password_reset_code_expires_at = None
                user.otp_attempts = 0
                user.save()
                logger.info(f"Password reset OTP verified for: {user.email}")
                return Response({"ok": True, "message": "OTP verified", "reset_token": reset_token}, status=status.HTTP_200_OK)
            elif purpose == 'two_factor':
                if user.otp_attempts >= MAX_ATTEMPTS:
                    return Response({"ok": False, "error": "Too many attempts"}, status=status.HTTP_403_FORBIDDEN)
                if user.email_verification_code != otp or user.email_verification_code_expires_at < timezone.now():
                    user.otp_attempts += 1
                    user.save(update_fields=['otp_attempts'])
                    return Response({"ok": False, "error": "OTP expired or invalid.", "attempts_left": MAX_ATTEMPTS - user.otp_attempts}, status=status.HTTP_400_BAD_REQUEST)
                user.otp_attempts = 0
                user.save()
                logger.info(f"2FA OTP verified for: {user.email}")
                return Response({"ok": True, "message": "OTP verified"}, status=status.HTTP_200_OK)
            return Response({"ok": False, "error": "Invalid purpose."}, status=status.HTTP_400_BAD_REQUEST)
        return Response({"ok": False, "error": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


# authentication/views.py

from datetime import timedelta
from django.utils import timezone
from django.core.mail import send_mail
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.tokens import RefreshToken

from vendor.models import Visitor, Visit, Campaign, Redemption
from authentication.models import User, Vendor, Token
from authentication.serializers import LoginSerializer
from django.conf import settings
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from math import radians, sin, cos, sqrt, atan2
from vendor.utils import generate_aliffited_id

import logging

logger = logging.getLogger(__name__)

class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data['email'].lower().strip()
        password = serializer.validated_data['password']
        user = User.objects.filter(email=email).first()

        if not user or not user.check_password(password):
            return Response({"detail": "ইমেইল বা পাসওয়ার্ড ভুল।"}, status=401)

        # ভেরিফিকেশন ও এক্টিভিটি চেক
        if user.role != 'vendor':
            if not user.is_email_verified:
                return Response({
                    "detail": "ইমেইল ভেরিফাই করা হয়নি। OTP দিয়ে ভেরিফাই করুন।",
                    "next_step": "verify_email_otp"
                }, status=403)
            if not user.is_active:
                return Response({"detail": "আপনার একাউন্ট সক্রিয় করা হয়নি।"}, status=403)
        else:
            if not user.is_active:
                return Response({"detail": "আপনার ভেন্ডর একাউন্ট সক্রিয় নয়।", "contact_admin": True}, status=403)

        # প্রথম লগইন পপআপ
        first_login_popup = False
        if not user.first_login_done:
            first_login_popup = True
            user.first_login_done = True
            user.save(update_fields=['first_login_done'])

        # 2FA চেক
        if user.is_2fa_enabled:
            code = user.generate_email_verification_code()
            send_mail(
                '2FA ভেরিফিকেশন কোড',
                f'আপনার 2FA OTP: {code}\nমেয়াদ: ৫ মিনিট',
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=True,
            )
            return Response({
                "detail": "2FA প্রয়োজন। ইমেইলে OTP পাঠানো হয়েছে।",
                "next_step": "verify_2fa_otp",
                "first_login_popup": first_login_popup
            }, status=206)

        # Token তৈরি
        refresh = RefreshToken.for_user(user)
        lifetime = timedelta(days=900) if serializer.validated_data.get('remember_me', False) else timedelta(days=7)
        refresh.set_exp(lifetime=lifetime)

        refresh_token_str = str(refresh)
        access_token_str = str(refresh.access_token)

        Token.objects.filter(user=user).delete()
        Token.objects.create(
            user=user,
            email=user.email,
            refresh_token=refresh_token_str,
            access_token=access_token_str,
            refresh_token_expires_at=timezone.now() + refresh.lifetime,
            access_token_expires_at=timezone.now() + timedelta(days=365),
        )

        logger.info(f"সফল লগইন: {user.email} ({user.role})")

        # Live tracking (user only)
        if user.role == 'user':
            channel_layer = get_channel_layer()
            if channel_layer:
                async_to_sync(channel_layer.group_send)(
                    "live_location_group",
                    {
                        "type": "user_online",
                        "user_id": user.id,
                        "email": user.email,
                        "full_name": user.full_name or "User",
                        "message": f"{user.email} is now online and being tracked"
                    }
                )

        # ===== auto_checkin পুরোপুরি মুছে ফেলা হয়েছে =====

        response_data = {
            "access_token": access_token_str,
            "access_token_expires_in": 365 * 24 * 60,
            "refresh_token": refresh_token_str,
            "refresh_token_expires_in": int(refresh.lifetime.total_seconds()),
            "token_type": "Bearer",
            "first_login_popup": first_login_popup,
            "user": {
                "id": user.id,
                "email": user.email,
                "full_name": user.full_name or "",
                "role": user.role,
                "is_active": user.is_active,
                "email_verified": user.is_email_verified
            }
        }

        return Response(response_data, status=200)







class RefreshTokenView(APIView):
    """Refresh access token using a valid refresh token."""
    permission_classes = [AllowAny]
    def post(self, request):
        serializer = RefreshTokenSerializer(data=request.data)
        if serializer.is_valid():
            refresh_token_str = serializer.validated_data['refresh_token']
            try:
                refresh = RefreshToken(refresh_token_str)
                user = User.objects.get(id=refresh.payload['user_id'])
                token_obj = Token.objects.filter(user=user, refresh_token=refresh_token_str, revoked=False).first()
                if not token_obj or token_obj.refresh_token_expires_at < timezone.now():
                    return Response({"detail": "Refresh token invalid or expired."}, status=status.HTTP_401_UNAUTHORIZED)
                new_access = refresh.access_token
                access_expires_in = 900
                token_obj.access_token = str(new_access)
                token_obj.access_token_expires_at = timezone.now() + timedelta(minutes=15)
                token_obj.save()
                logger.info(f"Token refreshed for: {user.email}")
                return Response({
                    "access_token": str(new_access),
                    "access_token_expires_in": access_expires_in
                }, status=status.HTTP_200_OK)
            except Exception as e:
                logger.error(f"Token refresh failed: {str(e)}")
                return Response({"detail": "Refresh token invalid or expired."}, status=status.HTTP_401_UNAUTHORIZED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LogoutView(APIView):
    """Handle user logout by revoking refresh tokens."""
    permission_classes = [IsAuthenticated]
    def post(self, request):
        refresh_token_str = request.data.get('refresh_token')
        if refresh_token_str:
            Token.objects.filter(refresh_token=refresh_token_str, user=request.user, revoked=False).update(revoked=True)
        else:
            Token.objects.filter(user=request.user, revoked=False).update(revoked=True)
        logger.info(f"User logged out: {request.user.email}")
        return Response({"message": "Logged out. Refresh token revoked."}, status=status.HTTP_200_OK)

class ForgotPasswordView(APIView):
    """Initiate password reset by sending an OTP."""
    permission_classes = [AllowAny]
    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = User.objects.filter(email=email).first()
            if user:
                code = user.generate_password_reset_code()
                send_mail(
                    'Password Reset',
                    f'Your OTP is {code}. Expires in 5 minutes.',
                    settings.DEFAULT_FROM_EMAIL,
                    [user.email],
                    fail_silently=False,
                )
            logger.info(f"Password reset requested for: {email}")
            return Response({
                "message": "If the email exists, a password reset OTP has been sent. Expires in 5 minutes."
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class VerifyResetOTPView(APIView):
    """Verify OTP for password reset."""
    permission_classes = [AllowAny]
    def post(self, request):
        serializer = VerifyResetOTPSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp = serializer.validated_data['otp']
            user = User.objects.filter(email=email).first()
            if not user or user.password_reset_code != otp or user.password_reset_code_expires_at < timezone.now():
                return Response({"detail": "OTP expired or invalid."}, status=status.HTTP_400_BAD_REQUEST)
            reset_token = str(uuid4())
            PasswordResetSession.objects.create(user=user, token=reset_token)
            user.password_reset_code = None
            user.password_reset_code_expires_at = None
            user.save()
            logger.info(f"Password reset OTP verified for: {user.email}")
            return Response({
                "message": "OTP verified. You may now reset your password.",
                "reset_token": reset_token
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ResetPasswordConfirmView(APIView):
    """Confirm password reset with a new password."""
    permission_classes = [AllowAny]
    def post(self, request):
        serializer = ResetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            reset_token = serializer.validated_data['reset_token']
            new_password = serializer.validated_data['new_password']
            session = PasswordResetSession.objects.filter(token=reset_token).first()
            if not session or session.is_expired():
                return Response({"detail": "Reset token invalid or expired."}, status=status.HTTP_401_UNAUTHORIZED)
            user = session.user
            user.set_password(new_password)
            user.save()
            session.delete()
            Token.objects.filter(user=user).update(revoked=True)
            logger.info(f"Password reset for: {user.email}")
            return Response({"message": "Password reset successfully. Please login with new password."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ChangePasswordView(APIView):
    """Change password for authenticated users."""
    permission_classes = [IsAuthenticated]
    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        if serializer.is_valid():
            if not request.user.check_password(serializer.validated_data['old_password']):
                return Response({"detail": "Old password incorrect."}, status=status.HTTP_400_BAD_REQUEST)
            request.user.set_password(serializer.validated_data['new_password'])
            request.user.save()
            Token.objects.filter(user=request.user).update(revoked=True)
            logger.info(f"Password changed for: {request.user.email}")
            return Response({"message": "Password changed successfully. All existing refresh tokens revoked."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class Enable2FAView(APIView):
    """Initiate 2FA enablement for authenticated users."""
    permission_classes = [IsAuthenticated]
    def post(self, request):
        serializer = Enable2FASerializer(data=request.data)
        if serializer.is_valid():
            method = serializer.validated_data['method']
            code = request.user.generate_email_verification_code()
            send_mail(
                'Enable 2FA',
                f'Your OTP to enable 2FA is {code}. Expires in 5 minutes.',
                settings.DEFAULT_FROM_EMAIL,
                [request.user.email],
                fail_silently=False,
            )
            logger.info(f"2FA enable initiated for: {request.user.email}")
            return Response({
                "message": "2FA enable initiated. Verify the OTP sent to your email to finish enabling 2FA.",
                "next_step": "verify_2fa_otp"
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class Verify2FAView(APIView):
    """Verify 2FA OTP to enable 2FA."""
    permission_classes = [IsAuthenticated]
    def post(self, request):
        serializer = Verify2FASerializer(data=request.data)
        if serializer.is_valid():
            otp = serializer.validated_data['otp']
            method = serializer.validated_data['method']
            if request.user.email_verification_code != otp or request.user.email_verification_code_expires_at < timezone.now():
                return Response({"detail": "OTP expired or invalid."}, status=status.HTTP_400_BAD_REQUEST)
            request.user.is_2fa_enabled = True
            request.user.email_verification_code = None
            request.user.email_verification_code_expires_at = None
            request.user.save()
            logger.info(f"2FA enabled for: {request.user.email}")
            return Response({"message": "2FA enabled successfully."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



@method_decorator(never_cache, name='dispatch')
class MeView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser, JSONParser]  # JSON + Multipart + Form

    def get(self, request):
        user = User.objects.select_related('profile').get(pk=request.user.pk)
        serializer = UserProfileSerializer(user, context={'request': request})
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request):
        profile, _ = Profile.objects.get_or_create(user=request.user)
        serializer = ProfileUpdateSerializer(
            instance=profile,
            data=request.data,           # শুধু request.data ব্যবহার
            context={'request': request},
            partial=True
        )

        if not serializer.is_valid():
            return Response({
                "success": False,
                "errors": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        with transaction.atomic():
            old_image = profile.image
            serializer.save()

            # পুরানো ইমেজ ডিলিট (যদি নতুন আসে)
            if old_image and old_image != profile.image:
                if hasattr(old_image, 'path') and old_image.path != profile.image.path:
                    if default_storage.exists(old_image.path):
                        default_storage.delete(old_image.path)

        fresh_user = User.objects.select_related('profile').get(pk=request.user.pk)
        fresh_serializer = UserProfileSerializer(fresh_user, context={'request': request})

        return Response({
            "success": True,
            "message": "Profile updated successfully!",
            "user": fresh_serializer.data
        }, status=status.HTTP_200_OK)

    def patch(self, request):
        # PATCH PUT-এর মতোই কাজ করবে
        return self.put(request)

    def delete(self, request):
        password = request.data.get('current_password')

        if not password:
            return Response({
                "success": False,
                "detail": "Current password is required."
            }, status=status.HTTP_400_BAD_REQUEST)

        if not request.user.check_password(password):
            return Response({
                "success": False,
                "detail": "Current password is incorrect."
            }, status=status.HTTP_400_BAD_REQUEST)

        email = request.user.email
        request.user.delete()
        logger.info(f"Account deleted successfully: {email}")

        return Response({
            "success": True,
            "message": "Account deleted successfully."
        }, status=status.HTTP_200_OK)


class ResendOTPView(APIView):
    """Resend verification OTP for email verification."""
    permission_classes = [AllowAny]
    def post(self, request):
        serializer = ResendOTPSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = User.objects.filter(email=email).first()
            if not user:
                return Response({"detail": "If the email exists, an OTP has been sent."}, status=status.HTTP_200_OK)
            if user.is_email_verified:
                return Response({"detail": "Email already verified."}, status=status.HTTP_400_BAD_REQUEST)
            code = user.generate_email_verification_code()
            send_mail(
                'Resend Verification OTP',
                f'Your new OTP is {code}. Expires in 5 minutes.',
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )
            logger.info(f"OTP resent for: {user.email}")
            return Response({"message": "Verification OTP resent. Expires in 5 minutes."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)






class MyReferralCodeView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        serializer = ReferralCodeSerializer(user)
        return Response({
            "success": True,
            "data": serializer.data
        }, status=status.HTTP_200_OK)
    





class CompleteVendorProfileView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser, JSONParser]

    def get(self, request):
        """GET: ভেন্ডর প্রোফাইল দেখা"""
        user = request.user
        if user.role != 'vendor':
            return Response({"success": False, "message": "Only vendors can view profile"}, status=403)

        try:
            vendor = Vendor.objects.get(user=user)
        except Vendor.DoesNotExist:
            return Response({"success": False, "message": "Vendor profile not found"}, status=404)

        # Shop images এ base URL যোগ করা
        base_url = request.build_absolute_uri('/')[:-1]
        shop_images_full = []
        if vendor.shop_images:
            for img in vendor.shop_images:
                if img.startswith('http'):
                    shop_images_full.append(img)
                else:
                    shop_images_full.append(f"{base_url}{img}")

        # Thumbnail (prefer explicit field, else first shop image)
        thumbnail_url = None
        if hasattr(vendor, "thumbnail_image") and getattr(vendor, "thumbnail_image"):
            try:
                thumbnail_url = request.build_absolute_uri(vendor.thumbnail_image.url)
            except Exception:
                thumbnail_url = None
        elif shop_images_full:
            thumbnail_url = shop_images_full[0]

        return Response({
            "success": True,
            "profile_complete": vendor.is_profile_complete,
            "vendor": {
                "id": vendor.id,
                "vendor_name": vendor.vendor_name or "",
                "shop_name": vendor.shop_name or "",
                "phone_number": vendor.phone_number or "",
                "shop_address": vendor.shop_address or "",
                "category": vendor.category or "",
                "latitude": float(vendor.latitude) if vendor.latitude else None,
                "longitude": float(vendor.longitude) if vendor.longitude else None,
                "thumbnail_image": thumbnail_url,
                "shop_images": shop_images_full,
                "description": vendor.description or "",
                "activities": vendor.activities or [],
                "rating": float(vendor.rating) if vendor.rating else 0.0,
                "review_count": vendor.review_count or 0,
                "nid_front": request.build_absolute_uri(vendor.nid_front.url) if vendor.nid_front else None,
                "nid_back": request.build_absolute_uri(vendor.nid_back.url) if vendor.nid_back else None,
                "trade_license": request.build_absolute_uri(vendor.trade_license.url) if vendor.trade_license else None,
            }
        }, status=200)

    def post(self, request):
        user = request.user
        if user.role != 'vendor':
            return Response({"success": False, "message": "Only vendors can complete profile"}, status=403)

        try:
            vendor = Vendor.objects.get(user=user)
        except Vendor.DoesNotExist:
            return Response({"success": False, "message": "Vendor profile not found"}, status=404)

        data = request.data

        # Basic fields
        vendor.vendor_name = data.get('vendor_name', vendor.vendor_name)
        vendor.shop_name = data.get('shop_name', vendor.shop_name)
        vendor.phone_number = data.get('phone_number', vendor.phone_number)
        vendor.shop_address = data.get('shop_address', vendor.shop_address)
        vendor.category = data.get('category', vendor.category)
        vendor.description = data.get('description', vendor.description)
        vendor.website = data.get('website', vendor.website)

        # Location
        if data.get('latitude'):
            vendor.latitude = Decimal(str(data.get('latitude')))
        if data.get('longitude'):
            vendor.longitude = Decimal(str(data.get('longitude')))

        # Activities
        activities = data.get('activities')
        if activities:
            if isinstance(activities, str):
                try:
                    activities = json.loads(activities)
                except Exception:
                    activities = [a.strip() for a in activities.split(',') if a.strip()]
            vendor.activities = activities

        # Rating & Review Count
        if data.get('rating') is not None:
            try:
                vendor.rating = float(data.get('rating'))
            except (ValueError, TypeError):
                pass

        if data.get('review_count') is not None:
            try:
                vendor.review_count = int(data.get('review_count'))
            except (ValueError, TypeError):
                pass

        # Shop Images (start with existing images)
        shop_images = vendor.shop_images or []

        # Decide whether to replace existing images or append.
        # If any uploaded file key mentions shop_image(s) we treat this request as replacing
        # the vendor's existing shop_images with the newly uploaded ones.
        try:
            uploaded_keys = list(request.FILES.keys())
        except Exception:
            uploaded_keys = []

        has_new_shop_images = any(
            k.startswith('shop_image') or 'shop_images' in k
            for k in uploaded_keys
        )

        if has_new_shop_images:
            shop_images = []

    # Quick debug info about uploaded files
        try:
            uploaded_keys = list(request.FILES.keys())
            # Count total files uploaded (supports repeated keys)
            uploaded_count = sum(len(request.FILES.getlist(k)) if hasattr(request.FILES, 'getlist') else 1 for k in request.FILES.keys())
        except Exception:
            uploaded_keys = list(request.FILES.keys())
            uploaded_count = len(uploaded_keys)

        # 1) Accept multiple files under the single key 'shop_images' (common in Postman / JS clients)
        for file in request.FILES.getlist('shop_images'):
            ext = os.path.splitext(file.name)[1].lower()
            filename = f"{uuid.uuid4().hex}{ext}"
            path = f"vendors/{vendor.id}/{filename}"
            saved_path = default_storage.save(path, file)
            shop_images.append(f"/media/{saved_path}")

        # 2) Also accept array-style key 'shop_images[]'
        for file in request.FILES.getlist('shop_images[]'):
            ext = os.path.splitext(file.name)[1].lower()
            filename = f"{uuid.uuid4().hex}{ext}"
            path = f"vendors/{vendor.id}/{filename}"
            saved_path = default_storage.save(path, file)
            shop_images.append(f"/media/{saved_path}")

        # 3) Keep backward-compatible support for individual keys like shop_image1, shop_image2
        for key in request.FILES:
            if key.startswith('shop_image'):
                file = request.FILES[key]
                ext = os.path.splitext(file.name)[1].lower()
                filename = f"{uuid.uuid4().hex}{ext}"
                path = f"vendors/{vendor.id}/{filename}"
                saved_path = default_storage.save(path, file)
                shop_images.append(f"/media/{saved_path}")

        vendor.shop_images = shop_images

        # NID & Trade License
        # Thumbnail image (optional): save separately and ensure it becomes the first image in shop_images
        if request.FILES.get('thumbnail_image'):
            file = request.FILES['thumbnail_image']
            ext = os.path.splitext(file.name)[1].lower()
            path = f"vendors/{vendor.id}/thumbnail{ext}"
            # remove old thumbnail file if exists
            if hasattr(vendor, 'thumbnail_image') and vendor.thumbnail_image and hasattr(vendor.thumbnail_image, 'path'):
                try:
                    if os.path.exists(vendor.thumbnail_image.path):
                        os.remove(vendor.thumbnail_image.path)
                except Exception:
                    pass
            # save thumbnail to the ImageField
            vendor.thumbnail_image.save(os.path.basename(file.name), file, save=False)
        if request.FILES.get('nid_front'):
            file = request.FILES['nid_front']
            ext = os.path.splitext(file.name)[1].lower()
            path = f"vendors/{vendor.id}/nid_front{ext}"
            if vendor.nid_front and hasattr(vendor.nid_front, 'path'):
                if os.path.exists(vendor.nid_front.path):
                    os.remove(vendor.nid_front.path)  # Remove old file
            vendor.nid_front.save(os.path.basename(file.name), file, save=True)

        if request.FILES.get('nid_back'):
            file = request.FILES['nid_back']
            ext = os.path.splitext(file.name)[1].lower()
            path = f"vendors/{vendor.id}/nid_back{ext}"
            if vendor.nid_back and hasattr(vendor.nid_back, 'path'):
                if os.path.exists(vendor.nid_back.path):
                    os.remove(vendor.nid_back.path)  # Remove old file
            vendor.nid_back.save(os.path.basename(file.name), file, save=True)

        if request.FILES.get('trade_license'):
            file = request.FILES['trade_license']
            ext = os.path.splitext(file.name)[1].lower()
            path = f"vendors/{vendor.id}/trade_license{ext}"
            if vendor.trade_license and hasattr(vendor.trade_license, 'path'):
                if os.path.exists(vendor.trade_license.path):
                    os.remove(vendor.trade_license.path)  # Remove old file
            vendor.trade_license.save(os.path.basename(file.name), file, save=True)

        # Ensure thumbnail (if present) is reflected in shop_images as the first item
        try:
            if vendor.thumbnail_image and vendor.thumbnail_image.url:
                thumb_path = f"/media/{vendor.thumbnail_image.name}" if not vendor.thumbnail_image.name.startswith('/media/') else vendor.thumbnail_image.name
                # remove any existing occurrence of this path in shop_images
                shop_images = [p for p in shop_images if p != thumb_path]
                # put thumbnail at the start
                shop_images.insert(0, thumb_path)
        except Exception:
            pass

        vendor.shop_images = shop_images
        vendor.is_profile_complete = True
        vendor.save()

        # build full URLs for response
        base_url = request.build_absolute_uri('/')[:-1]
        shop_images_full = []
        if vendor.shop_images:
            for img in vendor.shop_images:
                if img.startswith('http'):
                    shop_images_full.append(img)
                else:
                    shop_images_full.append(f"{base_url}{img}")
        # Build response like GET so POST returns the same structure
        thumbnail_url = None
        if hasattr(vendor, "thumbnail_image") and getattr(vendor, "thumbnail_image"):
            try:
                thumbnail_url = request.build_absolute_uri(vendor.thumbnail_image.url)
            except Exception:
                thumbnail_url = None
        # If no explicit thumbnail, fallback to first shop image
        if not thumbnail_url and shop_images_full:
            thumbnail_url = shop_images_full[0]

        response_payload = {
            "success": True,
            "profile_complete": vendor.is_profile_complete,
            "message": "Profile completed successfully!",
            "vendor": {
                "id": vendor.id,
                "vendor_name": vendor.vendor_name or "",
                "shop_name": vendor.shop_name or "",
                "phone_number": vendor.phone_number or "",
                "shop_address": vendor.shop_address or "",
                "category": vendor.category or "",
                "latitude": float(vendor.latitude) if vendor.latitude else None,
                "longitude": float(vendor.longitude) if vendor.longitude else None,
                "thumbnail_image": thumbnail_url,
                "shop_images": shop_images_full,
                "description": vendor.description or "",
                "activities": vendor.activities or [],
                "rating": float(vendor.rating) if vendor.rating else 0.0,
                "review_count": vendor.review_count or 0,
                "nid_front": request.build_absolute_uri(vendor.nid_front.url) if vendor.nid_front else None,
                "nid_back": request.build_absolute_uri(vendor.nid_back.url) if vendor.nid_back else None,
                "trade_license": request.build_absolute_uri(vendor.trade_license.url) if vendor.trade_license else None,
            }
        }

        # Add debug info when DEBUG is True so we can see what arrived vs what was saved
        if getattr(settings, 'DEBUG', False):
            try:
                saved_count = len(vendor.shop_images) if vendor.shop_images else 0
            except Exception:
                saved_count = len(shop_images)

            response_payload['debug'] = {
                'uploaded_keys': uploaded_keys,
                'uploaded_count': uploaded_count,
                'saved_count': saved_count,
            }

        return Response(response_payload, status=200)




class AllVendorsListView(APIView):
    permission_classes = [AllowAny]   # চাইলে IsAuthenticated করতে পারো

    def get(self, request):
        vendors = User.objects.filter(role="vendor")

        data = []

        for user in vendors:
            if not hasattr(user, "vendor_profile"):
                continue

            v = user.vendor_profile

            data.append({
                "id": user.id,
                "vendor_name": v.vendor_name,
                "shop_name": v.shop_name,
                "phone_number": v.phone_number,
                "shop_address": v.shop_address,
                "category": v.category,
                "latitude": str(v.latitude) if v.latitude else "",
                "longitude": str(v.longitude) if v.longitude else "",
                "shop_images": v.shop_images or [],
                "description": v.description or "",
                "activities": v.activities or [],
                "rating": float(v.rating) if v.rating else 0.0,
                "review_count": v.review_count or 0
            })

        return Response({
            "success": True,
            "total_vendors": len(data),
            "vendors": data
        }, status=200)


# authentication/views.py → CompleteVendorProfileView এর নিচে যোগ করো
# ================== VENDOR: প্রোফাইল আপডেট রিকোয়েস্ট করা ==================
# authentication/views.py
# authentication/views.py → VendorProfileUpdateRequestView (ফাইনাল + কাজ করা ভার্সন)




class VendorProfileUpdateRequestView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]  # এটা না থাকলে ইমেজ + FormData কাজ করবে না!

    def post(self, request):
        if request.user.role != 'vendor':
            return Response({
                "success": False,
                "message": "শুধুমাত্র ভেন্ডর এই কাজ করতে পারবে"
            }, status=403)

        try:
            vendor = request.user.vendor_profile
        except AttributeError:
            return Response({
                "success": False,
                "message": "ভেন্ডর প্রোফাইল পাওয়া যায়নি। প্রথমে প্রোফাইল কমপ্লিট করুন।"
            }, status=404)

        data = request.data.copy()
        files = request.FILES

        allowed_fields = [
            'shop_name', 'vendor_name', 'phone_number', 'shop_address',
            'category', 'latitude', 'longitude',
            'rating', 'review_count',
            'description', 'activities'
        ]

        new_data = {}

        # === description হ্যান্ডলিং ===
        if 'description' in data:
            desc = data['description']
            new_data['description'] = str(desc).strip() if desc and str(desc).strip() else ""

        # === activities হ্যান্ডলিং (মূল সমাধান এখানে!) ===
        if 'activities' in data:
            acts_input = data['activities']

            if isinstance(acts_input, str) and acts_input.strip():
                try:
                    # প্রথমে JSON পার্স করার চেষ্টা করো
                    parsed = json.loads(acts_input)
                    if isinstance(parsed, list):
                        new_data['activities'] = [str(item).strip() for item in parsed if str(item).strip()]
                    else:
                        new_data['activities'] = []
                except:
                    # JSON না হলে কমা দিয়ে স্প্লিট করো
                    items = [item.strip() for item in acts_input.split(',') if item.strip()]
                    new_data['activities'] = items
            elif isinstance(acts_input, list):
                new_data['activities'] = [str(item).strip() for item in acts_input if str(item).strip()]
            else:
                new_data['activities'] = []

        # === বাকি ফিল্ডগুলো ===
        for key in allowed_fields:
            if key in ['description', 'activities']:
                continue

            value = data.get(key)
            if value in [None, '', 'null', 'undefined', 'None']:
                continue

            if key == 'rating':
                try:
                    value = round(float(value), 2)
                    if not 0 <= value <= 5:
                        return Response({"success": False, "message": "রেটিং ০-৫ এর মধ্যে হতে হবে"}, status=400)
                except:
                    return Response({"success": False, "message": "রেটিং সঠিক ফরম্যাটে দিন"}, status=400)

            elif key == 'review_count':
                try:
                    value = max(0, int(value))
                except:
                    return Response({"success": False, "message": "রিভিউ সংখ্যা সঠিক হতে হবে"}, status=400)

            elif key in ['latitude', 'longitude']:
                try:
                    value = str(value)
                except:
                    continue

            new_data[key] = value

        # === ইমেজ আপলোড ===
        uploaded_shop_images = []
        if 'shop_images' in files:
            for file in files.getlist('shop_images'):
                ext = os.path.splitext(file.name)[1].lower()
                if ext not in ['.jpg', '.jpeg', '.png', '.webp', '.gif']:
                    continue
                filename = f"update_{uuid.uuid4().hex}{ext}"
                path = default_storage.save(f'vendor_update_docs/shop_images/{filename}', ContentFile(file.read()))
                uploaded_shop_images.append(request.build_absolute_uri(settings.MEDIA_URL + path))

        # === রিকোয়েস্ট সেভ করা ===
        update_request = VendorProfileUpdateRequest.objects.create(
            vendor=vendor,
            requested_by=request.user,
            new_data=new_data,
            nid_front=files.get('nid_front'),
            nid_back=files.get('nid_back'),
            trade_license=files.get('trade_license'),
            shop_images=uploaded_shop_images
        )

        return Response({
            "success": True,
            "message": "প্রোফাইল আপডেট রিকোয়েস্ট সফলভাবে পাঠানো হয়েছে। এডমিন শীঘ্রই রিভিউ করবে।",
            "request_id": update_request.id,
            "status": update_request.status,
            "requested_changes": new_data,
            "uploaded_shop_images_count": len(uploaded_shop_images),
            "preview_images": uploaded_shop_images[:3]
        }, status=201)

    def get(self, request):
        if request.user.role != 'vendor':
            return Response({"success": False, "message": "অ্যাক্সেস নিষেধ"}, status=403)

        try:
            vendor = request.user.vendor_profile
            requests = vendor.update_requests.all().order_by('-created_at')
            data = []
            for r in requests:
                data.append({
                    "id": r.id,
                    "status": r.status,
                    "status_bangla": dict(VendorProfileUpdateRequest.STATUS_CHOICES).get(r.status, r.status),
                    "requested_at": r.created_at.strftime("%d %b %Y, %I:%M %p"),
                    "reviewed_at": r.reviewed_at.strftime("%d %b %Y, %I:%M %p") if r.reviewed_at else None,
                    "reason": r.reason or "কোনো কারণ দেওয়া হয়নি",
                    "new_data": r.new_data,
                    "documents": {
                        "nid_front": request.build_absolute_uri(r.nid_front.url) if r.nid_front else None,
                        "nid_back": request.build_absolute_uri(r.nid_back.url) if r.nid_back else None,
                        "trade_license": request.build_absolute_uri(r.trade_license.url) if r.trade_license else None,
                    },
                    "shop_images": r.shop_images or []
                })
            return Response({"success": True, "requests": data})
        except:
            return Response({"success": False, "message": "প্রোফাইল পাওয়া যায়নি"})



# views.py এর মধ্যে যেকোনো জায়গায় যোগ করো (Admin section এর কাছে ভালো)
# views.py তে যোগ করো

# views.py তে যোগ করো (Admin section এর কাছে)



class AdminPendingVendorUpdateRequestsView(APIView):
   
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if request.user.role != 'admin':
            return Response({
                "success": False,
                "message": "Only admins can view this information"
            }, status=403)

        # শুধু পেন্ডিং রিকোয়েস্ট
        pending_requests = VendorProfileUpdateRequest.objects.filter(
            status='pending'
        ).select_related(
            'vendor', 'vendor__user', 'requested_by'
        ).order_by('-created_at')

        total_pending = pending_requests.count()
        request_list = []

        for req in pending_requests:
            vendor = req.vendor
            new_data = req.new_data or {}
            changes = []

            # ফিল্ড ম্যাপিং: (বাংলা নাম, পুরানো ভ্যালু)
            field_mapping = {
                'vendor_name': ('Vendor Name', vendor.vendor_name or "Not provided"),
                'shop_name': ('Shop Name', vendor.shop_name or "Not provided"),
                'phone_number': ('Phone Number', vendor.phone_number or "Not provided"),
                'shop_address': ('Shop Address', vendor.shop_address or "Not provided"),
                'category': ('Category', vendor.category or "Not provided"),
                'description': ('Description', vendor.description or "Not provided"),
                'activities': ('Activities', ", ".join(vendor.activities) if vendor.activities else "Not provided"),
                'rating': ('Rating', float(vendor.rating) if v.vendor_rating else 0.0),
                'review_count': ('Review Count', vendor.review_count if vendor.review_count else 0),
            }

            # প্রতিটি ফিল্ড চেক করি যেটা চেঞ্জ করতে চাইছে
            for field_key, (bangla_name, old_value) in field_mapping.items():
                if field_key in new_data:
                    new_value = new_data[field_key]

                    # activities লিস্ট হলে স্ট্রিং করি
                    if field_key == 'activities' and isinstance(new_value, list):
                        new_value = ", ".join(new_value) if new_value else "Not provided"

                    # রেটিং ফ্লোট করি
                    if field_key == 'rating':
                        try:
                            new_value = float(new_value)
                        except (ValueError, TypeError):
                            new_value = old_value

                    # পুরানো vs নতুন তুলনা
                    old_str = str(old_value).strip()
                    new_str = str(new_value).strip() if new_value is not None else ""

                    changes.append({
                        "field": bangla_name,
                        "old": old_str if old_str != "Not provided" else "Not provided",
                        "new": new_str if new_str else "Not provided",
                        "changed": old_str != new_str
                    })

            # ছবি চেক
            new_images_count = len(req.shop_images) if req.shop_images else 0
            old_images_count = len(vendor.shop_images) if vendor.shop_images else 0

            # ডকুমেন্ট URL
            documents = {
                "nid_front": request.build_absolute_uri(req.nid_front.url) if req.nid_front else None,
                "nid_back": request.build_absolute_uri(req.nid_back.url) if req.nid_back else None,
                "trade_license": request.build_absolute_uri(req.trade_license.url) if req.trade_license else None,
            }

            request_list.append({
                "request_id": req.id,
                "vendor_id": vendor.id,
                "vendor_email": vendor.user.email,
                "shop_name": vendor.shop_name or "Name not provided",
                "phone_number": vendor.phone_number or "not provided",
                "requested_by": req.requested_by.email,
                "requested_at": req.created_at.strftime("%d %b %Y, %I:%M %p"),
                "time_ago": self._time_ago(req.created_at),

                # Main thing: old vs new
                "changes": changes,
                "total_changes": len(changes),

                # Images
                "current_images": old_images_count,
                "will_add_images": new_images_count,
                "new_shop_images_preview": req.shop_images[:3] if req.shop_images else [],

                # Documents
                "has_documents": bool(req.nid_front or req.nid_back or req.trade_license),
                "documents": documents,
            })

        return Response({
            "success": True,
            "total_pending": total_pending,
            "message": f"Total {total_pending} pending requests" if total_pending else "No pending requests",
            "pending_requests": request_list
        }, status=200)

    # বোনাস: কতক্ষণ আগে রিকোয়েস্ট পাঠিয়েছে
    def _time_ago(self, past_time):
        now = timezone.now()
        diff = now - past_time

        if diff.days > 0:
            return f"{diff.days} days ago"
        elif diff.seconds >= 7200:
            return f"{diff.seconds // 3600} hours ago"
        elif diff.seconds >= 3600:
            return "1 hour ago"
        elif diff.seconds >= 120:
            return f"{diff.seconds // 60} minutes ago"
        elif diff.seconds >= 60:
            return "1 minute ago"
        else:
            return "Just now"

# ================== ADMIN ONLY API: Approve / Reject (Postman Friendly) ==================


# ================== ADMIN ONLY: Approve / Reject Vendor Update Request (100% Working) ==================

# =============================================================================
# ADMIN PANEL: Vendor Management APIs (ফাইনাল, সাজানো-গোছানো ভার্সন)
# =============================================================================



# -----------------------------------------------------------------------------
# সহায়ক ফাংশন: ফাইল কপি করা (নিরাপদে)
# -----------------------------------------------------------------------------
def copy_uploaded_file(source_field, target_field):
    """UploadedFile কে অন্য ফিল্ডে সঠিকভাবে কপি করে। পুরানো ফাইল মুছে ফেলে।"""
    if not source_field:
        return

    # পুরানো ফাইল থাকলে মুছে ফেলো
    if target_field:
        target_field.delete(save=False)

    try:
        source_field.open('rb')
        file_name = os.path.basename(source_field.name)
        target_field.save(file_name, File(source_field), save=False)
    except Exception as e:
        logger.error(f"File copy failed: {e}")
    finally:
        source_field.close()


# =============================================================================
# HELPER FUNCTIONS: Location parsing
# =============================================================================
def _parse_coord(value):
    """Safely convert Decimal/str/float to float or return None."""
    if value is None:
        return None
    if isinstance(value, str) and value.strip().lower() in ('', 'null', 'none', 'undefined'):
        return None
    try:
        return float(value)
    except Exception:
        try:
            return float(str(value).strip())
        except Exception:
            return None


def _get_location_from_request(request):
    """
    Extract (lat, lng) from:
      1) JWT payload in request.auth (keys: latitude/longitude, lat/lng, user_lat/user_lng)
      2) request.user.profile latitude/longitude
    Returns (float_lat, float_lng) or (None, None)
    """
    # 1) Try token payload
    try:
        token = getattr(request, "auth", None)
        if token:
            token_str = token if isinstance(token, str) else str(token)
            payload = {}
            try:
                payload = pyjwt.decode(token_str, settings.SECRET_KEY, algorithms=["HS256"], options={"verify_exp": False})
            except Exception:
                try:
                    payload = jose_jwt.decode(token_str, settings.SECRET_KEY, algorithms=["HS256"], options={"verify_exp": False})
                except Exception:
                    payload = {}

            lat = payload.get("latitude") or payload.get("lat") or payload.get("user_lat")
            lng = payload.get("longitude") or payload.get("lng") or payload.get("user_lng")
            plat = _parse_coord(lat)
            plng = _parse_coord(lng)
            if plat is not None and plng is not None:
                return plat, plng
    except Exception:
        pass

    # 2) Fallback to profile
    try:
        profile = getattr(request.user, "profile", None)
        if profile:
            plat = _parse_coord(getattr(profile, "latitude", None))
            plng = _parse_coord(getattr(profile, "longitude", None))
            if plat is not None and plng is not None:
                return plat, plng
    except Exception:
        pass

    return None, None


def calculate_distance(lat1, lon1, lat2, lon2):
    R = 6371  # Earth radius in km
    lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
    return R * c




def haversine_distance(lat1, lon1, lat2, lon2):
    R = 6371  # পৃথিবীর ব্যাসার্ধ (কিমি)
    lat1, lon1, lat2, lon2 = map(float, [lat1, lon1, lat2, lon2])
    lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c * 1000  # মিটারে কনভার্ট

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_nearby_vendors(request):

    # ===============================
    # ইউজারের লোকেশন: token -> profile
    # ===============================
    user_lat, user_lng = _get_location_from_request(request)

    if user_lat is None or user_lng is None:
        return Response({
            "success": False,
            "message": "Your profile does not have location information. Please update it."
        }, status=400)

    # শুধুমাত্র প্রোফাইল কমপ্লিট এবং লোকেশন সেট করা ভেন্ডর
    vendors = Vendor.objects.filter(
        is_profile_complete=True,
        latitude__isnull=False,
        longitude__isnull=False
    )

    nearby_vendors = []

    for vendor in vendors:
        distance_meters = haversine_distance(
            user_lat, user_lng,
            vendor.latitude, vendor.longitude
        )

        # ২ কিলোমিটারের মধ্যে
        if distance_meters <= 2000:
            nearby_vendors.append({
                "id": vendor.id,
                "vendor_name": vendor.vendor_name or "N/A",
                "shop_name": vendor.shop_name or "N/A",
                "phone_number": vendor.phone_number or "N/A",
                "email": vendor.user.email if hasattr(vendor, 'user') and vendor.user else "N/A",
                "shop_address": vendor.shop_address or "N/A",
                "category": vendor.category or "others",
                "description": vendor.description or "",
                "activities": vendor.activities or [],
                "rating": float(vendor.rating) if vendor.rating else 0.0,
                "review_count": vendor.review_count or 0,
                "shop_images": vendor.shop_images or [],
                "distance_meters": round(distance_meters, 1),
                "location": {
                    "latitude": str(vendor.latitude),
                    "longitude": str(vendor.longitude)
                }
            })

    # দূরত্ব অনুযায়ী সর্ট করা
    nearby_vendors.sort(key=lambda x: x['distance_meters'])

    return Response({
        "success": True,
        "your_location": {
            "lat": user_lat,
            "lng": user_lng
        },
        "search_radius_meters": 2000,
        "total_found": len(nearby_vendors),
        "vendors": nearby_vendors
    }, status=200)





# Haversine distance
def haversine_distance(lat1, lon1, lat2, lon2):
    R = 6371  # পৃথিবীর ব্যাসার্ধ (কিমি)
    lat1, lon1, lat2, lon2 = map(float, [lat1, lon1, lat2, lon2])
    lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c * 1000  # মিটারে কনভার্ট

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def category_nearby_vendors(request, category):  # এখানে category path থেকে আসবে
    # ===============================
    # ইউজারের প্রোফাইল থেকে লোকেশন নেওয়া
    # ===============================
    user_lat, user_lng = _get_location_from_request(request)
    if user_lat is None or user_lng is None:
        return Response({
            "success": False,
            "message": "Your profile does not have location information. Please update it.",
            "debug": {
                "profile_exists": bool(getattr(request.user, "profile", None))
            }
        }, status=400)

    vendors = Vendor.objects.filter(is_profile_complete=True, latitude__isnull=False, longitude__isnull=False, category__iexact=category.strip())
    nearby_vendors = []
    for vendor in vendors:
        vlat = _parse_coord(vendor.latitude)
        vlng = _parse_coord(vendor.longitude)
        if vlat is None or vlng is None:
            continue
        distance_m = haversine_distance(user_lat, user_lng, vlat, vlng)
        if distance_m <= 2000:
            nearby_vendors.append({
                "id": vendor.id,
                "vendor_name": vendor.vendor_name or "N/A",
                "shop_name": vendor.shop_name or "N/A",
                "distance_meters": round(distance_m, 1),
                "location": {"latitude": str(vendor.latitude), "longitude": str(vendor.longitude)}
            })
    nearby_vendors.sort(key=lambda x: x['distance_meters'])
    return Response({
        "success": True,
        "your_location": {"lat": user_lat, "lng": user_lng},
        "search_radius_meters": 2000,
        "category": category,
        "total_found": len(nearby_vendors),
        "vendors": nearby_vendors
    }, status=200)






# views.py এর শেষে যোগ করো


class AdminAllVendorCredentialsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if request.user.role != 'admin':
            return Response({
                "success": False,
                "message": "Only admins can view this information"
            }, status=403)

        vendors = Vendor.objects.select_related('user').all().order_by('-created_at')
        credentials = []

        for vendor in vendors:
            if vendor.plain_password:  # যাদের পাসওয়ার্ড সেভ আছে
                credentials.append({
                    "vendor_id": vendor.id,
                    "shop_name": vendor.shop_name if vendor.shop_name != "N/A" else "not given name",
                    "email": vendor.user.email,
                    "password": vendor.plain_password,  # প্লেইন টেক্সট পাসওয়ার্ড
                    "created_at": vendor.user.date_joined.strftime("%d %b %Y, %I:%M %p")
                })

        return Response({
            "success": True,
            "total_vendors": len(credentials),
            "credentials": credentials
        })


# authentication/views.py এর শেষে যোগ করো

class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = ["id", "title", "message", "aliffited_id", "shop_name", "reward_name", "is_read", "created_at"]

class NotificationListAPI(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        qs = Notification.objects.filter(user=request.user).order_by("-created_at")
        serializer = NotificationSerializer(qs, many=True)
        return Response({
            "success": True,
            "count": qs.count(),
            "notifications": serializer.data
        })



@api_view(['GET'])
@permission_classes([IsAuthenticated])
def live_users_view(request):
    live_users_data = []

    for user_id in ONLINE_USERS:
        try:
            profile = Profile.objects.get(user_id=user_id)
            live_users_data.append({
                "user_id": user_id,
                "email": profile.user.email,
                "latitude": profile.latitude,
                "longitude": profile.longitude,
                "last_seen": profile.updated_at.strftime("%H:%M:%S") if hasattr(profile, "updated_at") else None
            })
        except Profile.DoesNotExist:
            live_users_data.append({
                "user_id": user_id,
                "email": None,
                "latitude": None,
                "longitude": None,
                "last_seen": None
            })

    return Response({
        "success": True,
        "total_online": len(ONLINE_USERS),
        "live_users": live_users_data,
        "timestamp": datetime.now().strftime("%H:%M:%S")
    })
# =============================================================================
# ADMIN: Approve/Reject Vendor Update Request
# =============================================================================
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def approve_vendor_update_request(request, request_id):
    """Admin approves a vendor profile update request."""
    if request.user.role != 'admin':
        return Response({
            "success": False,
            "message": "Only admins can approve requests"
        }, status=403)

    try:
        update_request = VendorProfileUpdateRequest.objects.get(id=request_id)
    except VendorProfileUpdateRequest.DoesNotExist:
        return Response({
            "success": False,
            "message": "Request not found"
        }, status=404)

    if update_request.status != 'pending':
        return Response({
            "success": False,
            "message": f"Request already {update_request.status}"
        }, status=400)

    vendor = update_request.vendor
    new_data = update_request.new_data or {}

    # Apply changes to vendor profile
    field_mapping = {
        'vendor_name': 'vendor_name',
        'shop_name': 'shop_name',
        'phone_number': 'phone_number',
        'shop_address': 'shop_address',
        'category': 'category',
        'description': 'description',
        'activities': 'activities',
        'latitude': 'latitude',
        'longitude': 'longitude',
        'rating': 'rating',
        'review_count': 'review_count',
    }

    for key, attr in field_mapping.items():
        if key in new_data:
            value = new_data[key]
            if key in ['latitude', 'longitude']:
                try:
                    value = Decimal(str(value))
                except:
                    continue
            elif key == 'rating':
                try:
                    value = float(value)
                except:
                    continue
            elif key == 'review_count':
                try:
                    value = int(value)
                except:
                    continue
            setattr(vendor, attr, value)

    # Add new shop images if any
    if update_request.shop_images:
        existing_images = vendor.shop_images or []
        existing_images.extend(update_request.shop_images)
        vendor.shop_images = existing_images

    # Copy documents if provided
    if update_request.nid_front:
        copy_uploaded_file(update_request.nid_front, vendor.nid_front)
    if update_request.nid_back:
        copy_uploaded_file(update_request.nid_back, vendor.nid_back)
    if update_request.trade_license:
        copy_uploaded_file(update_request.trade_license, vendor.trade_license)

    vendor.save()

    # Update request status
    update_request.status = 'approved'
    update_request.reviewed_by = request.user
    update_request.reviewed_at = timezone.now()
    update_request.save()

    # Send notification to vendor
    try:
        Notification.objects.create(
            user=vendor.user,
            title="প্রোফাইল আপডেট অনুমোদিত",
            message="আপনার প্রোফাইল আপডেট রিকোয়েস্ট অনুমোদন করা হয়েছে।"
        )
    except:
        pass

    return Response({
        "success": True,
        "message": "Vendor profile update approved successfully",
        "request_id": request_id,
        "vendor_id": vendor.id,
        "shop_name": vendor.shop_name
    }, status=200)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def reject_vendor_update_request(request, request_id):
    """Admin rejects a vendor profile update request."""
    if request.user.role != 'admin':
        return Response({
            "success": False,
            "message": "Only admins can reject requests"
        }, status=403)

    try:
        update_request = VendorProfileUpdateRequest.objects.get(id=request_id)
    except VendorProfileUpdateRequest.DoesNotExist:
        return Response({
            "success": False,
            "message": "Request not found"
        }, status=404)

    if update_request.status != 'pending':
        return Response({
            "success": False,
            "message": f"Request already {update_request.status}"
        }, status=400)

    reason = request.data.get('reason', 'No reason provided')

    update_request.status = 'rejected'
    update_request.reason = reason
    update_request.reviewed_by = request.user
    update_request.reviewed_at = timezone.now()
    update_request.save()

    # Send notification to vendor
    try:
        Notification.objects.create(
            user=update_request.vendor.user,
            title="প্রোফাইল আপডেট প্রত্যাখ্যাত",
            message=f"আপনার প্রোফাইল আপডেট রিকোয়েস্ট প্রত্যাখ্যান করা হয়েছে। কারণ: {reason}"
        )
    except:
        pass

    return Response({
        "success": True,
        "message": "Vendor profile update rejected",
        "request_id": request_id,
        "reason": reason
    }, status=200)



# google and apple login


# ===============================
# ✅ Helper Functions
# ===============================
def generate_unique_username(email):
    """Email থেকে unique username তৈরি করুন"""
    base_username = email.split("@")[0]
    username = base_username
    counter = 1
    
    while User.objects.filter(username=username).exists():
        username = f"{base_username}{counter}"
        counter += 1
    
    return username


def random_username():
    """Generate random Apple username"""
    return "apple_" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))


# ===============================
# ✅ Google Login - আসল CallBack
# ===============================
class GoogleLoginView(APIView):
    """Flutter থেকে Google token পাবে এবং verify করবে"""
    permission_classes = [AllowAny]

    def post(self, request):
        id_token = request.data.get("id_token")  # Flutter থেকে আসবে
        
        if not id_token:
            return Response({"error": "id_token is required"}, status=400)

        try:
            # Google Token Verify করুন
            from google.auth.transport import requests as google_requests
            from google.oauth2 import id_token
            
            request_obj = google_requests.Request()
            payload = id_token.verify_oauth2_token(
                id_token, 
                request_obj, 
                settings.GOOGLE_CLIENT_ID
            )
            
            email = payload.get("email")
            full_name = payload.get("name", "")
            picture = payload.get("picture")
            
            if not email:
                return Response({"error": "Email not found"}, status=400)

            # User create/get
            user, created = User.objects.get_or_create(
                email=email,
                defaults={
                    "full_name": full_name,
                    "is_email_verified": True,
                    "is_active": True,
                    "role": "user"
                }
                                             )

            if created:
                user.set_unusable_password()
                user.save()

            # Profile তৈরি করুন
            profile, _ = Profile.objects.get_or_create(user=user)

            # ছবি ডাউনলোড করুন (optional)
            if picture and not profile.image.name:
                try:
                    img_response = requests.get(picture, timeout=10)
                    if img_response.status_code == 200:
                        filename = f"google_{user.id}_{int(time.time())}.jpg"
                        profile.image.save(
                            filename, 
                            ContentFile(img_response.content), 
                            save=True
                        )
                except:
                    pass

            # JWT Token তৈরি করুন
            refresh = RefreshToken.for_user(user)
            Token.objects.filter(user=user).delete()
            token_obj = Token.objects.create(
                user=user,
                email=user.email,
                refresh_token=str(refresh),
                access_token=str(refresh.access_token),
                refresh_token_expires_at=timezone.now() + timedelta(days=30),
                access_token_expires_at=timezone.now() + timedelta(days=365),
                revoked=False
            )

            return JsonResponse({
                "success": True,
                "created": created,
                "refresh": str(refresh),
                "access": str(refresh.access_token),
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "full_name": user.full_name or "",
                    "profile_image": request.build_absolute_uri(profile.image.url) if profile.image else None,
                }
            }, status=200)

        except Exception as e:
            logger.error(f"Google login error: {str(e)}", exc_info=True)
            return JsonResponse({"error": f"Login failed: {str(e)}"}, status=500)


# ===============================
# ✅ Apple Login
# ===============================
class AppleLoginView(APIView):
    """Flutter থেকে Apple identity token পাবে"""
    permission_classes = [AllowAny]

    def post(self, request):
        id_token = request.data.get("id_token")
        email = request.data.get("email", "").strip().lower()  # ✅ Request থেকে নিন
        full_name = request.data.get("full_name", "").strip()
        
        if not id_token:
            return Response({"error": "id_token is required"}, status=400)

        if not email:
            return Response({"error": "Email is required"}, status=400)

        try:
            import jwt as pyjwt
            
            # Token decode
            decoded = pyjwt.decode(
                id_token,
                options={"verify_signature": False}
            )

            apple_id = decoded.get("sub")

            # User create/get (email normalize করে)
            user, created = User.objects.get_or_create(
                email=email,  # ✅ Normalized email
                defaults={
                    "full_name": full_name or "Apple User",
                    "is_email_verified": True,
                    "is_active": True,
                    "role": "user"
                }
            )

            # ✅ Always update profile info (even if user exists)
            updated = False
            if full_name and user.full_name != full_name:
                parts = full_name.split(" ", 1)
                user.first_name = parts[0]
                user.last_name = parts[1] if len(parts) > 1 else ""
                user.full_name = full_name
                updated = True

            # Update email if it changed
            if user.email != email:
                user.email = email
                updated = True

            if updated or created:
                if created:
                    user.set_unusable_password()
                user.save()

            # Profile তৈরি করুন
            profile, _ = Profile.objects.get_or_create(user=user)

            # Gravatar ছবি যোগ করুন
            if not profile.image or not profile.image.name:
                try:
                    email_hash = hashlib.md5(email.lower().encode()).hexdigest()
                    gravatar_url = f"https://www.gravatar.com/avatar/{email_hash}?s=200&d=identicon&r=g"
                    img_response = requests.get(gravatar_url, timeout=10)
                    if img_response.status_code == 200:
                        filename = f"apple_{user.id}_{int(time.time())}.jpg"
                        profile.image.save(filename, ContentFile(img_response.content), save=True)
                except Exception as e:
                    logger.warning(f"Gravatar download failed: {e}")

            # JWT Token তৈরি করুন
            refresh = RefreshToken.for_user(user)
            Token.objects.filter(user=user).delete()
            Token.objects.create(
                user=user,
                email=user.email,  # ✅ Updated email use করুন
                refresh_token=str(refresh),
                access_token=str(refresh.access_token),
                refresh_token_expires_at=timezone.now() + timedelta(days=30),
                access_token_expires_at=timezone.now() + timedelta(days=365),
                revoked=False
            )

            logger.info(f"Apple login {'created' if created else 'logged in'}: {user.email}")

            return JsonResponse({
                "success": True,
                "created": created,
                "access_token": str(refresh.access_token),
                "refresh_token": str(refresh),
                "token_type": "Bearer",
                "user": {
                    "id": user.id,
                    "email": user.email,  # ✅ Updated email
                    "full_name": user.full_name or "",
                    "role": user.role,
                    "profile_picture": request.build_absolute_uri(profile.image.url) if profile.image and profile.image.name else None,
                }
            }, status=200)

        except Exception as e:
            logger.error(f"Apple login failed: {e}", exc_info=True)
            return JsonResponse({
                "error": "Apple login failed",
                "details": str(e)
            }, status=500)

from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
import json
import requests
import time
from django.core.files.base import ContentFile
from django.utils import timezone
from datetime import timedelta
from rest_framework_simplejwt.tokens import RefreshToken
from authentication.models import User, Profile, Token
import logging

logger = logging.getLogger(__name__)

@csrf_exempt
def google_login_view(request):
    """Flutter থেকে Google ID Token পাবে"""
    
    if request.method != 'POST':
        return JsonResponse({"error": "Only POST allowed"}, status=405)
    
    try:
        data = json.loads(request.body)
    except:
        return JsonResponse({"error": "Invalid JSON"}, status=400)

    email = data.get("email", "").strip().lower()  # ✅ Normalize email
    full_name = data.get("full_name", "").strip()
    photo_url = data.get("photo_url")

    if not email:
        return JsonResponse({"error": "Email is required"}, status=400)

    try:
        # User create/get by normalized email
        user, created = User.objects.get_or_create(
            email=email,  # ✅ Exact match হবে
            defaults={
                "full_name": full_name,
                "is_active": True,
                "is_email_verified": True,
                "role": "user"
            }
        )

        # ✅ Always update profile info (even if user exists)
        updated = False
        if full_name and user.full_name != full_name:
            parts = full_name.split(" ", 1)
            user.first_name = parts[0]
            user.last_name = parts[1] if len(parts) > 1 else ""
            user.full_name = full_name
            updated = True

        # Update email if it changed
        if user.email != email:
            user.email = email
            updated = True

        if updated or created:
            if created:
                user.set_unusable_password()
            user.save()

        # Profile
        profile, _ = Profile.objects.get_or_create(user=user)

        # Download profile photo (only if no image exists)
        if photo_url and (not profile.image or not profile.image.name):
            try:
                res = requests.get(photo_url, timeout=10)
                if res.status_code == 200:
                    ext = photo_url.split(".")[-1].split("?")[0]
                    ext = ext if ext.lower() in ["jpg", "jpeg", "png"] else "jpg"
                    filename = f"google_{user.id}_{int(time.time())}.{ext}"
                    profile.image.save(filename, ContentFile(res.content), save=True)
            except Exception as e:
                logger.warning(f"Profile photo download failed: {e}")

        # Tokens
        refresh = RefreshToken.for_user(user)
        Token.objects.filter(user=user).delete()
        token_obj = Token.objects.create(
            user=user,
            email=user.email,  # ✅ Always use latest email
            refresh_token=str(refresh),
            access_token=str(refresh.access_token),
            refresh_token_expires_at=timezone.now() + timedelta(days=30),
            access_token_expires_at=timezone.now() + timedelta(days=365),
            revoked=False
        )

        return JsonResponse({
            "success": True,
            "created": created,
            "access_token": str(refresh.access_token),
            "refresh_token": str(refresh),
            "token_type": "Bearer",
            "user": {
                "id": user.id,
                "email": user.email,  # ✅ Updated email
                "full_name": user.full_name or "",
                "role": user.role,
                "profile_picture": request.build_absolute_uri(profile.image.url) if profile.image and profile.image.name else None,
            }
        }, status=200)

    except Exception as e:
        logger.error(f"Google login error: {str(e)}", exc_info=True)
        return JsonResponse({"error": f"Login failed: {str(e)}"}, status=500)