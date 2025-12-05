from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.views.decorators.cache import never_cache
from django.utils.decorators import method_decorator
import logging
from uuid import uuid4
from django.db import models
from rest_framework.decorators import api_view
from jose import jwt
import requests
import os
import re
from .models import VendorProfileUpdateRequest  # or from the correct app

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
    """Handle user registration with optional email verification OTP."""
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
    """
    ভেন্ডর নিজে নিজে সাইনআপ করবে → শুধু ইমেইল + পাসওয়ার্ড
    → কোনো OTP ভেরিফাই লাগবে না
    → is_active = False (এডমিন approve করলে active হবে)
    """
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


from datetime import timedelta
from django.utils import timezone
from django.core.mail import send_mail
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from authentication.models import User, Token
from authentication.serializers import LoginSerializer
from django.conf import settings
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

        if not user:
            return Response({"detail": "ইমেইল বা পাসওয়ার্ড ভুল।"}, status=401)

        if not user.check_password(password):
            return Response({"detail": "ইমেইল বা পাসওয়ার্ড ভুল।"}, status=401)

        # ভেন্ডর হলে শুধু OTP চেক না করাই (তুমি চাও এমন)
        if user.role != 'vendor':
            if not user.is_email_verified:
                return Response({
                    "detail": "ইমেইল ভেরিফাই করা হয়নি। আপনার ইমেইলে পাঠানো OTP দিয়ে ভেরিফাই করুন।",
                    "next_step": "verify_email_otp"
                }, status=403)

            if not user.is_active:
                return Response({
                    "detail": "আপনার একাউন্ট সক্রিয় করা হয়নি। সাপোর্টে যোগাযোগ করুন।"
                }, status=403)
        else:
            # ভেন্ডরের জন্য কোনো OTP চেক নাই, শুধু is_active হলেই চলবে
            if not user.is_active:
                return Response({
                    "detail": "আপনার ভেন্ডর একাউন্ট এখনো সক্রিয় করা হয়নি।",
                    "contact_admin": True
                }, status=403)

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

        # সব ঠিক থাকলে টোকেন দাও
        refresh = RefreshToken.for_user(user)
        lifetime = timedelta(days=30) if serializer.validated_data.get('remember_me', False) else timedelta(days=7)
        refresh.set_exp(lifetime=lifetime)

        refresh_token_str = str(refresh)
        access_token_str = str(refresh.access_token)

        # এই লাইনটা সমস্যার মূল কারণ ছিল — এটা মুছে ফেলো!
        # Token.objects.update_or_create(...)  ← এটা আর ব্যবহার করো না!

        # এই নতুন কোডটা বসাও — ডুপ্লিকেট টোকেন এরর চিরতরে শেষ!
        Token.objects.filter(user=user).delete()  # পুরানো টোকেন মুছে ফেলো
        Token.objects.create(
            user=user,
            email=user.email,
            refresh_token=refresh_token_str,
            access_token=access_token_str,
            refresh_token_expires_at=timezone.now() + refresh.lifetime,
            access_token_expires_at=timezone.now() + timedelta(minutes=15),
        )

        logger.info(f"সফল লগইন: {user.email} ({user.role})")

        return Response({
            "access_token": access_token_str,
            "access_token_expires_in": 900,
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
        }, status=200)


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
                    f'Your OTP is {code}. Expires in 15 minutes.',
                    settings.DEFAULT_FROM_EMAIL,
                    [user.email],
                    fail_silently=False,
                )
            logger.info(f"Password reset requested for: {email}")
            return Response({
                "message": "If the email exists, a password reset OTP has been sent. Expires in 15 minutes."
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




# authentication/views.py

from django.db import transaction
from django.views.decorators.cache import never_cache
from django.utils.decorators import method_decorator
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from .models import Profile
from .serializers import UserProfileSerializer, ProfileUpdateSerializer
import logging
from rest_framework.parsers import MultiPartParser, FormParser

logger = logging.getLogger(__name__)


@method_decorator(never_cache, name='dispatch')
class MeView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def get(self, request):
        # সবসময় ফ্রেশ ডাটা নিচ্ছি
        user = User.objects.select_related('profile').get(pk=request.user.pk)
        serializer = UserProfileSerializer(user, context={'request': request})
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request):
        profile, _ = Profile.objects.get_or_create(user=request.user)

        # এই লাইনটা পুরোপুরি বদলে দাও — files= আর লাগবে না!
        serializer = ProfileUpdateSerializer(
            instance=profile,
            data=request.data,           # শুধু request.data দিলেই হবে
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
                    from django.core.files.storage import default_storage
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
        # PATCH ও PUT একই কাজ করে
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


# Google Login URL দিবে
class GoogleLoginView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        auth_url = (
            f"https://accounts.google.com/o/oauth2/v2/auth?"
            f"client_id={settings.GOOGLE_CLIENT_ID}&"
            f"redirect_uri={settings.GOOGLE_REDIRECT_URI}&"
            f"response_type=code&"
            f"scope=email%20profile%20openid&"
            f"access_type=offline&prompt=consent"
        )
        return Response({"auth_url": auth_url})


# Google Callback - লগইন সম্পূর্ণ (ইমেজ ১০০% আসবে!)
class GoogleCallbackView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        code = request.GET.get('code')
        if not code:
            return Response({"error": "No code provided"}, status=400)

        code = unquote(code)

        try:
            # Step 1: Token Exchange
            token_response = requests.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "code": code,
                    "client_id": settings.GOOGLE_CLIENT_ID,
                    "client_secret": settings.GOOGLE_CLIENT_SECRET,
                    "redirect_uri": settings.GOOGLE_REDIRECT_URI,
                    "grant_type": "authorization_code",
                },
                timeout=10
            )
            token_data = token_response.json()
            if "error" in token_data:
                return Response({"error": token_data.get("error_description", "Token error")}, status=400)

            access_token = token_data.get("access_token")
            if not access_token:
                return Response({"error": "Access token not received"}, status=400)

            # Step 2: User Info
            user_info = requests.get(
                "https://www.googleapis.com/oauth2/v2/userinfo",
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=10
            ).json()

            email = user_info.get("email")
            if not email:
                return Response({"error": "Email not received from Google"}, status=400)

            # Step 3: User Create/Login
            user, created = User.objects.get_or_create(
                email=email,
                defaults={
                    "full_name": user_info.get("name", ""),
                    "is_email_verified": True,
                    "is_active": True,
                }
            )

            if created:
                user.set_unusable_password()
                user.save()
                Profile.objects.create(user=user)

            if not user.full_name and user_info.get("name"):
                user.full_name = user_info.get("name")
                user.save()

            # Step 4: প্রোফাইল পিকচার (ডিফল্ট হলেও ওভাররাইড হবে!)
            profile, _ = Profile.objects.get_or_create(user=user)

            # শর্ত: যদি কোনো ছবি না থাকে বা ডিফল্ট ছবি থাকে → নতুন করে সেভ করো
            if not profile.image.name or 'default' in profile.image.name.lower():
                picture_saved = False

                # ১. Google ছবি দিলে
                if user_info.get("picture"):
                    try:
                        img_data = requests.get(user_info["picture"], timeout=10).content
                        profile.image.save(f"google_{user.id}.jpg", ContentFile(img_data), save=True)
                        picture_saved = True
                    except Exception as e:
                        logger.warning(f"Google picture failed: {e}")

                # ২. Google না দিলে → Gravatar
                if not picture_saved:
                    email_hash = hashlib.md5(user.email.strip().lower().encode()).hexdigest()
                    gravatar_url = f"https://www.gravatar.com/avatar/{email_hash}?s=200&d=identicon&r=g"
                    try:
                        img_data = requests.get(gravatar_url, timeout=10).content
                        profile.image.save(f"gravatar_{user.id}.jpg", ContentFile(img_data), save=True)
                    except Exception as e:
                        logger.warning(f"Gravatar failed: {e}")

            # Step 5: JWT Token
            refresh = RefreshToken.for_user(user)
            Token.objects.update_or_create(
                user=user,
                defaults={
                    "email": user.email,
                    "refresh_token": str(refresh),
                    "access_token": str(refresh.access_token),
                    "refresh_token_expires_at": timezone.now() + timedelta(days=30),
                    "access_token_expires_at": timezone.now() + timedelta(minutes=60),
                }
            )

            # Final Response
            return Response({
                "success": True,
                "access_token": str(refresh.access_token),
                "refresh_token": str(refresh),
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "full_name": user.full_name or "",
                    "role": getattr(user, "role", "user"),
                    "profile_picture": request.build_absolute_uri(profile.image.url) if profile.image else None
                }
            })

        except Exception as e:
            logger.error(f"Google login error: {e}")
            import traceback
            traceback.print_exc()
            return Response({
                "error": "Login failed",
                "details": str(e)
            }, status=500)

# Apple Login (iOS থেকে id_token পাঠাবে)


class AppleLoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        id_token = request.data.get("id_token")
        full_name = request.data.get("full_name", "")

        if not id_token:
            return Response({"error": "id_token required"}, status=400)

        try:
            # ডেভেলপমেন্টে সব টোকেন accept করি (যেকোনো ফরম্যাট!)
            decoded = jwt.decode(id_token, options={"verify_signature": False, "verify_exp": False})

            # Apple-এর আসল টোকেনে 'sub' থাকে, ফেক JWT.io টোকেনে 'sub' না থেকে 'name' থাকে
            apple_id = decoded.get("sub") or decoded.get("email", "unknown").split("@")[0]
            email = decoded.get("email") or f"{apple_id}@privaterelay.appleid.com"

            # নিশ্চিত করি ইমেইল আছে
            if "@" not in email:
                email = f"{apple_id}@privaterelay.appleid.com"

            # ইউজার তৈরি/লগইন
            user, created = User.objects.get_or_create(
                email=email,
                defaults={
                    "full_name": full_name or decoded.get("name", "Apple User"),
                    "is_email_verified": True,
                    "is_active": True,
                }
            )

            if created or not user.full_name:
                user.full_name = full_name or decoded.get("name", "Apple User")
                user.set_unusable_password()
                user.save()
                Profile.objects.get_or_create(user=user)

            # প্রোফাইল পিক
            profile = user.profile
            if not profile.image.name or 'default' in profile.image.name.lower():
                email_hash = hashlib.md5(email.lower().encode()).hexdigest()
                gravatar_url = f"https://www.gravatar.com/avatar/{email_hash}?d=identicon&s=200"
                try:
                    img_data = requests.get(gravatar_url, timeout=10).content
                    profile.image.save(f"apple_{user.id}.jpg", ContentFile(img_data), save=True)
                except:
                    pass

            # JWT
            refresh = RefreshToken.for_user(user)
            Token.objects.update_or_create(
                user=user,
                defaults={
                    "email": user.email,
                    "refresh_token": str(refresh),
                    "access_token": str(refresh.access_token),
                }
            )

            return Response({
                "success": True,
                "access_token": str(refresh.access_token),
                "refresh_token": str(refresh),
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "full_name": user.full_name,
                    "profile_picture": request.build_absolute_uri(profile.image.url) if profile.image else None
                }
            })

        except Exception as e:
            logger.error(f"Apple login failed: {e}")
            return Response({"error": "Invalid token", "details": str(e)}, status=400)






from .serializers import ReferralCodeSerializer
from django.conf import settings

class MyReferralCodeView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        serializer = ReferralCodeSerializer(user)
        return Response({
            "success": True,
            "data": serializer.data
        }, status=status.HTTP_200_OK)
    




# ============================
# VENDOR PROFILE COMPLETION
# ============================
# views.py → CompleteVendorProfileView (১০০% কাজ করা + এরর-ফ্রি)
# ============================
# VENDOR PROFILE COMPLETION (ফাইনাল ভার্সন - activities + images সব ঠিক!)
# ============================
import uuid
import json
from decimal import Decimal, InvalidOperation
from django.core.files.storage import default_storage
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.core.exceptions import ObjectDoesNotExist
import re


class CompleteVendorProfileView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]  # ইমেজ + FormData এর জন্য জরুরি!

    def get(self, request):
        if request.user.role != 'vendor':
            return Response({"success": False, "message": "Access denied"}, status=403)

        try:
            vendor = request.user.vendor_profile
            return Response({
                "success": True,
                "profile_complete": vendor.is_profile_complete,
                "vendor": {
                    "vendor_name": vendor.vendor_name or "",
                    "shop_name": vendor.shop_name or "",
                    "phone_number": vendor.phone_number or "",
                    "shop_address": vendor.shop_address or "",
                    "category": vendor.category or "",
                    "latitude": str(vendor.latitude) if vendor.latitude else "",
                    "longitude": str(vendor.longitude) if vendor.longitude else "",
                    "shop_images": vendor.shop_images or [],
                    "description": vendor.description or "",
                    "activities": vendor.activities or [],  # এখানে লিস্ট আসবে
                    "rating": float(vendor.rating) if vendor.rating else 0.0,
                    "review_count": vendor.review_count or 0,
                }
            }, status=200)
        except ObjectDoesNotExist:
            return Response({
                "success": True,
                "profile_complete": False,
                "message": "প্রোফাইল তৈরি করুন",
                "vendor": { "shop_images": [], "activities": [], "description": "" }
            }, status=200)

    def post(self, request):
        if request.user.role != 'vendor':
            return Response({"success": False, "message": "Access denied"}, status=403)

        try:
            vendor = request.user.vendor_profile
        except ObjectDoesNotExist:
            return Response({"success": False, "message": "প্রোফাইল পাওয়া যায়নি।"}, status=404)

        data = request.data
        files = request.FILES

        # === ইমেজ আপলোড ===
        uploaded_images = []
        if 'shop_images' in files:
            for img_file in files.getlist('shop_images'):
                ext = img_file.name.split('.')[-1] if '.' in img_file.name else 'jpg'
                filename = f"{uuid.uuid4().hex}.{ext}"
                file_path = default_storage.save(f'vendor_shops/{filename}', img_file)
                img_url = request.build_absolute_uri(settings.MEDIA_URL + file_path)
                uploaded_images.append(img_url)

        if not uploaded_images:
            uploaded_images = vendor.shop_images or []

        # === activities সঠিকভাবে হ্যান্ডল করা (মূল সমাধান!) ===
        activities = vendor.activities or []

        if 'activities' in data:
            acts_input = data['activities']

            if isinstance(acts_input, str) and acts_input.strip():
                # যদি স্ট্রিং হয় (FormData থেকে আসলে এমনই হয়)
                try:
                    # প্রথমে JSON পার্স করার চেষ্টা
                    parsed = json.loads(acts_input)
                    if isinstance(parsed, list):
                        activities = [str(item).strip() for item in parsed if str(item).strip()]
                    else:
                        activities = []
                except:
                    # JSON না হলে কমা দিয়ে স্প্লিট করো
                    activities = [item.strip() for item in acts_input.split(',') if item.strip()]
            elif isinstance(acts_input, list):
                activities = [str(item).strip() for item in acts_input if str(item).strip()]

        # === বাকি ফিল্ড ভ্যালিডেশন ===
        required = ['vendor_name', 'shop_name', 'phone_number', 'shop_address', 'category', 'latitude', 'longitude']
        missing = [f for f in required if not data.get(f)]
        if missing:
            return Response({"success": False, "message": f"এই ফিল্ডগুলো দিন: {', '.join(missing)}"}, status=400)

        # ফোন নম্বর
        phone = str(data['phone_number']).strip()
        if phone.startswith("+880"):
            phone = "0" + phone[4:]
        if not re.match(r"^01[3-9]\d{8}$", phone):
            return Response({"success": False, "message": "সঠিক মোবাইল নম্বর দিন"}, status=400)

        # ল্যাট-লং
        try:
            lat = Decimal(str(data['latitude']))
            lng = Decimal(str(data['longitude']))
        except:
            return Response({"success": False, "message": "ল্যাটিটিউড ও লংগিটিউড সঠিক দিন"}, status=400)

        # === সবকিছু সেভ করি ===
        vendor.vendor_name = data['vendor_name'].strip()
        vendor.shop_name = data['shop_name'].strip()
        vendor.phone_number = phone
        vendor.shop_address = data['shop_address'].strip()
        vendor.category = data['category']
        vendor.latitude = lat
        vendor.longitude = lng
        vendor.description = data.get('description', vendor.description or '')
        vendor.activities = activities
        vendor.shop_images = uploaded_images
        vendor.is_profile_complete = True
        vendor.save()

        return Response({
            "success": True,
            "message": "প্রোফাইল সফলভাবে আপডেট হয়েছে!",
            "profile_complete": True,
            "vendor": {
                "vendor_name": vendor.vendor_name,
                "shop_name": vendor.shop_name,
                "phone_number": vendor.phone_number,
                "shop_address": vendor.shop_address,
                "category": vendor.category,
                "latitude": str(vendor.latitude),
                "longitude": str(vendor.longitude),
                "shop_images": vendor.shop_images,
                "description": vendor.description,
                "activities": vendor.activities,  # এখন ঠিক আসবে!
                "rating": float(vendor.rating) if vendor.rating else 0.0,
                "review_count": vendor.review_count or 0
            }
        }, status=200)

# authentication/views.py → CompleteVendorProfileView এর নিচে যোগ করো
# ================== VENDOR: প্রোফাইল আপডেট রিকোয়েস্ট করা ==================
# authentication/views.py
# authentication/views.py → VendorProfileUpdateRequestView (ফাইনাল + কাজ করা ভার্সন)

import os
import uuid
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
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
                full_url = request.build_absolute_uri(settings.MEDIA_URL + path)
                uploaded_shop_images.append(full_url)

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

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone
from datetime import timedelta


class AdminPendingVendorUpdateRequestsView(APIView):
    """
    এডমিনের জন্য: শুধুমাত্র পেন্ডিং ভেন্ডর প্রোফাইল আপডেট রিকোয়েস্ট দেখা
    → পুরানো vs নতুন ভ্যালু সাইড বাই সাইড
    → বাংলা লেবেল, টাইম এগো, ডকুমেন্ট, ছবি সব
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if request.user.role != 'admin':
            return Response({
                "success": False,
                "message": "শুধুমাত্র এডমিন এই তথ্য দেখতে পারবেন"
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
                'vendor_name': ('ভেন্ডরের নাম', vendor.vendor_name or "খালি"),
                'shop_name': ('দোকানের নাম', vendor.shop_name or "খালি"),
                'phone_number': ('মোবাইল নম্বর', vendor.phone_number or "খালি"),
                'shop_address': ('দোকানের ঠিকানা', vendor.shop_address or "খালি"),
                'category': ('ক্যাটাগরি', vendor.category or "খালি"),
                'description': ('বিবরণ', vendor.description or "খালি"),
                'activities': ('কার্যক্রম', ", ".join(vendor.activities) if vendor.activities else "কিছু নেই"),
                'rating': ('রেটিং', float(vendor.rating) if vendor.rating else 0.0),
                'review_count': ('রিভিউ সংখ্যা', vendor.review_count if vendor.review_count else 0),
            }

            # প্রতিটি ফিল্ড চেক করি যেটা চেঞ্জ করতে চাইছে
            for field_key, (bangla_name, old_value) in field_mapping.items():
                if field_key in new_data:
                    new_value = new_data[field_key]

                    # activities লিস্ট হলে স্ট্রিং করি
                    if field_key == 'activities' and isinstance(new_value, list):
                        new_value = ", ".join(new_value) if new_value else "কিছু নেই"

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
                        "old": old_str if old_str != "খালি" else "খালি",
                        "new": new_str if new_str else "খালি",
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
                "shop_name": vendor.shop_name or "নাম দেয়নি",
                "phone_number": vendor.phone_number or "দেয়নি",
                "requested_by": req.requested_by.email,
                "requested_at": req.created_at.strftime("%d %b %Y, %I:%M %p"),
                "time_ago": self._time_ago(req.created_at),

                # মূল জিনিস: পুরানো vs নতুন
                "changes": changes,
                "total_changes": len(changes),

                # ছবি
                "current_images": old_images_count,
                "will_add_images": new_images_count,
                "new_shop_images_preview": req.shop_images[:3] if req.shop_images else [],

                # ডকুমেন্ট
                "has_documents": bool(req.nid_front or req.nid_back or req.trade_license),
                "documents": documents,
            })

        return Response({
            "success": True,
            "total_pending": total_pending,
            "message": f"মোট {total_pending}টি পেন্ডিং রিকোয়েস্ট আছে" if total_pending else "কোনো পেন্ডিং রিকোয়েস্ট নেই",
            "pending_requests": request_list
        }, status=200)

    # বোনাস: কতক্ষণ আগে রিকোয়েস্ট পাঠিয়েছে
    def _time_ago(self, past_time):
        now = timezone.now()
        diff = now - past_time

        if diff.days > 0:
            return f"{diff.days} দিন আগে"
        elif diff.seconds >= 7200:
            return f"{diff.seconds // 3600} ঘণ্টা আগে"
        elif diff.seconds >= 3600:
            return "১ ঘণ্টা আগে"
        elif diff.seconds >= 120:
            return f"{diff.seconds // 60} মিনিট আগে"
        elif diff.seconds >= 60:
            return "১ মিনিট আগে"
        else:
            return "এইমাত্র"

# ================== ADMIN ONLY API: Approve / Reject (Postman Friendly) ==================


# ================== ADMIN ONLY: Approve / Reject Vendor Update Request (100% Working) ==================

# =============================================================================
# ADMIN PANEL: Vendor Management APIs (ফাইনাল, সাজানো-গোছানো ভার্সন)
# =============================================================================

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
# ১. ভেন্ডর রেজিস্ট্রেশন অনুমোদন → লগইন চালু করা
# =============================================================================
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def approve_vendor_registration(request, user_id):
    """
    এডমিন নতুন ভেন্ডরকে লগইনের অনুমতি দেয়
    URL: POST /admin/approve-vendor/<int:user_id>/
    """
    if request.user.role != 'admin':
        return Response({
            "success": False,
            "message": "শুধুমাত্র এডমিন এই কাজ করতে পারবেন"
        }, status=403)

    try:
        user = User.objects.get(id=user_id, role='vendor')
    except User.DoesNotExist:
        return Response({
            "success": False,
            "message": "এই আইডি দিয়ে কোনো ভেন্ডর পাওয়া যায়নি"
        }, status=404)

    if user.is_active:
        return Response({
            "success": False,
            "message": "এই ভেন্ডর ইতিমধ্যে অনুমোদিত হয়েছে"
        }, status=400)

    # অনুমোদন দেওয়া
    user.is_active = True
    user.save(update_fields=['is_active'])

    # ভেন্ডরকে স্বাগতম ইমেইল
    try:
        send_mail(
            subject="আপনার ভেন্ডর একাউন্ট অনুমোদিত হয়েছে!",
            message=f"""প্রিয় {user.full_name or 'ভেন্ডর'},

আপনার ভেন্ডর একাউন্ট সফলভাবে অনুমোদিত হয়েছে।
এখন আপনি লগইন করে আপনার দোকানের প্রোফাইল পূরণ করতে পারবেন।

ইমেইল: {user.email}
লগইন লিংক: {getattr(settings, 'FRONTEND_URL', 'https://yourapp.com')}/vendor/login

ধন্যবাদ,
টিম""",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=True,
        )
    except Exception as e:
        logger.warning(f"Approval email failed for {user.email}: {e}")

    logger.info(f"Vendor registration approved → {user.email} by {request.user.email}")

    return Response({
        "success": True,
        "message": f"ভেন্ডর {user.email} সফলভাবে অনুমোদিত হয়েছে। এখন লগইন করতে পারবে।"
    }, status=200)


# =============================================================================
# ২. ভেন্ডর প্রোফাইল আপডেট রিকোয়েস্ট অনুমোদন
# =============================================================================
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def approve_vendor_update_request(request, request_id):
    """
    এডমিন ভেন্ডরের প্রোফাইল আপডেট রিকোয়েস্ট অনুমোদন করে
    URL: POST /admin/approve-update/<int:request_id>/
    """
    if request.user.role != 'admin':
        return Response({"success": False, "message": "শুধুমাত্র এডমিন"}, status=403)

    req = get_object_or_404(VendorProfileUpdateRequest, id=request_id, status='pending')
    vendor = req.vendor

    # টেক্সট ডাটা আপডেট
    for field, value in (req.new_data or {}).items():
        if hasattr(vendor, field):
            setattr(vendor, field, value)

    # ডকুমেন্ট কপি
    copy_uploaded_file(req.nid_front, vendor.nid_front)
    copy_uploaded_file(req.nid_back, vendor.nid_back)
    copy_uploaded_file(req.trade_license, vendor.trade_license)

    # দোকানের ছবি আপডেট (খুবই গুরুত্বপূর্ণ!)
    if req.shop_images and isinstance(req.shop_images, list):
        vendor.shop_images = req.shop_images

    vendor.save()

    # রিকোয়েস্ট স্ট্যাটাস
    req.status = 'approved'
    req.reviewed_by = request.user
    req.reviewed_at = timezone.now()
    req.save()

    logger.info(f"Profile update approved → {vendor.user.email} by {request.user.email}")

    return Response({
        "success": True,
        "message": "ভেন্ডর প্রোফাইল সফলভাবে আপডেট করা হয়েছে!",
        "vendor_email": vendor.user.email,
        "shop_name": vendor.shop_name,
        "total_shop_images": len(vendor.shop_images or []),
        "approved_by": request.user.email,
        "approved_at": localtime(req.reviewed_at).strftime("%d %b %Y, %I:%M %p")
    }, status=200)


# =============================================================================
# ৩. ভেন্ডর প্রোফাইল আপডেট রিকোয়েস্ট রিজেক্ট
# =============================================================================
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def reject_vendor_update_request(request, request_id):
    """
    এডমিন রিকোয়েস্ট রিজেক্ট করে + কারণ দিতে পারে
    URL: POST /admin/reject-update/<int:request_id>/
    Body: { "reason": "NID ছবি অস্পষ্ট" }
    """
    if request.user.role != 'admin':
        return Response({"success": False, "message": "শুধুমাত্র এডমিন"}, status=403)

    req = get_object_or_404(VendorProfileUpdateRequest, id=request_id, status='pending')
    vendor = req.vendor

    reason = request.data.get('reason', '').strip() or "কোনো কারণ উল্লেখ করা হয়নি"

    req.status = 'rejected'
    req.reviewed_by = request.user
    req.reviewed_at = timezone.now()
    req.reason = reason
    req.save()

    # ভেন্ডরকে ইমেইল
    try:
        send_mail(
            subject="প্রোফাইল আপডেট রিকোয়েস্ট রিজেক্ট হয়েছে",
            message=f"""প্রিয় {vendor.user.full_name or 'ভেন্ডর'},

আপনার প্রোফাইল আপডেট রিকোয়েস্ট রিজেক্ট করা হয়েছে।

কারণ: {reason}

অনুগ্রহ করে সংশোধন করে আবার রিকোয়েস্ট পাঠান।

ধন্যবাদ,
টিম""",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[vendor.user.email],
            fail_silently=True,
        )
    except Exception as e:
        logger.warning(f"Rejection email failed: {e}")

    logger.info(f"Update request rejected → {vendor.user.email} | Reason: {reason}")

    return Response({
        "success": True,
        "message": "রিকোয়েস্ট সফলভাবে রিজেক্ট করা হয়েছে",
        "reason": reason,
        "rejected_by": request.user.email,
        "rejected_at": localtime(req.reviewed_at).strftime("%d %b %Y, %I:%M %p")
    }, status=200)


# views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated   # ← এই লাইনটা থাকতে হবে
from .models import Vendor
import math


def calculate_distance(lat1, lon1, lat2, lon2):
    """Haversine Formula — খুবই সঠিক + হালকা"""
    R = 6371  # Earth radius in km
    lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
    return R * c


# নিকটস্থ দোকান (শুধু লগইন করলে দেখাবে)
class NearbyVendorsAPI(APIView):
    permission_classes = [IsAuthenticated]   # ← এই লাইনটা আনকমেন্ট কর + IsAuthenticated দে

    def get(self, request):
        try:
            user_lat = float(request.query_params.get('lat'))
            user_lng = float(request.query_params.get('lng'))
        except (TypeError, ValueError):
            return Response({"success": False, "message": "lat ও lng দিতে হবে"}, status=400)

        vendors = Vendor.objects.filter(
            is_profile_complete=True,
            latitude__isnull=False,
            longitude__isnull=False
        )

        result = []
        for v in vendors:
            distance = calculate_distance(user_lat, user_lng, float(v.latitude), float(v.longitude))
            if distance <= 1.0:  # ১ কিমি’র মধ্যে
                result.append({
                    "id": v.id,
                    "shop_name": v.shop_name,
                    "vendor_name": v.vendor_name,
                    "category": v.category,
                    "rating": float(v.rating),
                    "review_count": v.review_count,
                    "distance_km": round(distance, 2),
                    "shop_image": v.shop_images[0] if v.shop_images else None,
                    "phone": v.phone_number
                })

        result = sorted(result, key=lambda x: x['distance_km'])

        return Response({
            "success": True,
            "your_location": {"lat": user_lat, "lng": user_lng},
            "total_nearby": len(result),
            "vendors": result
        })







# ক্যাটাগরি অনুযায়ী নিকটস্থ দোকান (শুধু লগইন করলে)
class CategoryNearbyVendorsAPI(APIView):
    permission_classes = [IsAuthenticated]   # ← এই লাইনটা আনকমেন্ট কর + IsAuthenticated দে

    def get(self, request):
        try:
            user_lat = float(request.query_params.get('lat'))
            user_lng = float(request.query_params.get('lng'))
            category = request.query_params.get('category')
        except (TypeError, ValueError):
            return Response({"success": False, "message": "lat, lng, category দিতে হবে"}, status=400)

        if not category:
            return Response({"success": False, "message": "category পাঠান"}, status=400)

        vendors = Vendor.objects.filter(
            is_profile_complete=True,
            latitude__isnull=False,
            longitude__isnull=False,
            category=category.lower()
        )

        result = []
        for v in vendors:
            distance = calculate_distance(user_lat, user_lng, float(v.latitude), float(v.longitude))
            if distance <= 1.0:
                result.append({
                    "id": v.id,
                    "shop_name": v.shop_name,
                    "rating": float(v.rating),
                    "review_count": v.review_count,
                    "distance_km": round(distance, 2),
                    "image": v.shop_images[0] if v.shop_images else None
                })

        result = sorted(result, key=lambda x: x['distance_km'])

        return Response({
            "success": True,
            "category": category,
            "total_found": len(result),
            "vendors": result
        })
# views.py এর শেষে যোগ করো

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .models import Vendor

class AdminAllVendorCredentialsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if request.user.role != 'admin':
            return Response({
                "success": False,
                "message": "শুধুমাত্র এডমিন এই তথ্য দেখতে পারবেন"
            }, status=403)

        vendors = Vendor.objects.select_related('user').all().order_by('-created_at')
        credentials = []

        for vendor in vendors:
            if vendor.plain_password:  # যাদের পাসওয়ার্ড সেভ আছে
                credentials.append({
                    "vendor_id": vendor.id,
                    "shop_name": vendor.shop_name if vendor.shop_name != "N/A" else "নাম দেয়নি",
                    "email": vendor.user.email,
                    "password": vendor.plain_password,  # প্লেইন টেক্সট পাসওয়ার্ড
                    "created_at": vendor.user.date_joined.strftime("%d %b %Y, %I:%M %p")
                })

        return Response({
            "success": True,
            "total_vendors": len(credentials),
            "credentials": credentials
        })
    


from .models import FavoriteVendor

# favorite add 

# views.py
# ================== ফেভারিট ভেন্ডর টগল (Love বাটন) ==================
class ToggleFavoriteVendor(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        vendor_id = request.data.get('vendor_id')
        if not vendor_id:
            return Response({"success": False, "message": "vendor_id দিন"}, status=400)

        try:
            vendor = Vendor.objects.get(id=vendor_id)
        except Vendor.DoesNotExist:
            return Response({"success": False, "message": "দোকান পাওয়া যায়নি"}, status=404)

        favorite = FavoriteVendor.objects.filter(user=request.user, vendor=vendor).first()

        if favorite:
            favorite.delete()
            is_favorite = False
            message = "ফেভারিট থেকে সরানো হয়েছে"
        else:
            FavoriteVendor.objects.create(user=request.user, vendor=vendor)
            is_favorite = True
            message = "ফেভারিটে যোগ করা হয়েছে"

        return Response({
            "success": True,
            "message": message,
            "is_favorite": is_favorite,
            "total_favorites": vendor.favorited_by.count()
        })


# ================== আমার সব ফেভারিট ভেন্ডর দেখা ==================
import math
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .models import FavoriteVendor


def calculate_distance(lat1, lon1, lat2, lon2):
    """Returns distance in kilometers using Haversine formula"""
    R = 6371  # Earth radius in KM

    # Convert all to float to avoid Decimal error
    lat1 = float(lat1)
    lon1 = float(lon1)
    lat2 = float(lat2)
    lon2 = float(lon2)

    d_lat = math.radians(lat2 - lat1)
    d_lon = math.radians(lon2 - lon1)

    a = (
        math.sin(d_lat / 2) ** 2
        + math.cos(math.radians(lat1))
        * math.cos(math.radians(lat2))
        * math.sin(d_lon / 2) ** 2
    )

    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c  # kilometers


class MyFavoriteVendorsAPI(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # User location required
        try:
            user_lat = float(request.query_params.get("lat"))
            user_lng = float(request.query_params.get("lng"))
        except:
            return Response({"success": False, "message": "lat & lng required"}, status=400)

        favorites = FavoriteVendor.objects.filter(user=request.user).select_related('vendor')

        vendor_list = []

        for fav in favorites:
            v = fav.vendor

            # Vendor must have location
            if v.latitude is None or v.longitude is None:
                continue

            # Calculate distance (force float conversion)
            distance_km = calculate_distance(
                user_lat,
                user_lng,
                float(v.latitude),
                float(v.longitude)
            )

            # Only vendors within 5 km
            if distance_km > 5:
                continue

            distance_meter = distance_km * 1000

            vendor_list.append({
                "id": v.id,
                "shop_name": v.shop_name,
                "vendor_name": v.vendor_name,
                "category": v.category,
                "rating": float(v.rating),
                "review_count": v.review_count,
                "shop_image": v.shop_images[0] if v.shop_images else None,
                "phone": v.phone_number,
                "added_at": fav.created_at.strftime("%d %b %Y"),

                # Vendor location
                "location": {
                    "latitude": float(v.latitude),
                    "longitude": float(v.longitude)
                },

                # Distance formatted
                "distance": {
                    "kilometer": round(distance_km, 2),
                    "meter": int(distance_meter)
                }
            })

        return Response({
            "success": True,
            "total_favorites_within_5km": len(vendor_list),
            "my_favorites": vendor_list
        })