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
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            send_verification = request.data.get('send_verification_otp', True)
            if send_verification:
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
                    "is_active": False,
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
                    "is_active": True,
                    "message": "User created successfully."
                }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




class VendorSignUpView(APIView):
    """
    Vendor নিজে নিজে সাইনআপ করবে → শুধু ইমেইল + পাসওয়ার্ড
    কোনো full_name, phone লাগবে না
    """
    permission_classes = [AllowAny]  # কেউ লগইন না থাকলেও করতে পারবে

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

        # ভেন্ডর ইউজার তৈরি করো (শুধু ইমেইল + পাসওয়ার্ড)
        user = User.objects.create_user(
            email=email.lower(),
            password=password,
            role='vendor',
            is_active=False  # এডমিন অ্যাপ্রুভ করলে active হবে
        )

        # OTP পাঠাও ইমেইল ভেরিফিকেশনের জন্য
        code = user.generate_email_verification_code()
        send_mail(
            'ভেন্ডর একাউন্ট যাচাই করুন - DanoTreak',
            f'আপনার ভেরিফিকেশন কোড: {code}\nএই কোড ৫ মিনিটের জন্য বৈধ।',
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            fail_silently=False,
        )
        vendor, created = Vendor.objects.get_or_create(user=user)
        vendor.plain_password = password  # এই লাইনটা যোগ করো
        vendor.save()



        return Response({
            "success": True,
            "message": "ভেন্ডর একাউন্ট তৈরি হয়েছে! ইমেইল চেক করে OTP দিয়ে যাচাই করুন।",
            "next_step": "verify_email_with_otp",
            "user": {
                "id": user.id,
                "email": user.email,
                "role": "vendor",
                "is_active": False
            }
        }, status=status.HTTP_201_CREATED)
    





class InitialAdminSignUpView(APIView):
    """Handle initial admin signup (only one admin allowed initially)."""
    permission_classes = [AllowAny]
    def post(self, request):
        if User.objects.filter(role='admin').exists():
            return Response({"detail": "An admin already exists. Use admin-signup endpoint."}, status=status.HTTP_400_BAD_REQUEST)
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            user.role = 'admin'
            user.is_email_verified = True
            user.is_active = True
            user.save()
            code = user.generate_email_verification_code()
            send_mail(
                'Verify Your Admin Email',
                f'Your verification code is {code} (already verified for initial admin).',
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )
            refresh = RefreshToken.for_user(user)
            refresh_token = str(refresh)
            access_token = str(refresh.access_token)
            refresh_expires_at = timezone.now() + refresh.lifetime
            access_expires_at = timezone.now() + timedelta(minutes=15)
            Token.objects.create(
                user=user,
                email=user.email,
                refresh_token=refresh_token,
                access_token=access_token,
                refresh_token_expires_at=refresh_expires_at,
                access_token_expires_at=access_expires_at
            )
            logger.info(f"Initial admin created: {user.email}")
            return Response({
                "id": user.id,
                "email": user.email,
                "role": user.role,
                "message": "Initial admin created successfully."
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

class LoginView(APIView):
    """Handle user login with password and optional 2FA."""
    permission_classes = [AllowAny]
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']
            user = User.objects.filter(email=email).first()
            if user and user.check_password(password):
                if not user.is_email_verified:
                    return Response({"detail": "Email not verified."}, status=status.HTTP_403_FORBIDDEN)
                if user.is_2fa_enabled:
                    code = user.generate_email_verification_code()
                    send_mail(
                        '2FA Verification',
                        f'Your 2FA OTP is {code}. Expires in 5 minutes.',
                        settings.DEFAULT_FROM_EMAIL,
                        [user.email],
                        fail_silently=False,
                    )
                    return Response({
                        "detail": "2FA required. OTP sent to email.",
                        "next_step": "verify_2fa_otp"
                    }, status=status.HTTP_206_PARTIAL_CONTENT)
                refresh = RefreshToken.for_user(user)
                lifetime = timedelta(days=30) if serializer.validated_data['remember_me'] else timedelta(days=7)
                refresh.set_exp(lifetime=lifetime)
                refresh_token_str = str(refresh)
                access_token_str = str(refresh.access_token)
                access_expires_in = 900
                refresh_expires_in = int(refresh.lifetime.total_seconds())
                Token.objects.create(
                    user=user,
                    email=user.email,
                    refresh_token=refresh_token_str,
                    access_token=access_token_str,
                    refresh_token_expires_at=timezone.now() + timedelta(seconds=refresh_expires_in),
                    access_token_expires_at=timezone.now() + timedelta(minutes=15)
                )
                logger.info(f"User logged in: {user.email}")
                return Response({
                    "access_token": access_token_str,
                    "access_token_expires_in": access_expires_in,
                    "refresh_token": refresh_token_str,
                    "refresh_token_expires_in": refresh_expires_in,
                    "token_type": "Bearer",
                    "user": {
                        "id": user.id,
                        "email": user.email,
                        "full_name": user.full_name,
                        "email_verified": user.is_email_verified,
                        "role": user.role
                    }
                }, status=status.HTTP_200_OK)
            return Response({"detail": "Invalid credentials."}, status=status.HTTP_401_UNAUTHORIZED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

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

class MeView(APIView):
    """Handle user profile retrieval, update, and deletion."""
    permission_classes = [IsAuthenticated]
    @method_decorator(never_cache)
    def get(self, request):
        logger.debug(f"GET request for user: {request.user.email}")
        serializer = UserProfileSerializer(request.user, context={'request': request})
        return Response(serializer.data, status=status.HTTP_200_OK)
    def put(self, request):
        profile, created = Profile.objects.get_or_create(user=request.user)
        logger.debug(f"PUT request for user: {request.user.email}, data: {request.data}")
        serializer = ProfileUpdateSerializer(profile, data=request.data, context={'request': request}, partial=True)
        if serializer.is_valid():
            serializer.save()
            logger.info(f"Profile updated for user: {request.user.email}")
            return Response({
                "message": "Profile updated successfully.",
                "user": UserProfileSerializer(request.user, context={'request': request}).data
            }, status=status.HTTP_200_OK)
        logger.error(f"Profile update failed for user: {request.user.email}, errors: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def patch(self, request):
        return self.put(request)
    def delete(self, request):
        password = request.data.get('current_password')
        if password and not request.user.check_password(password):
            return Response({"detail": "Current password incorrect."}, status=status.HTTP_400_BAD_REQUEST)
        email = request.user.email
        request.user.delete()
        logger.info(f"Account deleted: {email}")
        return Response({"message": "Account deleted."}, status=status.HTTP_200_OK)

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

import re
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.core.exceptions import ObjectDoesNotExist
from decimal import Decimal, InvalidOperation


class CompleteVendorProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if request.user.role != 'vendor':
            return Response({"success": False, "message": "Access denied"}, status=403)

        try:
            vendor = request.user.vendor_profile

            response_data = {
                "success": True,
                "profile_complete": vendor.is_profile_complete,
                "vendor": {
                    "vendor_name": vendor.vendor_name if vendor.vendor_name != "N/A" else "",
                    "shop_name": vendor.shop_name if vendor.shop_name != "N/A" else "",
                    "phone_number": vendor.phone_number if vendor.phone_number != "N/A" else "",
                    "shop_address": vendor.shop_address if vendor.shop_address != "N/A" else "",
                    "category": vendor.category if vendor.category != "others" else "",
                    "latitude": str(vendor.latitude) if vendor.latitude else "",
                    "longitude": str(vendor.longitude) if vendor.longitude else "",
                    "shop_images": vendor.shop_images or [],
                    "description": vendor.description or "",                     # ← যোগ করা হয়েছে
                    "activities": vendor.activities or [],                       # ← যোগ করা হয়েছে
                    "rating": float(vendor.rating) if vendor.rating else 0.0,
                    "review_count": vendor.review_count if hasattr(vendor, 'review_count') else 0,
                }
            }

            if not vendor.is_profile_complete:
                response_data["message"] = "আপনার প্রোফাইল এখনো সম্পূর্ণ হয়নি। নিচের তথ্যগুলো পূরণ করুন।"

            return Response(response_data)

        except ObjectDoesNotExist:
            return Response({
                "success": True,
                "profile_complete": False,
                "message": "আপনার কোনো দোকানের প্রোফাইল নেই। প্রথমে তৈরি করুন।",
                "vendor": {
                    "vendor_name": "",
                    "shop_name": "",
                    "phone_number": "",
                    "shop_address": "",
                    "category": "",
                    "latitude": "",
                    "longitude": "",
                    "shop_images": [],
                    "description": "",        # ← এখানেও যোগ করা
                    "activities": [],         # ← এখানেও যোগ করা
                    "rating": 0.0,
                    "review_count": 0
                }
            })
        

    def post(self, request):
        if request.user.role != 'vendor':
            return Response({"success": False, "message": "Access denied"}, status=403)

        try:
            vendor = request.user.vendor_profile
        except ObjectDoesNotExist:
            return Response({"success": False, "message": "প্রোফাইল পাওয়া যায়নি। প্রথমে কমপ্লিট করুন।"}, status=404)

        data = request.data
        updated = False

        # Case 1: প্রোফাইল ইতিমধ্যে complete আছে → শুধু description, activities, shop_images আপডেট করতে চাই
        if vendor.is_profile_complete:
            if any(key in data for key in ['description', 'activities', 'shop_images']):
                if 'description' in data:
                    vendor.description = str(data['description']).strip() if data['description'] not in [None, ""] else ""
                    updated = True

                if 'activities' in data:
                    acts = data['activities']
                    if isinstance(acts, list):
                        vendor.activities = [str(a).strip() for a in acts if str(a).strip()]
                    else:
                        vendor.activities = []
                    updated = True

                if 'shop_images' in data:
                    imgs = data['shop_images']
                    if isinstance(imgs, list):
                        vendor.shop_images = [str(i).strip() for i in imgs if str(i).strip()]
                    else:
                        vendor.shop_images = []
                    updated = True

                if updated:
                    vendor.save()
                    return Response({
                        "success": True,
                        "message": "প্রোফাইলের বিবরণ, কার্যক্রম এবং ছবি সফলভাবে আপডেট হয়েছে!",
                        "profile_complete": True,
                        "vendor": self._get_vendor_data(vendor)
                    }, status=200)

        # Case 2: প্রথমবার প্রোফাইল কমপ্লিট করা বা ফুল আপডেট (required fields দিয়ে)
        required_fields = ['vendor_name', 'shop_name', 'phone_number', 'shop_address', 'category', 'latitude', 'longitude']
        missing = [field for field in required_fields if not data.get(field)]
        if missing:
            return Response({
                "success": False,
                "message": f"নিচের তথ্যগুলো দিতে হবে: {', '.join(missing)}"
            }, status=400)

        # Phone validation
        phone = str(data['phone_number']).strip()
        if phone.startswith("+880"):
            phone = "0" + phone[4:]
        if not re.match(r"^01[3-9]\d{8}$", phone):
            return Response({"success": False, "message": "সঠিক বাংলাদেশি মোবাইল নম্বর দিন"}, status=400)

        # Latitude & Longitude validation
        try:
            lat = Decimal(str(data['latitude']))
            lng = Decimal(str(data['longitude']))
            if not (-90 <= lat <= 90 and -180 <= lng <= 180):
                raise ValueError("Lat/Long out of range")
        except (InvalidOperation, ValueError, TypeError) as e:
            return Response({"success": False, "message": "সঠিক ল্যাটিটিউড ও লংগিটিউড দিন"}, status=400)

        # Optional fields
        description = str(data.get('description', vendor.description or '')).strip()
        activities_input = data.get('activities', vendor.activities or [])
        activities = [str(a).strip() for a in activities_input if str(a).strip()] if isinstance(activities_input, list) else []

        shop_images_input = data.get('shop_images', vendor.shop_images or [])
        shop_images = [str(i).strip() for i in shop_images_input if str(i).strip()] if isinstance(shop_images_input, list) else []

        # Rating & Review Count
        try:
            rating = Decimal(str(data.get('rating', vendor.rating or '0.00')))
            rating = max(Decimal('0.00'), min(Decimal('5.00'), rating)).quantize(Decimal('0.01'))
        except:
            rating = vendor.rating or Decimal('0.00')

        try:
            review_count = max(0, int(data.get('review_count', vendor.review_count or 0)))
        except:
            review_count = vendor.review_count or 0

        # আপডেট করি
        vendor.vendor_name = data['vendor_name'].strip()
        vendor.shop_name = data['shop_name'].strip()
        vendor.phone_number = phone
        vendor.shop_address = data['shop_address'].strip()
        vendor.category = data['category']
        vendor.latitude = lat
        vendor.longitude = lng
        vendor.description = description
        vendor.activities = activities
        vendor.shop_images = shop_images
        vendor.rating = rating
        vendor.review_count = review_count
        vendor.is_profile_complete = True  # এটা অবশ্যই True করতে হবে!

        vendor.save()

        return Response({
            "success": True,
            "message": "প্রোফাইল সম্পূর্ণভাবে আপডেট হয়েছে!",
            "profile_complete": True,
            "vendor": self._get_vendor_data(vendor)
        }, status=200)


    # হেল্পার মেথড — ডুপ্লিকেট কোড কমানোর জন্য
    def _get_vendor_data(self, vendor):
        return {
            "vendor_name": vendor.vendor_name,
            "shop_name": vendor.shop_name,
            "phone_number": vendor.phone_number,
            "shop_address": vendor.shop_address,
            "category": vendor.category,
            "latitude": str(vendor.latitude) if vendor.latitude else "",
            "longitude": str(vendor.longitude) if vendor.longitude else "",
            "description": vendor.description,
            "activities": vendor.activities,
            "shop_images": vendor.shop_images,
            "rating": float(vendor.rating),
            "review_count": vendor.review_count
        }




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

        # সব ফিল্ড যেগুলো আপডেট করা যাবে
        allowed_fields = [
            'shop_name', 'vendor_name', 'phone_number', 'shop_address',
            'category', 'latitude', 'longitude',
            'rating', 'review_count',
            'description',      # ← যোগ হয়েছে
            'activities'        # ← যোগ হয়েছে
        ]

        new_data = {}

        # ================ description & activities স্পেশাল হ্যান্ডলিং ================
        if 'description' in data:
            desc = data['description']
            if desc is not None and str(desc).strip():
                new_data['description'] = str(desc).strip()
            else:
                new_data['description'] = ""

        if 'activities' in data:
            acts = data['activities']
            if isinstance(acts, list):
                clean_activities = [str(item).strip() for item in acts if str(item).strip()]
                new_data['activities'] = clean_activities
            else:
                new_data['activities'] = []
        # =============================================================================

        # বাকি ফিল্ডগুলো (description, activities বাদ দিয়ে)
        for key in allowed_fields:
            if key in ['description', 'activities']:
                continue  # আগেই হ্যান্ডেল করা হয়েছে

            value = data.get(key)
            if value in [None, '', 'null', 'undefined']:
                continue

            if key == 'rating':
                try:
                    value = round(float(value), 2)
                    if not 0 <= value <= 5:
                        return Response({"success": False, "message": "রেটিং ০ থেকে ৫ এর মধ্যে হতে হবে"}, status=400)
                except (ValueError, TypeError):
                    return Response({"success": False, "message": "রেটিং সঠিক ফরম্যাটে দিন (যেমন: 4.85)"}, status=400)

            elif key == 'review_count':
                try:
                    value = int(value)
                    if value < 0:
                        value = 0
                except (ValueError, TypeError):
                    return Response({"success": False, "message": "রিভিউ সংখ্যা সঠিক হতে হবে"}, status=400)

            new_data[key] = value

        # দোকানের ছবি আপলোড (যদি থাকে)
        uploaded_shop_images = []
        if 'shop_images' in request.FILES:
            for file in request.FILES.getlist('shop_images'):
                ext = os.path.splitext(file.name)[1].lower()
                if ext not in ['.jpg', '.jpeg', '.png', '.webp']:
                    continue
                filename = f"shop_{uuid.uuid4().hex}{ext}"
                path = default_storage.save(f'vendor_update_docs/shop_images/{filename}', ContentFile(file.read()))
                full_url = request.build_absolute_uri(settings.MEDIA_URL + path)
                uploaded_shop_images.append(full_url)

        # রিকোয়েস্ট সেভ করা
        update_request = VendorProfileUpdateRequest.objects.create(
            vendor=vendor,
            requested_by=request.user,
            new_data=new_data,
            nid_front=request.FILES.get('nid_front'),
            nid_back=request.FILES.get('nid_back'),
            trade_license=request.FILES.get('trade_license'),
            shop_images=uploaded_shop_images
        )

        return Response({
            "success": True,
            "message": "প্রোফাইল আপডেট রিকোয়েস্ট সফলভাবে পাঠানো হয়েছে। এডমিন শীঘ্রই রিভিউ করবে।",
            "request_id": update_request.id,
            "status": update_request.status,
            "requested_changes": new_data,   # ← এখানে description + activities ও দেখাবে
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
                    "shop_images": r.shop_images
                })
            return Response({"success": True, "requests": data})
        except Exception:
            return Response({"success": False, "message": "প্রোফাইল পাওয়া যায়নি"})
        


# ================== ADMIN ONLY API: Approve / Reject (Postman Friendly) ==================


# ================== ADMIN ONLY: Approve / Reject Vendor Update Request (100% Working) ==================

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.core.files import File
import os


def admin_only(user):
    return user.is_authenticated and user.role == 'admin'


def copy_uploaded_file(source_field, target_field):
    """সঠিকভাবে ফাইল কপি করে (যা আগে কাজ করত না)"""
    if not source_field:
        return

    # পুরানো ফাইল মুছে ফেলো
    if target_field:
        target_field.delete(save=False)

    try:
        source_field.open('rb')  # ফাইল ওপেন করা জরুরি
        file_name = os.path.basename(source_field.name)
        target_field.save(file_name, File(source_field), save=False)
    finally:
        source_field.close()


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def approve_vendor_update_request(request, request_id):
    if not admin_only(request.user):
        return Response({
            "success": False,
            "message": "শুধুমাত্র এডমিন এই কাজ করতে পারবে"
        }, status=403)

    req = get_object_or_404(VendorProfileUpdateRequest, id=request_id, status='pending')
    vendor = req.vendor

    # টেক্সট ডাটা আপডেট
    for field, value in req.new_data.items():
        if hasattr(vendor, field):
            setattr(vendor, field, value)

    # NID, NID Back, Trade License কপি করো
    copy_uploaded_file(req.nid_front, vendor.nid_front)
    copy_uploaded_file(req.nid_back, vendor.nid_back)
    copy_uploaded_file(req.trade_license, vendor.trade_license)

    # দোকানের ছবি আপডেট করো (এটাই আগে মিস করেছিলে!)
    if req.shop_images and isinstance(req.shop_images, list):
        vendor.shop_images = req.shop_images  # এই লাইনটা যোগ করো

    # সব শেষে সেভ করো
    vendor.save()

    # রিকোয়েস্ট স্ট্যাটাস
    req.status = 'approved'
    req.reviewed_by = request.user
    req.reviewed_at = timezone.now()
    req.save()

    return Response({
        "success": True,
        "message": "ভেন্ডর প্রোফাইল সম্পূর্ণ আপডেট হয়েছে! দোকানের ছবি, NID, ট্রেড লাইসেন্স সব আপডেট হয়েছে",
        "shop_name": vendor.shop_name,
        "shop_images_count": len(vendor.shop_images),
        "documents_updated": bool(req.nid_front or req.nid_back or req.trade_license),
        "approved_by": request.user.email,
        "approved_at": timezone.localtime(req.reviewed_at).strftime("%d %b %Y, %I:%M %p")
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def reject_vendor_update_request(request, request_id):
    if not admin_only(request.user):
        return Response({
            "success": False,
            "message": "শুধুমাত্র এডমিন এই কাজ করতে পারবে"
        }, status=403)

    req = get_object_or_404(VendorProfileUpdateRequest, id=request_id, status='pending')
    
    reason = request.data.get('reason', 'কোনো কারণ উল্লেখ করা হয়নি')

    req.status = 'rejected'
    req.reviewed_by = request.user
    req.reviewed_at = timezone.now()
    req.reason = reason
    req.save()

    return Response({
        "success": True,
        "message": "প্রোফাইল আপডেট রিকোয়েস্ট রিজেক্ট করা হয়েছে",
        "reason": reason,
        "rejected_by": request.user.email,
        "rejected_at": timezone.localtime(req.reviewed_at).strftime("%d %b %Y, %I:%M %p")
    })



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
