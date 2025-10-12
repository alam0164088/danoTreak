from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from django.contrib.auth import get_user_model
import jwt
from datetime import timedelta
import logging
from uuid import uuid4
from django.db import models

from .models import Token, Profile, PasswordResetSession, Vendor, LoyaltyProgram, Visit, Redemption
from .permissions import IsAdmin, IsVendor
from .serializers import (
    RegisterSerializer, SendOTPSerializer, VerifyOTPSerializer, LoginSerializer,
    RefreshTokenSerializer, LogoutSerializer, ForgotPasswordSerializer,
    VerifyResetOTPSerializer, ResetPasswordSerializer, ChangePasswordSerializer,
    Enable2FASerializer, Verify2FASerializer, ResendOTPSerializer, UserProfileSerializer,
    ProfileUpdateSerializer, VendorSerializer, LoyaltyProgramSerializer, VisitSerializer, RedemptionSerializer,
)

logger = logging.getLogger('authentication')
User = get_user_model()

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
    """Handle vendor signup by an existing admin."""
    permission_classes = [IsAuthenticated, IsAdmin]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            user.role = 'vendor'
            user.is_active = False
            user.save()
            vendor_data = {
                'business_name': request.data.get('business_name'),
                'location': request.data.get('location'),
                'geofence_radius': request.data.get('geofence_radius', 100.0)
            }
            vendor_serializer = VendorSerializer(data=vendor_data)
            if vendor_serializer.is_valid():
                vendor_serializer.save(user=user)
                code = user.generate_email_verification_code()
                send_mail(
                    'Verify Your Vendor Email',
                    f'Your verification code is {code}. Expires in 5 minutes.',
                    settings.DEFAULT_FROM_EMAIL,
                    [user.email],
                    fail_silently=False,
                )
                logger.info(f"Vendor created by {request.user.email}: {user.email}")
                return Response({
                    "id": user.id,
                    "email": user.email,
                    "message": "Vendor created. Verification OTP sent to email."
                }, status=status.HTTP_201_CREATED)
            return Response(vendor_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

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
            refresh_payload = jwt.decode(refresh_token, settings.SECRET_KEY, algorithms=["HS256"])
            access_expires_in = 900
            refresh_expires_in = int(refresh_payload['exp'] - refresh_payload['iat'])
            Token.objects.create(
                user=user,
                email=user.email,
                refresh_token=refresh_token,
                access_token=access_token,
                refresh_token_expires_at=timezone.now() + timedelta(seconds=refresh_expires_in),
                access_token_expires_at=timezone.now() + timedelta(minutes=15)
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

class VendorDashboardView(APIView):
    """Handle vendor dashboard access with real-time statistics."""
    permission_classes = [IsAuthenticated, IsVendor]

    def get(self, request):
        user = request.user
        try:
            vendor = Vendor.objects.get(user=user)
        except Vendor.DoesNotExist:
            return Response({"detail": "Vendor profile not found."}, status=status.HTTP_404_NOT_FOUND)

        visits = Visit.objects.filter(vendor=vendor)
        redemptions = Redemption.objects.filter(loyalty_program__vendor=vendor)
        total_visits = visits.count()
        total_redemptions = redemptions.count()
        avg_redemption_value = redemptions.aggregate(models.Avg('loyalty_program__max_redemptions_per_day'))['loyalty_program__max_redemptions_per_day__avg'] or 0
        top_users = visits.values('user__email').annotate(total_visits=models.Count('id')).order_by('-total_visits')[:5]

        serializer = UserProfileSerializer(user, context={'request': request})
        return Response({
            "message": "Vendor dashboard accessed successfully.",
            "user": serializer.data,
            "stats": {
                "total_visits": total_visits,
                "total_redemptions": total_redemptions,
                "avg_redemption_value": avg_redemption_value,
                "top_users": top_users
            }
        }, status=status.HTTP_200_OK)

class LoyaltyProgramView(APIView):
    """Handle loyalty program creation, update, and retrieval."""
    permission_classes = [IsAuthenticated, IsVendor]

    def get(self, request, program_id=None):
        try:
            vendor = Vendor.objects.get(user=request.user)
        except Vendor.DoesNotExist:
            return Response({"detail": "Vendor profile not found."}, status=status.HTTP_404_NOT_FOUND)

        if program_id:
            try:
                program = LoyaltyProgram.objects.get(id=program_id, vendor=vendor)
                serializer = LoyaltyProgramSerializer(program)
                return Response(serializer.data, status=status.HTTP_200_OK)
            except LoyaltyProgram.DoesNotExist:
                return Response({"detail": "Loyalty program not found."}, status=status.HTTP_404_NOT_FOUND)
        else:
            programs = LoyaltyProgram.objects.filter(vendor=vendor)
            serializer = LoyaltyProgramSerializer(programs, many=True)
            return Response({"programs": serializer.data}, status=status.HTTP_200_OK)

    def post(self, request):
        try:
            vendor = Vendor.objects.get(user=request.user)
        except Vendor.DoesNotExist:
            return Response({"detail": "Vendor profile not found."}, status=status.HTTP_404_NOT_FOUND)

        data = request.data.copy()
        data['vendor'] = vendor.id
        serializer = LoyaltyProgramSerializer(data=data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            logger.info(f"Loyalty program created by {request.user.email}: {serializer.data['campaign_name']}")
            return Response({"message": "Loyalty program created successfully.", "program": serializer.data}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class RedemptionView(APIView):
    """Handle redemption log and fraud flagging."""
    permission_classes = [IsAuthenticated, IsVendor]

    def get(self, request):
        try:
            vendor = Vendor.objects.get(user=request.user)
        except Vendor.DoesNotExist:
            return Response({"detail": "Vendor profile not found."}, status=status.HTTP_404_NOT_FOUND)

        redemptions = Redemption.objects.filter(loyalty_program__vendor=vendor)
        serializer = RedemptionSerializer(redemptions, many=True)
        return Response({"redemptions": serializer.data}, status=status.HTTP_200_OK)

    def post(self, request, redemption_id):
        try:
            vendor = Vendor.objects.get(user=request.user)
            redemption = Redemption.objects.get(id=redemption_id, loyalty_program__vendor=vendor)
        except Vendor.DoesNotExist:
            return Response({"detail": "Vendor profile not found."}, status=status.HTTP_404_NOT_FOUND)
        except Redemption.DoesNotExist:
            return Response({"detail": "Redemption not found."}, status=status.HTTP_404_NOT_FOUND)

        fraud_flagged = request.data.get('fraud_flagged', False)
        redemption.fraud_flagged = fraud_flagged
        redemption.save()
        logger.info(f"Redemption {redemption_id} fraud flag updated by {request.user.email}: {fraud_flagged}")
        return Response({"message": "Fraud flag updated successfully."}, status=status.HTTP_200_OK)

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
                return Response({"detail": "If the email exists, an OTP has been sent."}, status=status.HTTP_200_OK)
            code = None
            if purpose == 'email_verification' and not user.is_email_verified:
                code = user.generate_email_verification_code()
            elif purpose == 'password_reset':
                code = user.generate_password_reset_code()
            elif purpose == 'two_factor' and user.is_2fa_enabled:
                code = user.generate_email_verification_code()
            else:
                return Response({"detail": f"Invalid request for {purpose}."}, status=status.HTTP_400_BAD_REQUEST)
            if code:
                send_mail(
                    f'{purpose.replace("_", " ").title()} OTP',
                    f'Your OTP is {code}. Expires in 5 minutes.',
                    settings.DEFAULT_FROM_EMAIL,
                    [user.email],
                    fail_silently=False,
                )
                logger.info(f"OTP sent for {purpose}: {user.email}")
            return Response({"message": "OTP sent to email. Expires in 5 minutes."}, status=status.HTTP_200_OK)
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
            
            # Track OTP attempts
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
                refresh_payload = jwt.decode(refresh_token_str, settings.SECRET_KEY, algorithms=["HS256"])
                access_expires_in = 900
                refresh_expires_in = int(refresh_payload['exp'] - refresh_payload['iat'])
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

    def get(self, request):
        serializer = UserProfileSerializer(request.user, context={'request': request})
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request):
        profile, _ = Profile.objects.get_or_create(user=request.user)
        serializer = ProfileUpdateSerializer(profile, data=request.data, context={'request': request}, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "message": "Profile updated successfully.",
                "user": UserProfileSerializer(request.user, context={'request': request}).data
            }, status=status.HTTP_200_OK)
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