from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.core.mail import send_mail
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from django.conf import settings
from django.utils import timezone
from django.contrib.auth import get_user_model
import jwt
import random
import logging
from datetime import datetime
import datetime as dt

from .models import Token, Profile
from .permissions import IsAdmin
from .serializers import (
    SignUpSerializer,
    LoginSerializer,
    EmailVerificationSerializer,
    UserSerializer,
    PasswordResetRequestSerializer,
    PasswordResetVerifyCodeSerializer,
    PasswordResetSetPasswordSerializer,
    PasswordResetSetPasswordWithoutOTPSerializer,
    LogoutSerializer,
    ProfileSerializer
)

logger = logging.getLogger(__name__)
User = get_user_model()

class InitialAdminSignUpView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        if User.objects.filter(role='admin').exists():
            return Response({"error": "An admin already exists. Use admin-signup endpoint."}, status=status.HTTP_400_BAD_REQUEST)
        
        serializer = SignUpSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            user.role = 'admin'
            user.is_email_verified = True
            user.save()
            
            refresh = RefreshToken.for_user(user)
            refresh_token = str(refresh)
            access_token = str(refresh.access_token)
            
            refresh_payload = jwt.decode(refresh_token, settings.SECRET_KEY, algorithms=["HS256"])
            access_payload = jwt.decode(access_token, settings.SECRET_KEY, algorithms=["HS256"])
            refresh_expires_at = datetime.fromtimestamp(refresh_payload['exp'], tz=dt.timezone.utc)
            access_expires_at = datetime.fromtimestamp(access_payload['exp'], tz=dt.timezone.utc)
            
            Token.objects.create(
                user=user,
                email=user.email,
                refresh_token=refresh_token,
                access_token=access_token,
                refresh_token_expires_at=refresh_expires_at,
                access_token_expires_at=access_expires_at
            )
            
            code = str(random.randint(100000, 999999))
            user.email_verification_code = code
            user.save()
            
            send_mail(
                'Verify Your Admin Email',
                f'Your verification code is {code} (already verified for initial admin).',
                settings.EMAIL_HOST_USER,
                [user.email],
                fail_silently=False,
            )
            logger.info(f"Initial admin created: {user.email}")
            return Response({
                "message": "Initial admin created successfully.",
                "refresh": refresh_token,
                "access": access_token,
                "role": user.role,
                "email": user.email
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class SignUpView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = SignUpSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            code = str(random.randint(100000, 999999))
            user.email_verification_code = code
            user.save()
            
            refresh = RefreshToken.for_user(user)
            refresh_token = str(refresh)
            access_token = str(refresh.access_token)
            
            refresh_payload = jwt.decode(refresh_token, settings.SECRET_KEY, algorithms=["HS256"])
            access_payload = jwt.decode(access_token, settings.SECRET_KEY, algorithms=["HS256"])
            
            refresh_expires_at = datetime.fromtimestamp(refresh_payload['exp'], tz=dt.timezone.utc)
            access_expires_at = datetime.fromtimestamp(access_payload['exp'], tz=dt.timezone.utc)
            
            Token.objects.create(
                user=user,
                email=user.email,
                refresh_token=refresh_token,
                access_token=access_token,
                refresh_token_expires_at=refresh_expires_at,
                access_token_expires_at=access_expires_at
            )
            
            send_mail(
                'Verify Your Email',
                f'Your verification code is {code}',
                settings.EMAIL_HOST_USER,
                [user.email],
                fail_silently=False,
            )
            logger.info(f"User signed up: {user.email}")
            return Response({
                "message": "User created. Verification code sent to email.",
                "refresh": refresh_token,
                "access": access_token,
                "role": user.role,
                "email": user.email
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class AdminSignUpView(APIView):
    permission_classes = [IsAdmin]

    def post(self, request):
        serializer = SignUpSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            user.role = 'admin'
            code = str(random.randint(100000, 999999))
            user.email_verification_code = code
            user.save()
            send_mail(
                'Verify Your Admin Email',
                f'Your verification code is {code}',
                settings.EMAIL_HOST_USER,
                [user.email],
                fail_silently=False,
            )
            logger.info(f"Admin created by {request.user.email}: {user.email}")
            return Response({"message": "Admin created. Verification code sent to email.", "email": user.email}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ResendOTPView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({"error": "Email is required."}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.filter(email=email).first()
        if not user:
            return Response({"error": "User with this email does not exist."}, status=status.HTTP_404_NOT_FOUND)
        
        if user.is_email_verified:
            return Response({"error": "Email is already verified."}, status=status.HTTP_400_BAD_REQUEST)
        
        code = str(random.randint(100000, 999999))
        user.email_verification_code = code
        user.save()
        
        try:
            send_mail(
                'Verify Your Email',
                f'Your new verification code is {code}',
                settings.EMAIL_HOST_USER,
                [user.email],
                fail_silently=False,
            )
            logger.info(f"Resend OTP sent to: {user.email}")
            return Response({"message": "New OTP sent to email.", "email": user.email}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Failed to resend OTP to {user.email}: {str(e)}")
            return Response({"error": "Failed to send OTP. Please try again."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']
            user = User.objects.filter(email=email).first()
            if user and user.check_password(password):
                if not user.is_email_verified:
                    return Response({"error": "Email not verified."}, status=status.HTTP_403_FORBIDDEN)
                
                refresh = RefreshToken.for_user(user)
                refresh_token = str(refresh)
                access_token = str(refresh.access_token)
                
                refresh_payload = jwt.decode(refresh_token, settings.SECRET_KEY, algorithms=["HS256"])
                access_payload = jwt.decode(access_token, settings.SECRET_KEY, algorithms=["HS256"])
                
                refresh_expires_at = datetime.fromtimestamp(refresh_payload['exp'], tz=dt.timezone.utc)
                access_expires_at = datetime.fromtimestamp(access_payload['exp'], tz=dt.timezone.utc)
                
                Token.objects.create(
                    user=user,
                    email=user.email,
                    refresh_token=refresh_token,
                    access_token=access_token,
                    refresh_token_expires_at=refresh_expires_at,
                    access_token_expires_at=access_expires_at
                )
                logger.info(f"User logged in: {user.email}")
                return Response({
                    "refresh": refresh_token,
                    "access": access_token,
                    "role": user.role,
                    "email": user.email
                })
            return Response({"error": "Invalid credentials."}, status=status.HTTP_401_UNAUTHORIZED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class EmailVerificationView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email")
        code = request.data.get("code")

        if not email or not code:
            return Response({"error": "Email and Code are required."}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.filter(email=email, email_verification_code=code).first()
        if not user:
            return Response({"error": "Invalid email or OTP."}, status=status.HTTP_400_BAD_REQUEST)
        
        user.is_email_verified = True
        user.email_verification_code = None
        user.save()
        logger.info(f"OTP verified: {user.email}")
        return Response({
            "message": "OTP verified successfully.",
            "user": {"email": user.email, "role": user.role}
        }, status=status.HTTP_200_OK)

class PasswordResetRequestView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = User.objects.filter(email=email).first()
            if not user:
                return Response({"error": "User with this email does not exist."}, status=status.HTTP_404_NOT_FOUND)
            
            code = user.generate_password_reset_code()
            send_mail(
                'Password Reset OTP',
                f'Your OTP for password reset is {code}. It expires in 10 minutes.',
                settings.EMAIL_HOST_USER,
                [user.email],
                fail_silently=False,
            )
            logger.info(f"Password reset OTP sent to: {user.email}")
            return Response({"message": "OTP sent to email for password reset.", "email": user.email}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetVerifyCodeView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email")
        code = request.data.get("code")

        if not email or not code:
            return Response({"error": "Email and Code are required."}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.filter(email=email, password_reset_code=code).first()
        if not user:
            return Response({"error": "Invalid email or OTP."}, status=status.HTTP_400_BAD_REQUEST)
        if user.password_reset_code_expires_at < timezone.now():
            return Response({"error": "OTP has expired."}, status=status.HTTP_400_BAD_REQUEST)

        return Response({"message": "OTP verified. You can now set a new password.", "email": user.email}, status=status.HTTP_200_OK)

class PasswordResetSetPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = PasswordResetSetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            code = serializer.validated_data.get('code')
            email = serializer.validated_data.get('email')
            new_password = serializer.validated_data['new_password']
            
            user = None
            if code and email:
                user = User.objects.filter(email=email, password_reset_code=code).first()
                if not user:
                    return Response({"error": "Invalid email or OTP."}, status=status.HTTP_400_BAD_REQUEST)
                if user.password_reset_code_expires_at < timezone.now():
                    return Response({"error": "OTP has expired."}, status=status.HTTP_400_BAD_REQUEST)
                user.password_reset_code = None
                user.password_reset_code_expires_at = None
            elif email:
                user = User.objects.filter(email=email).first()
                if not user:
                    return Response({"error": "User with this email does not exist."}, status=status.HTTP_404_NOT_FOUND)
            else:
                if not request.user.is_authenticated:
                    return Response({"error": "Authentication required."}, status=status.HTTP_401_UNAUTHORIZED)
                user = request.user
            
            user.set_password(new_password)
            user.save()
            logger.info(f"Password reset/changed for: {user.email}")
            return Response({"message": "Password reset successfully."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetSetPasswordWithoutOTPView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = PasswordResetSetPasswordWithoutOTPSerializer(data=request.data)
        if serializer.is_valid():
            new_password = serializer.validated_data['new_password']
            user = request.user
            user.set_password(new_password)
            user.save()
            logger.info(f"Password changed for user: {user.email}")
            return Response({"message": "Password changed successfully."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class AdminDashboardView(APIView):
    permission_classes = [IsAdmin]

    def get(self, request):
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        logger.info(f"Admin dashboard accessed by: {request.user.email}")
        return Response({"message": "Welcome to Admin Dashboard", "users": serializer.data}, status=status.HTTP_200_OK)

class AdminUserManagementView(APIView):
    permission_classes = [IsAdmin]

    def get(self, request, user_id):
        try:
            user = User.objects.get(id=user_id)
            serializer = UserSerializer(user)
            logger.info(f"User {user.email} viewed by {request.user.email}")
            return Response(serializer.data, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

    def put(self, request, user_id):
        try:
            user = User.objects.get(id=user_id)
            role = request.data.get('role')
            if role not in ['admin', 'user']:
                return Response({"error": "Invalid role. Must be 'admin' or 'user'."}, status=status.HTTP_400_BAD_REQUEST)
            user.role = role
            user.save()
            serializer = UserSerializer(user)
            logger.info(f"User {user.email} role updated to {role} by {request.user.email}")
            return Response({"message": "User role updated successfully.", "user": serializer.data}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, user_id):
        try:
            user = User.objects.get(id=user_id)
            user_email = user.email
            user.delete()
            logger.info(f"User {user_email} deleted by {request.user.email}")
            return Response({"message": "User deleted successfully."}, status=status.HTTP_204_NO_CONTENT)
        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = LogoutSerializer(data=request.data)
        if serializer.is_valid():
            password = serializer.validated_data['password']
            user = request.user
            if not user.check_password(password):
                return Response({"error": "Invalid password."}, status=status.HTTP_401_UNAUTHORIZED)
            
            Token.objects.filter(user=user).delete()
            logger.info(f"All tokens deleted for user: {user.email}")
            return Response({"message": "Successfully logged out."}, status=status.HTTP_205_RESET_CONTENT)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        profile, created = Profile.objects.get_or_create(user=request.user)
        serializer = ProfileSerializer(profile)
        logger.info(f"Profile viewed by: {request.user.email}")
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request):
        profile, created = Profile.objects.get_or_create(user=request.user)
        serializer = ProfileSerializer(profile, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            logger.info(f"Profile updated for user: {request.user.email}")
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)