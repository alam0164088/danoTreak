from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import SignUpSerializer, LoginSerializer, EmailVerificationSerializer, UserSerializer
from .models import User, Token
from django.core.mail import send_mail
import random
from rest_framework_simplejwt.tokens import RefreshToken
from .permissions import IsAdmin
from django.conf import settings
import jwt
from datetime import datetime
import datetime as dt  # Import datetime module for timezone.utc
from rest_framework.permissions import IsAuthenticated
import logging

# Set up logging
logger = logging.getLogger(__name__)

class InitialAdminSignUpView(APIView):
    permission_classes = []

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
                "role": user.role
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class SignUpView(APIView):
    permission_classes = []

    def post(self, request):
        serializer = SignUpSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            code = str(random.randint(100000, 999999))
            user.email_verification_code = code
            user.save()
            send_mail(
                'Verify Your Email',
                f'Your verification code is {code}',
                settings.EMAIL_HOST_USER,
                [user.email],
                fail_silently=False,
            )
            logger.info(f"User signed up: {user.email}")
            return Response({"message": "User created. Verification code sent to email."}, status=status.HTTP_201_CREATED)
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
            return Response({"message": "Admin created. Verification code sent to email."}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    permission_classes = []

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
                    "role": user.role
                })
            return Response({"error": "Invalid credentials."}, status=status.HTTP_401_UNAUTHORIZED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class EmailVerificationView(APIView):
    permission_classes = []

    def post(self, request):
        serializer = EmailVerificationSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            code = serializer.validated_data['code']
            user = User.objects.filter(email=email, email_verification_code=code).first()
            if user:
                user.is_email_verified = True
                user.email_verification_code = None
                user.save()
                logger.info(f"Email verified: {user.email}")
                return Response({"message": "Email verified successfully."}, status=status.HTTP_200_OK)
            return Response({"error": "Invalid code or email."}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class AdminDashboardView(APIView):
    permission_classes = [IsAdmin]

    def get(self, request):
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        logger.info(f"Admin dashboard accessed by: {request.user.email}")
        return Response({
            "message": "Welcome to Admin Dashboard",
            "users": serializer.data
        }, status=status.HTTP_200_OK)

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
            return Response({
                "message": "User role updated successfully.",
                "user": serializer.data
            }, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

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
        try:
            refresh_token = request.data.get("refresh_token")
            if not refresh_token:
                Token.objects.filter(user=request.user).delete()
                logger.info(f"All tokens deleted for user: {request.user.email}")
                return Response({"message": "Successfully logged out."}, status=status.HTTP_205_RESET_CONTENT)
            
            token = RefreshToken(refresh_token)
            token.blacklist()
            Token.objects.filter(refresh_token=refresh_token).delete()
            logger.info(f"User logged out: {request.user.email}")
            return Response({"message": "Successfully logged out."}, status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            logger.error(f"Logout error for {request.user.email}: {str(e)}")
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)