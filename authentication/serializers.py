from rest_framework import serializers
from .models import User, SubscriptionPlan, Profile
import re

class SignUpSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'confirm_password']

    def validate(self, data):
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError({"password": "Passwords do not match."})
        if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$', data['password']):
            raise serializers.ValidationError({
                "password": "Password must be at least 8 characters long and contain both letters and numbers."
            })
        return data

    def create(self, validated_data):
        validated_data.pop('confirm_password')
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password'],
            role='user'
        )
        # Profile creation handled by signal
        return user

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

class EmailVerificationSerializer(serializers.Serializer):
    code = serializers.CharField(max_length=6, min_length=6)

class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

class PasswordResetVerifyCodeSerializer(serializers.Serializer):
    code = serializers.CharField(max_length=6, min_length=6)

class PasswordResetSetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(required=False)
    code = serializers.CharField(max_length=6, min_length=6, required=False)
    new_password = serializers.CharField(write_only=True, min_length=8)
    confirm_password = serializers.CharField(write_only=True, min_length=8)

    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError({"password": "Passwords do not match."})
        if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$', data['new_password']):
            raise serializers.ValidationError({
                "password": "Password must be at least 8 characters long and contain both letters and numbers."
            })
        if not data.get('code') and not data.get('email'):
            raise serializers.ValidationError({"error": "Either code or email is required."})
        return data

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'role', 'is_email_verified']

class PasswordResetSetPasswordWithoutOTPSerializer(serializers.Serializer):
    new_password = serializers.CharField(write_only=True, min_length=8)
    confirm_password = serializers.CharField(write_only=True, min_length=8)

    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError({"password": "Passwords do not match."})
        if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$', data['new_password']):
            raise serializers.ValidationError({
                "password": "Password must be at least 8 characters long and contain both letters and numbers."
            })
        return data

class LogoutSerializer(serializers.Serializer):
    password = serializers.CharField(write_only=True)

class SubscriptionPlanSerializer(serializers.ModelSerializer):
    class Meta:
        model = SubscriptionPlan
        fields = ['id', 'name', 'price']

class ProfileSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='user.username', required=False, read_only=True)
    email = serializers.EmailField(source='user.email', required=False, read_only=True)

    class Meta:
        model = Profile
        fields = ['employee_id', 'full_name', 'username', 'email']
        read_only_fields = ['username', 'email', 'employee_id']  # employee_id read-only since it's set to user.id

    def validate_employee_id(self, value):
        if value:  # Should not be updated via serializer
            raise serializers.ValidationError("Employee ID cannot be updated manually.")
        return value