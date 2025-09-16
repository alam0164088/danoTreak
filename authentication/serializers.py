from rest_framework import serializers
from .models import User, SubscriptionPlan, Profile
import re
from django.utils import timezone
from datetime import timedelta

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)
    password_confirm = serializers.CharField(write_only=True, min_length=8)
    send_verification_otp = serializers.BooleanField(default=True)

    class Meta:
        model = User
        fields = ['email', 'password', 'password_confirm', 'full_name', 'send_verification_otp']

    def validate(self, data):
        if data['password'] != data['password_confirm']:
            raise serializers.ValidationError({"password": "Passwords do not match."})
        if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$', data['password']):
            raise serializers.ValidationError({
                "password": "Password must be at least 8 characters long and contain letters, numbers, and special characters."
            })
        return data

    def create(self, validated_data):
        validated_data.pop('password_confirm')
        validated_data.pop('send_verification_otp')
        user = User.objects.create_user(
            username=validated_data['email'],
            email=validated_data['email'],
            password=validated_data['password'],
            full_name=validated_data['full_name'],
            role='user'
        )
        return user

class SendOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    purpose = serializers.ChoiceField(choices=['email_verification', 'password_reset', 'two_factor'])

class VerifyOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6, min_length=6)
    purpose = serializers.ChoiceField(choices=['email_verification', 'password_reset', 'two_factor'])

class Verify2FASerializer(serializers.Serializer):
    otp = serializers.CharField(max_length=6, min_length=6)
    method = serializers.ChoiceField(choices=['email'])

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    remember_me = serializers.BooleanField(default=False)

class RefreshTokenSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()

class LogoutSerializer(serializers.Serializer):
    refresh_token = serializers.CharField(required=False)

class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

class VerifyResetOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6, min_length=6)

class ResetPasswordSerializer(serializers.Serializer):
    reset_token = serializers.CharField()
    new_password = serializers.CharField(write_only=True, min_length=8)
    new_password_confirm = serializers.CharField(write_only=True, min_length=8)

    def validate(self, data):
        if data['new_password'] != data['new_password_confirm']:
            raise serializers.ValidationError({"new_password": "Passwords do not match."})
        if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$', data['new_password']):
            raise serializers.ValidationError({
                "new_password": "Password must be at least 8 characters long and contain letters, numbers, and special characters."
            })
        return data

class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True, min_length=8)
    new_password_confirm = serializers.CharField(write_only=True, min_length=8)

    def validate(self, data):
        if data['new_password'] != data['new_password_confirm']:
            raise serializers.ValidationError({"new_password": "Passwords do not match."})
        if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$', data['new_password']):
            raise serializers.ValidationError({
                "new_password": "Password must be at least 8 characters long and contain letters, numbers, and special characters."
            })
        return data

class Enable2FASerializer(serializers.Serializer):
    method = serializers.ChoiceField(choices=['email', 'auth_app', 'sms'])

class ResendOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    purpose = serializers.ChoiceField(choices=['email_verification'])

class UserProfileSerializer(serializers.ModelSerializer):
    email_verified = serializers.BooleanField(source='is_email_verified', read_only=True)

    class Meta:
        model = User
        fields = ['id', 'email', 'full_name', 'gender', 'email_verified', 'created_at', 'role']
        read_only_fields = ['id', 'email', 'created_at', 'role']

class ProfileUpdateSerializer(serializers.ModelSerializer):
    full_name = serializers.CharField(source='user.full_name', required=False)
    gender = serializers.CharField(source='user.gender', required=False)

    class Meta:
        model = Profile
        fields = ['full_name', 'phone', 'gender']

    def update(self, instance, validated_data):
        # Update User fields
        user_data = validated_data.pop('user', {})
        if 'full_name' in user_data:
            instance.user.full_name = user_data['full_name']
        if 'gender' in user_data:
            instance.user.gender = user_data['gender']
        instance.user.save()

        # Update Profile fields
        return super().update(instance, validated_data)

class SubscriptionPlanSerializer(serializers.ModelSerializer):
    class Meta:
        model = SubscriptionPlan
        fields = ['id', 'name', 'price']