from rest_framework import serializers
from .models import User, Profile, Vendor
import re
from django.utils import timezone
from datetime import timedelta

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)
    password_confirm = serializers.CharField(write_only=True, min_length=8)
    send_verification_otp = serializers.BooleanField(default=True)
    role = serializers.ChoiceField(choices=User.ROLE_CHOICES, default='user', required=False)

    class Meta:
        model = User
        fields = ['email', 'password', 'password_confirm', 'full_name', 'send_verification_otp', 'role']

    def validate(self, data):
        if data['password'] != data['password_confirm']:
            raise serializers.ValidationError({"password": "Passwords do not match."})
        if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$', data['password']):
            raise serializers.ValidationError({
                "password": "Password must be at least 8 characters long and contain letters, numbers, and special characters."
            })
        if data.get('role') in ['admin', 'vendor'] and not self.context['request'].user.is_authenticated:
            raise serializers.ValidationError({"role": "Only authenticated admins can assign 'admin' or 'vendor' roles."})
        if data.get('role') in ['admin', 'vendor'] and self.context['request'].user.role != 'admin':
            raise serializers.ValidationError({"role": "Only admins can assign 'admin' or 'vendor' roles."})
        return data

    def create(self, validated_data):
        validated_data.pop('password_confirm')
        validated_data.pop('send_verification_otp')
        user = User.objects.create_user(
            email=validated_data['email'],
            password=validated_data['password'],
            full_name=validated_data['full_name'],
            role=validated_data.get('role', 'user')
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
    method = serializers.ChoiceField(choices=['email'])

class ResendOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    purpose = serializers.ChoiceField(choices=['email_verification'])

class UserProfileSerializer(serializers.ModelSerializer):
    email_verified = serializers.BooleanField(source='is_email_verified', read_only=True)
    profile_image = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ['id', 'email', 'full_name', 'gender', 'email_verified', 'created_at', 'role', 'profile_image']
        read_only_fields = ['id', 'email', 'created_at', 'role']

    def get_profile_image(self, obj):
        try:
            profile = obj.profile
            if profile.image:
                return self.context['request'].build_absolute_uri(profile.image.url)
        except Profile.DoesNotExist:
            pass
        return self.context['request'].build_absolute_uri('/media/profile_images/default_profile.png')

class ProfileUpdateSerializer(serializers.ModelSerializer):
    full_name = serializers.CharField(source='user.full_name', required=False)
    gender = serializers.CharField(source='user.gender', required=False)
    image = serializers.ImageField(required=False)  # Added for image uploads

    class Meta:
        model = Profile
        fields = ['full_name', 'phone', 'gender', 'image']

    def update(self, instance, validated_data):
        user_data = validated_data.pop('user', {})
        full_name = user_data.get('full_name')
        gender = user_data.get('gender')

        if full_name:
            instance.user.full_name = full_name
        if gender:
            instance.user.gender = gender
        instance.user.save()
        instance.phone = validated_data.get('phone', instance.phone)
        instance.image = validated_data.get('image', instance.image)
        instance.save()
        return instance

# class SubscriptionPlanSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = SubscriptionPlan
#         fields = ['id', 'name', 'price']

class UserSerializer(serializers.ModelSerializer):
    email_verified = serializers.BooleanField(source='is_email_verified', read_only=True)
    profile_image = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ['id', 'email', 'full_name', 'gender', 'email_verified', 'created_at', 'role', 'profile_image']
        read_only_fields = ['id', 'email', 'created_at', 'role', 'email_verified']

    def get_profile_image(self, obj):
        try:
            profile = obj.profile
            if profile.image:
                return self.context['request'].build_absolute_uri(profile.image.url)
        except Profile.DoesNotExist:
            pass
        return self.context['request'].build_absolute_uri('/media/profile_images/default_profile.png')

class VendorSerializer(serializers.ModelSerializer):
    user = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = Vendor
        fields = ['id', 'user', 'business_name', 'location', 'geofence_radius', 'created_at', 'updated_at']
        read_only_fields = ['id', 'user', 'created_at', 'updated_at']

# class LoyaltyProgramSerializer(serializers.ModelSerializer):
#     vendor = serializers.PrimaryKeyRelatedField(read_only=True)

#     class Meta:
#         model = LoyaltyProgram
#         fields = ['id', 'vendor', 'campaign_name', 'visits_required', 'reward_description', 
#                   'max_redemptions_per_day', 'valid_until', 'cooldown_period', 'is_active', 'created_at']
#         read_only_fields = ['id', 'vendor', 'created_at']

#     def validate(self, data):
#         if data.get('visits_required') <= 0:
#             raise serializers.ValidationError({"visits_required": "Must be a positive integer."})
#         if data.get('max_redemptions_per_day') < 0:
#             raise serializers.ValidationError({"max_redemptions_per_day": "Cannot be negative."})
#         if data.get('cooldown_period') < 0:
#             raise serializers.ValidationError({"cooldown_period": "Cannot be negative."})
#         if data.get('valid_until') <= timezone.now():
#             raise serializers.ValidationError({"valid_until": "Must be a future date."})
#         return data

#     def create(self, validated_data):
#         vendor = self.context['request'].user.vendor  # Use authenticated vendor
#         return LoyaltyProgram.objects.create(vendor=vendor, **validated_data)


# class VisitSerializer(serializers.ModelSerializer):
#     user = serializers.PrimaryKeyRelatedField(read_only=True)
#     vendor = serializers.PrimaryKeyRelatedField(read_only=True)

#     class Meta:
#         model = Visit
#         fields = ['id', 'user', 'vendor', 'timestamp', 'duration', 'is_valid']
#         read_only_fields = ['id', 'user', 'vendor', 'timestamp', 'is_valid']

# class RedemptionSerializer(serializers.ModelSerializer):
#     user = serializers.PrimaryKeyRelatedField(read_only=True)
#     loyalty_program = serializers.PrimaryKeyRelatedField(read_only=True)

#     class Meta:
#         model = Redemption
#         fields = ['id', 'user', 'loyalty_program', 'timestamp', 'location_verified', 'fraud_flagged']
#         read_only_fields = ['id', 'user', 'loyalty_program', 'timestamp']