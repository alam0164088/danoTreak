from rest_framework import serializers
from .models import User, Profile, Vendor
import re
from django.utils import timezone
from datetime import timedelta





class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)
    password_confirm = serializers.CharField(write_only=True)
    send_verification_otp = serializers.BooleanField(required=False, default=False, write_only=True)
    
    # ✅ FIX: referral_code কে Model ফিল্ড থেকে আলাদা করো
    # এটা "কার রেফারেল ব্যবহার করছি" — নতুন ইউজারের নিজের code না
    referral_code = serializers.CharField(required=False, allow_blank=True, write_only=True)

    class Meta:
        model = User
        fields = ['email', 'password', 'password_confirm', 'full_name', 'phone',
                  'send_verification_otp', 'referral_code']
        extra_kwargs = {
            'password': {'write_only': True},
        }

    def validate(self, attrs):
        if attrs.get('password') != attrs.get('password_confirm'):
            raise serializers.ValidationError({"password_confirm": "Passwords do not match."})
        
        # ✅ referral_code আলাদা করে রাখো — model এ সরাসরি যাবে না
        self._used_referral_code = attrs.pop('referral_code', None)
        attrs.pop('password_confirm', None)
        attrs.pop('send_verification_otp', None)
        
        # Password complexity
        if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$', attrs['password']):
            raise serializers.ValidationError({
                "password": "Password must be at least 8 characters long and contain letters, numbers, and special characters."
            })

        # Role validation
        role = attrs.get('role')
        request_user = self.context['request'].user if 'request' in self.context else None
        if role in ['admin', 'vendor']:
            if not request_user or not request_user.is_authenticated:
                raise serializers.ValidationError({"role": "Only authenticated admins can assign 'admin' or 'vendor' roles."})
            if request_user.role != 'admin':
                raise serializers.ValidationError({"role": "Only admins can assign 'admin' or 'vendor' roles."})

        return attrs

    def create(self, validated_data):
        # ✅ Safety: এগুলো যদি এখনও থাকে তাহলে সরাও
        validated_data.pop('referral_code', None)
        validated_data.pop('password_confirm', None)
        validated_data.pop('send_verification_otp', None)

        password = validated_data.pop('password')
        user = User(**validated_data)
        user.set_password(password)
        # ✅ user.referral_code অটো generate হবে model save() এ — আমরা সেট করছি না
        
        # ✅ referred_by সেট করো (কার referral code ব্যবহার করেছে)
        used_code = getattr(self, '_used_referral_code', None)
        if used_code and str(used_code).strip():
            used_code = str(used_code).strip()
            try:
                referrer = User.objects.get(referral_code=used_code)
                user.referred_by = referrer
            except User.DoesNotExist:
                pass  # invalid code — silently ignore

        user.save()
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
    # role বাধ্যতামূলক: user/admin/vendor যে রোল দিয়ে লগইন করবে, শুধু সেই রোলই অনুমোদিত
    role = serializers.ChoiceField(choices=User.ROLE_CHOICES, required=True)

    def validate(self, data):
        email = data.get("email")
        role = data.get("role")
        try:
            user = User.objects.get(email=email)
            if user.role != role:
                raise serializers.ValidationError({"email": f"Only {role} accounts can log in."})
        except User.DoesNotExist:
            pass
        return data

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
    phone = serializers.CharField(source='profile.phone', read_only=True)
    full_name = serializers.SerializerMethodField()
    
    # এখানে source='gender' মুছে দিয়েছি — কারণ ফিল্ড নামই gender!
    gender = serializers.CharField(read_only=True)

    class Meta:
        model = User
        fields = [
            'id',
            'email',
            'full_name',
            'gender',           # এখানে কোনো source লাগবে না
            'phone',
            'email_verified',
            'created_at',
            'role',
            'profile_image'
        ]
        read_only_fields = ['id', 'email', 'created_at', 'role', 'email_verified']

    def get_full_name(self, obj):
        return obj.get_full_name().strip() or obj.email.split('@')[0]

    def get_profile_image(self, obj):
        request = self.context.get('request')
        if not request:
            return "/media/profile_images/default_profile.png"
        try:
            if hasattr(obj, 'profile') and obj.profile and obj.profile.image:
                return request.build_absolute_uri(obj.profile.image.url)
        except:
            pass
        return request.build_absolute_uri('/media/profile_images/default_profile.png')



class ProfileUpdateSerializer(serializers.ModelSerializer):
    full_name = serializers.CharField(required=False, write_only=True)
    gender = serializers.CharField(required=False, write_only=True)
    image = serializers.ImageField(required=False, allow_null=True)

    class Meta:
        model = Profile
        fields = ['full_name', 'gender', 'phone', 'image']

    def update(self, instance, validated_data):
        user = instance.user
        data = self.context['request'].data

        full_name = data.get('full_name')
        gender = data.get('gender')

        # নাম আপডেট — এই লাইনটা ঠিক করা হয়েছে!
        if full_name and full_name.strip():
            names = full_name.strip().split()
            user.first_name = names[0]
            user.last_name = ' '.join(names[1:]) if len(names) > 1 else ''
            user.save(update_fields=['first_name', 'last_name'])  # এটা ঠিক আছে

        # জেন্ডার
        if gender and gender.strip():
            user.gender = gender.strip().lower()
            user.save(update_fields=['gender'])

        # ফোন
        if 'phone' in validated_data:
            instance.phone = validated_data['phone']

        # ইমেজ
        if 'image' in validated_data:
            new_image = validated_data['image']
            if new_image is None:
                instance.image = None
            elif new_image:
                instance.image = new_image

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
#     vendor = serializers.PrimaryKeyRelatedField(readOnly=True)

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




# authentication/serializers.py

# ← এখানে অন্যান্য সিরিয়ালাইজার আছে (RegisterSerializer, LoginSerializer ইত্যাদি)
# ← সব শেষ হওয়ার পর নিচে এই কোডটা পেস্ট করো

from django.conf import settings   # যদি উপরে না থাকে তাহলে এখানে লিখো


class ReferralCodeSerializer(serializers.ModelSerializer):
    referral_code = serializers.CharField(read_only=True)
    referral_link = serializers.SerializerMethodField()
    total_referrals = serializers.IntegerField(source='referrals.count', read_only=True)

    class Meta:
        model = User
        fields = ['referral_code', 'referral_link', 'total_referrals']

    def get_referral_link(self, obj):
        base_url = getattr(settings, 'FRONTEND_URL', 'https://danotreak.com')
        return f"{base_url}/register?ref={obj.referral_code}"






