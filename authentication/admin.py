from django.contrib import admin
from .models import User, Token, PasswordResetSession, SubscriptionPlan, Profile, Vendor, LoyaltyProgram, Visit, Redemption, EmailOTP

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ['email', 'full_name', 'role', 'is_email_verified', 'is_active', 'created_at']
    list_filter = ['role', 'is_email_verified', 'is_active']
    search_fields = ['email', 'full_name']

@admin.register(Token)
class TokenAdmin(admin.ModelAdmin):
    list_display = ['user', 'email', 'access_token', 'refresh_token', 'revoked', 'created_at']
    list_filter = ['revoked']
    search_fields = ['user__email']

@admin.register(PasswordResetSession)
class PasswordResetSessionAdmin(admin.ModelAdmin):
    list_display = ['user', 'token', 'created_at']
    search_fields = ['user__email']

@admin.register(SubscriptionPlan)
class SubscriptionPlanAdmin(admin.ModelAdmin):
    list_display = ['name', 'price']
    search_fields = ['name']

@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ['user', 'employee_id', 'phone', 'created_at']
    search_fields = ['user__email', 'employee_id']

@admin.register(Vendor)
class VendorAdmin(admin.ModelAdmin):
    list_display = ['user', 'business_name', 'location', 'geofence_radius', 'created_at']
    search_fields = ['user__email', 'business_name']

@admin.register(LoyaltyProgram)
class LoyaltyProgramAdmin(admin.ModelAdmin):
    list_display = ['campaign_name', 'vendor', 'visits_required', 'is_active', 'valid_until', 'created_at']
    list_filter = ['is_active']
    search_fields = ['campaign_name', 'vendor__business_name']

@admin.register(Visit)
class VisitAdmin(admin.ModelAdmin):
    list_display = ['user', 'vendor', 'timestamp', 'duration', 'is_valid']
    list_filter = ['is_valid']
    search_fields = ['user__email', 'vendor__business_name']

@admin.register(Redemption)
class RedemptionAdmin(admin.ModelAdmin):
    list_display = ['user', 'loyalty_program', 'timestamp', 'location_verified', 'fraud_flagged']
    list_filter = ['location_verified', 'fraud_flagged']
    search_fields = ['user__email', 'loyalty_program__campaign_name']

from django.contrib import admin
from .models import EmailOTP

@admin.register(EmailOTP)
class EmailOTPAdmin(admin.ModelAdmin):
    list_display = ['email', 'raw_otp', 'otp_hash', 'expires_at', 'created_at']
    readonly_fields = ['raw_otp', 'otp_hash', 'expires_at', 'created_at']