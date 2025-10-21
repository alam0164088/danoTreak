from django.contrib import admin
from .models import User, Token, PasswordResetSession,  Profile, Vendor,EmailOTP

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


@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ['user', 'employee_id', 'phone', 'created_at']
    search_fields = ['user__email', 'employee_id']

@admin.register(Vendor)
class VendorAdmin(admin.ModelAdmin):
    list_display = ['user', 'business_name', 'location', 'geofence_radius', 'created_at']
    search_fields = ['user__email', 'business_name']




from django.contrib import admin
from .models import EmailOTP

@admin.register(EmailOTP)
class EmailOTPAdmin(admin.ModelAdmin):
    list_display = ['email', 'raw_otp', 'otp_hash', 'expires_at', 'created_at']
    readonly_fields = ['raw_otp', 'otp_hash', 'expires_at', 'created_at']