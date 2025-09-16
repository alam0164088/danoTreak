from django.contrib import admin
from .models import User, Token, PasswordResetSession, SubscriptionPlan, Profile


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = (
        'email', 
        'username', 
        'full_name', 
        'role', 
        'gender', 
        'is_email_verified', 
        'is_2fa_enabled', 
        'created_at'
    )
    search_fields = ('email', 'username', 'full_name')
    list_filter = ('role', 'is_email_verified', 'is_2fa_enabled', 'gender')
    ordering = ('-created_at',)
    readonly_fields = ('created_at',)


@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'employee_id', 'phone', 'created_at', 'updated_at')
    search_fields = ('user__email', 'employee_id', 'phone')
    ordering = ('-created_at',)


@admin.register(Token)
class TokenAdmin(admin.ModelAdmin):
    list_display = (
        'user', 
        'email', 
        'access_token', 
        'refresh_token', 
        'otp', 
        'access_token_expires_at', 
        'refresh_token_expires_at', 
        'revoked', 
        'created_at'
    )
    search_fields = ('user__email', 'email', 'otp')
    list_filter = ('revoked', 'created_at')
    ordering = ('-created_at',)
    readonly_fields = ('created_at',)


@admin.register(PasswordResetSession)
class PasswordResetSessionAdmin(admin.ModelAdmin):
    list_display = ('user', 'token', 'created_at', 'is_expired')
    search_fields = ('user__email',)
    list_filter = ('created_at',)
    ordering = ('-created_at',)


@admin.register(SubscriptionPlan)
class SubscriptionPlanAdmin(admin.ModelAdmin):
    list_display = ('name', 'price')
    search_fields = ('name',)
    ordering = ('name',)
