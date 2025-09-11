from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, Token

@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = ('email', 'username', 'role', 'is_email_verified', 'is_active', 'is_staff', 'date_joined')
    list_filter = ('role', 'is_email_verified', 'is_active', 'is_staff')
    search_fields = ('email', 'username')
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal Info', {'fields': ('username', 'role', 'is_email_verified', 'email_verification_code')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'username', 'password1', 'password2', 'role', 'is_email_verified'),
        }),
    )
    readonly_fields = ('date_joined', 'last_login', 'email_verification_code')
    ordering = ('email',)
    filter_horizontal = ('groups', 'user_permissions',)

@admin.register(Token)
class TokenAdmin(admin.ModelAdmin):
    list_display = ('email', 'user', 'refresh_token_expires_at', 'access_token_expires_at', 'created_at')
    list_filter = ('refresh_token_expires_at', 'access_token_expires_at', 'created_at')
    search_fields = ('email', 'user__email')
    fieldsets = (
        (None, {'fields': ('user', 'email', 'refresh_token', 'access_token', 'refresh_token_expires_at', 'access_token_expires_at', 'created_at')}),
    )
    readonly_fields = ('refresh_token', 'access_token', 'refresh_token_expires_at', 'access_token_expires_at', 'created_at')
    ordering = ('-created_at',)