from django.contrib import admin
from .models import User, Token, PasswordResetSession

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('email', 'username', 'role', 'is_email_verified')
    search_fields = ('email', 'username')
    list_filter = ('role', 'is_email_verified')
    ordering = ('email',)

@admin.register(Token)
class TokenAdmin(admin.ModelAdmin):
    list_display = ('user', 'email', 'refresh_token_expires_at', 'access_token_expires_at')
    search_fields = ('user__email', 'email')

@admin.register(PasswordResetSession)
class PasswordResetSessionAdmin(admin.ModelAdmin):
    list_display = ('user', 'token', 'created_at', 'is_expired')
    search_fields = ('user__email',)
    list_filter = ('created_at',)
    ordering = ('-created_at',)