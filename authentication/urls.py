from django.urls import path
from .views import (
    RegisterView, SendOTPView, ResendOTPView, VerifyOTPView, LoginView,
    RefreshTokenView, LogoutView, ForgotPasswordView, VerifyResetOTPView,
    ResetPasswordConfirmView, ChangePasswordView, Enable2FAView, Verify2FAView,
    MeView, VendorSignUpView, VendorDashboardView, AdminUserManagementView,
    LoyaltyProgramView, RedemptionView, InitialAdminSignUpView, AdminSignUpView,
)

urlpatterns = [
    # 🔹 Registration & OTP
    path('auth/register/', RegisterView.as_view(), name='register'),
    path('auth/otp/resend/', ResendOTPView.as_view(), name='resend-otp'),
    path('auth/otp/verify/', VerifyOTPView.as_view(), name='verify-otp'),

    # 🔹 Vendor Signup & Dashboard
    path('auth/vendor/register/', VendorSignUpView.as_view(), name='vendor-register'),
    path('auth/vendor/dashboard/', VendorDashboardView.as_view(), name='vendor-dashboard'),
    path('auth/vendor/loyalty/', LoyaltyProgramView.as_view(), name='loyalty-program'),
    path('auth/vendor/loyalty/<int:program_id>/', LoyaltyProgramView.as_view(), name='loyalty-program-detail'),
    path('auth/vendor/redemptions/', RedemptionView.as_view(), name='redemptions'),
    path('auth/vendor/redemptions/<int:redemption_id>/', RedemptionView.as_view(), name='redemption-detail'),

    # 🔹 Admin Signup
    path('auth/admin/register/initial/', InitialAdminSignUpView.as_view(), name='initial-admin-register'),
    path('auth/admin/register/', AdminSignUpView.as_view(), name='admin-register'),

    # 🔹 Login & Tokens
    path('auth/login/', LoginView.as_view(), name='login'),
    path('auth/token/refresh/', RefreshTokenView.as_view(), name='refresh-token'),
    path('auth/logout/', LogoutView.as_view(), name='logout'),

    # 🔹 Password Management
    path('auth/password/forgot/', ForgotPasswordView.as_view(), name='forgot-password'),
    path('auth/password/reset/verify/', VerifyResetOTPView.as_view(), name='verify-reset-otp'),
    path('auth/password/reset/confirm/', ResetPasswordConfirmView.as_view(), name='reset-password-confirm'),
    path('auth/password/change/', ChangePasswordView.as_view(), name='change-password'),

    # 🔹 Two-Factor Authentication (2FA)
    path('auth/2fa/enable/', Enable2FAView.as_view(), name='enable-2fa'),
    path('auth/2fa/verify/', Verify2FAView.as_view(), name='verify-2fa'),

    # 🔹 User Profile
    path('auth/me/', MeView.as_view(), name='me'),

    # 🔹 Admin User Management
    path('auth/admin/users/', AdminUserManagementView.as_view(), name='admin-user-management'),
    path('auth/admin/users/<int:user_id>/', AdminUserManagementView.as_view(), name='admin-user-detail'),
]