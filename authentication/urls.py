from django.urls import path

from .views import (
    InitialAdminSignUpView,
    SignUpView,
    AdminSignUpView,
    LoginView,
    EmailVerificationView,
    AdminDashboardView,
    AdminUserManagementView,
    LogoutView,
    PasswordResetRequestView,
    PasswordResetVerifyCodeView,
    PasswordResetSetPasswordView,
    PasswordResetSetPasswordWithoutOTPView
)

urlpatterns = [
    path('signup/', SignUpView.as_view(), name='signup'),
    path('login/', LoginView.as_view(), name='login'),
    path('verify-email/', EmailVerificationView.as_view(), name='verify-email'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('password-reset/request/', PasswordResetRequestView.as_view(), name='password-reset-request'),
    path('password-reset/verify-code/', PasswordResetVerifyCodeView.as_view(), name='verify-reset-code'),
    path('password-reset/set-password/', PasswordResetSetPasswordWithoutOTPView.as_view(), name='password-reset-set-password'),
    
]
