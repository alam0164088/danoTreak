# authentication/urls.py   ← পুরো ফাইলটা এমন করো

from django.urls import path
from .views import (
    RegisterView, VendorSignUpView, InitialAdminSignUpView, AdminSignUpView,
    AdminUserManagementView, SendOTPView, VerifyOTPView, LoginView,
    RefreshTokenView, LogoutView, ForgotPasswordView, VerifyResetOTPView,
    ResetPasswordConfirmView, ChangePasswordView, Enable2FAView,
    Verify2FAView, MeView, ResendOTPView,
    GoogleLoginView, GoogleCallbackView, AppleLoginView,  # AppleCallbackView নেই!
    MyReferralCodeView, CompleteVendorProfileView,
    VendorProfileUpdateRequestView, approve_vendor_update_request,
    reject_vendor_update_request, NearbyVendorsAPI, CategoryNearbyVendorsAPI,
    AdminAllVendorCredentialsView, ToggleFavoriteVendor, MyFavoriteVendorsAPI,
)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('vendor-signup/', VendorSignUpView.as_view(), name='vendor_signup'),
    path('complete-vendor-profile/', CompleteVendorProfileView.as_view(), name='complete_vendor_profile'),

    # Vendor Update Requests
    path('vendor/update-request/', VendorProfileUpdateRequestView.as_view(), name='vendor_update_request'),
    path('admin/approve-update/<int:request_id>/', approve_vendor_update_request, name='admin_approve_update'),
    path('admin/reject-update/<int:request_id>/', reject_vendor_update_request, name='admin_reject_update'),

    # Nearby & Favorites
    path('toggle-favorite/', ToggleFavoriteVendor.as_view(), name='toggle-favorite'),
    path('my-favorites-vendor/', MyFavoriteVendorsAPI.as_view(), name='my-favorites'),
    path('api/nearby-vendors/', NearbyVendorsAPI.as_view(), name='nearby-vendors'),
    path('api/nearby-category/', CategoryNearbyVendorsAPI.as_view(), name='nearby-category'),

    # Admin
    path('admin/all-vendor-credentials/', AdminAllVendorCredentialsView.as_view(), name='all-vendor-credentials'),
    path('initial-admin-signup/', InitialAdminSignUpView.as_view(), name='initial_admin_signup'),
    path('admin-signup/', AdminSignUpView.as_view(), name='admin_signup'),
    path('users/<int:user_id>/', AdminUserManagementView.as_view(), name='user_management_detail'),
    path('users/', AdminUserManagementView.as_view(), name='user_management_list'),

    # Auth
    path('send-otp/', SendOTPView.as_view(), name='send_otp'),
    path('verify-otp/', VerifyOTPView.as_view(), name='verify_otp'),
    path('login/', LoginView.as_view(), name='login'),
    path('refresh-token/', RefreshTokenView.as_view(), name='refresh_token'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('forgot-password/', ForgotPasswordView.as_view(), name='forgot_password'),
    path('verify-reset-otp/', VerifyResetOTPView.as_view(), name='verify_reset_otp'),
    path('reset-password/', ResetPasswordConfirmView.as_view(), name='reset_password'),
    path('change-password/', ChangePasswordView.as_view(), name='change_password'),
    path('enable-2fa/', Enable2FAView.as_view(), name='enable_2fa'),
    path('verify-2fa/', Verify2FAView.as_view(), name='verify_2fa'),
    path('me/', MeView.as_view(), name='me'),
    path('resend-otp/', ResendOTPView.as_view(), name='resend_otp'),
    path('my-referral-code/', MyReferralCodeView.as_view(), name='my_referral_code'),

    # Social Login
    # Social Login – এখানে /auth/ যোগ করলাম
    path("auth/google/login/", GoogleLoginView.as_view(), name="google_login"),
    path("auth/google/callback/", GoogleCallbackView.as_view(), name="google_callback"),
    path("auth/apple/login/", AppleLoginView.as_view(), name="apple_login"),
]