from django.urls import path
from .views import (
    RegisterView, VendorSignUpView, CompleteVendorProfileView,
    VendorProfileUpdateRequestView, approve_vendor_update_request,
    reject_vendor_update_request, AllVendorsListView, user_nearby_vendors,
    category_nearby_vendors, AdminAllVendorCredentialsView,
    InitialAdminSignUpView, AdminSignUpView, AdminUserManagementView,
    AdminPendingVendorUpdateRequestsView, live_users_view,
    SendOTPView, VerifyOTPView, LoginView, RefreshTokenView, LogoutView,
    ForgotPasswordView, VerifyResetOTPView, ResetPasswordConfirmView,
    ChangePasswordView, Enable2FAView, Verify2FAView, MeView,
    ResendOTPView, MyReferralCodeView,
    google_login_view,  # ✅ Function import করুন
    AppleLoginView,
)


urlpatterns = [
    # Live Users
    path('live-users/', live_users_view, name='live_users'),

    # Registration & Profile
    path('register/', RegisterView.as_view(), name='register'),
    path('vendor-signup/', VendorSignUpView.as_view(), name='vendor_signup'),
    path('complete-vendor-profile/', CompleteVendorProfileView.as_view(), name='complete_vendor_profile'),
    path('vendors/', AllVendorsListView.as_view(), name='all_vendors'),

    # Vendor Update Requests
    path('vendor/update-request/', VendorProfileUpdateRequestView.as_view(), name='vendor_update_request'),
    path('admin/approve-update/<int:request_id>/', approve_vendor_update_request, name='admin_approve_update'),
    path('admin/reject-update/<int:request_id>/', reject_vendor_update_request, name='admin_reject_update'),
    path('admin/vendor-update-requests/', AdminPendingVendorUpdateRequestsView.as_view(), name='admin_vendor_update_requests'),

    # Nearby Vendors
    path('user/nearby-vendors/', user_nearby_vendors, name='user_nearby_vendors'),
    path('category-nearby-vendors/<str:category>/', category_nearby_vendors, name='category_nearby_vendors'),

    # Admin
    path('admin/all-vendor-credentials/', AdminAllVendorCredentialsView.as_view(), name='all_vendor_credentials'),
    path('initial-admin-signup/', InitialAdminSignUpView.as_view(), name='initial_admin_signup'),
    path('admin-signup/', AdminSignUpView.as_view(), name='admin_signup'),
    path('users/<int:user_id>/', AdminUserManagementView.as_view(), name='user_management_detail'),
    path('users/', AdminUserManagementView.as_view(), name='user_management_list'),

    # Authentication
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

    # Social Login (Flutter থেকে POST)
    path('auth/google/login/', google_login_view, name='google_login'),  # ✅ Function call
    path('auth/apple/login/', AppleLoginView.as_view(), name='apple_login'),
]
