from django.urls import path
from .views import InitialAdminSignUpView, SignUpView, AdminSignUpView, LoginView, EmailVerificationView, AdminDashboardView, AdminUserManagementView, LogoutView
urlpatterns = [

    path('signup/', SignUpView.as_view(), name='signup'),

    path('login/', LoginView.as_view(), name='login'),
    path('verify-email/', EmailVerificationView.as_view(), name='verify-email'),
    path('logout/', LogoutView.as_view(), name='logout'),
    
]