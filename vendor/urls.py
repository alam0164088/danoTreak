# vendor/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('dashboard/', views.dashboard_overview),
    path('users/', views.user_management),
    path('campaigns/', views.campaign_list),           # GET - সব ক্যাম্পেইন
    path('campaigns/create/', views.create_campaign),  # POST - তৈরি
    path('campaigns/<int:campaign_id>/update/', views.update_campaign),   # PUT
    path('campaigns/<int:campaign_id>/delete/', views.delete_campaign),  # DELETE
    path('redeem-history/', views.redeem_history),
    path('block/<int:visitor_id>/', views.block_visitor),
    path('confirm/<int:redemption_id>/', views.confirm_redemption),
    path('checkin/', views.auto_checkin),
]