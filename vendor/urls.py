# vendor/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('dashboard/', views.dashboard_overview),
    path('users/', views.user_management),
    path('campaigns/', views.campaign_list),
    path('campaigns/create/', views.create_campaign),
    path("campaign/<int:campaign_id>/toggle/", views.toggle_campaign_status),

    path('campaigns/<int:campaign_id>/update/', views.update_campaign),
    path('campaigns/<int:campaign_id>/delete/', views.delete_campaign),
    path('redeem-history/', views.redeem_history),
    path('redeem/<int:redemption_id>/toggle/', views.toggle_redemption_status),

    path('block/<int:visitor_id>/', views.block_visitor),

   
    path('dashboard/stats/', views.DashboardStatsView.as_view(), name='dashboard-stats'),
    path('users-vendors/list/', views.UserAndVendorListView.as_view(), name='users_vendors_list'),
    path('campaign-redemption-report/', views.CampaignRedemptionReportView.as_view(), name='campaign_redemption_report'),
    
    

]

# local import
def get_notification_api_view():
    from authentication.views import NotificationListAPI
    return NotificationListAPI.as_view()

urlpatterns.append(
    path('get_user_rewards/', get_notification_api_view(), name='get_user_rewards')
)
