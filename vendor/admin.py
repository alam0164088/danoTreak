from django.contrib import admin
from .models import Campaign, Visitor, Visit, Redemption


# ------------------------------------------------------
# CAMPAIGN ADMIN
# ------------------------------------------------------
@admin.register(Campaign)
class CampaignAdmin(admin.ModelAdmin):
    list_display = [
        'name', 'vendor', 'required_visits',
        'reward_name', 'is_active', 'created_at'
    ]
    list_filter = ['is_active', 'vendor']
    search_fields = ['name', 'reward_name']
    readonly_fields = ['created_at']


# ------------------------------------------------------
# VISITOR ADMIN
# ------------------------------------------------------
@admin.register(Visitor)
class VisitorAdmin(admin.ModelAdmin):
    list_display = [
        'id', 'vendor', 'name',
        'total_visits', 'is_blocked', 'created_at'
    ]
    list_filter = ['is_blocked', 'vendor']
    search_fields = ['name']
    readonly_fields = ['total_visits', 'created_at']


# ------------------------------------------------------
# VISIT ADMIN
# ------------------------------------------------------
@admin.register(Visit)
class VisitAdmin(admin.ModelAdmin):
    list_display = [
        'id', 'visitor', 'vendor', 'timestamp', 'lat', 'lng'
    ]
    list_filter = ['vendor', 'timestamp']
    readonly_fields = ['timestamp']


# ------------------------------------------------------
# REDEMPTION ADMIN
# ------------------------------------------------------
@admin.register(Redemption)
class RedemptionAdmin(admin.ModelAdmin):
    list_display = [
        'id', 'visitor', 'campaign',
        'status', 'aliffited_id', 'redeemed_at'
    ]
    list_filter = ['status', 'campaign__vendor']
    readonly_fields = ['created_at', 'redeemed_at']
