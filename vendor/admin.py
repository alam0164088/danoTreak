# vendor/admin.py
from django.contrib import admin
from .models import Campaign, Visitor, Visit, Redemption

@admin.register(Campaign)
class CampaignAdmin(admin.ModelAdmin):
    list_display = ('name', 'vendor', 'reward_name', 'required_visits', 'is_active', 'created_at')
    list_filter = ('vendor', 'is_active',)
    search_fields = ('name', 'reward_name', 'vendor__shop_name')

@admin.register(Visitor)
class VisitorAdmin(admin.ModelAdmin):
    list_display = ('name', 'phone', 'vendor', 'total_visits', 'is_blocked', 'created_at')
    list_filter = ('vendor', 'is_blocked',)
    search_fields = ('name', 'phone', 'vendor__shop_name')

# @admin.register(Visit)
# class VisitAdmin(admin.ModelAdmin):
#     list_display = ('visitor', 'vendor', 'lat', 'lng', 'timestamp')
#     list_filter = ('vendor', 'timestamp',)
#     search_fields = ('visitor__name', 'visitor__phone', 'vendor__shop_name')

@admin.register(Redemption)
class RedemptionAdmin(admin.ModelAdmin):
    list_display = ('campaign', 'visitor', 'status', 'aliffited_id', 'redeemed_at', 'created_at')
    list_filter = ('status', 'campaign__vendor',)
    search_fields = ('visitor__name', 'visitor__phone', 'campaign__name', 'aliffited_id')
