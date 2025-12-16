from django.contrib import admin
from .models import User, Token, PasswordResetSession,  Profile, Vendor,EmailOTP

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ['email', 'full_name', 'role', 'is_email_verified', 'is_active', 'created_at']
    list_filter = ['role', 'is_email_verified', 'is_active']
    search_fields = ['email', 'full_name']

@admin.register(Token)
class TokenAdmin(admin.ModelAdmin):
    list_display = ['user', 'email', 'access_token', 'refresh_token', 'revoked', 'created_at']
    list_filter = ['revoked']
    search_fields = ['user__email']

@admin.register(PasswordResetSession)
class PasswordResetSessionAdmin(admin.ModelAdmin):
    list_display = ['user', 'token', 'created_at']
    search_fields = ['user__email']


@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ['user', 'employee_id', 'phone', 'created_at']
    search_fields = ['user__email', 'employee_id']

    

# authentication/admin.py

from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from .models import Vendor


@admin.register(Vendor)
class VendorAdmin(admin.ModelAdmin):
    list_display = (
        'shop_name_link',
        'vendor_name',
        'phone_number',
        'category_badge',
        'location_preview',
        'images_count',
        'profile_status',
        'created_at'
    )

    list_filter = ('category', 'is_profile_complete', 'created_at')
    search_fields = ('shop_name', 'vendor_name', 'phone_number', 'shop_address', 'user__email')

    # এখানে শুধু আসল ফিল্ড আর কাস্টম রিড-ওনলি মেথড রাখো
    readonly_fields = (
        'created_at', 
        'updated_at', 
        'open_in_google_maps',   # এটা এখানে রাখো
        'images_preview'         # এটাও এখানে
    )

    fieldsets = (
        ('User & Basic Info', {
            'fields': ('user', 'vendor_name', 'shop_name', 'phone_number', 'category')
        }),
        ('Address & Location', {
            'fields': ('shop_address', 'latitude', 'longitude', 'open_in_google_maps'),
        }),
        ('Shop Images', {
            'fields': ('shop_images', 'images_preview'),
            'description': 'ছবির URL গুলো JSON লিস্টে দিন। উদা: ["https://...", "https://..."]'
        }),
        ('Status', {
            'fields': ('is_profile_complete',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    # কাস্টম ডিসপ্লে মেথডগুলো
    def shop_name_link(self, obj):
        url = reverse("admin:authentication_vendor_change", args=[obj.pk])
        return format_html(f'<a href="{url}"><strong>{obj.shop_name}</strong></a>')
    shop_name_link.short_description = "Shop Name"

    def category_badge(self, obj):
        colors = {
            'food': '#ff6b6b', 'beverage': '#4ecdc4', 'grocery': '#45b7d1',
            'pharmacy': '#96ceb4', 'fashion': '#f8b500', 'electronics': '#a29bfe',
            'nightlife': '#6c5ce7', 'others': '#b2bec3'
        }
        color = colors.get(obj.category, '#636e72')
        return format_html(
            f'<span style="background:{color}; color:white; padding:4px 10px; border-radius:12px; font-size:11px; font-weight:bold;">'
            f'{obj.get_category_display()}</span>'
        )
    category_badge.short_description = "Category"

    def location_preview(self, obj):
        if obj.latitude and obj.longitude:
            maps_url = f"https://www.google.com/maps?q={obj.latitude},{obj.longitude}"
            return format_html(f'<a href="{maps_url}" target="_blank">Open Map<br><small>{obj.latitude}, {obj.longitude}</small></a>')
        return "Not Set"
    location_preview.short_description = "Location"

    def open_in_google_maps(self, obj):
        if obj.latitude and obj.longitude:
            maps_url = f"https://www.google.com/maps?q={obj.latitude},{obj.longitude}"
            return format_html(f'<a href="{maps_url}" target="_blank" style="color:#1a73e8; font-weight:bold;">Open in Google Maps</a>')
        return "No location"
    open_in_google_maps.short_description = "Google Maps"

    def images_count(self, obj):
        count = len(obj.shop_images) if isinstance(obj.shop_images, list) else 0
        return f"{count} images"
    images_count.short_description = "Images"

    def images_preview(self, obj):
        if not obj.shop_images:
            return "No images uploaded"
        html = "<div style='display:flex; flex-wrap:wrap; gap:8px; margin-top:10px;'>"
        for url in obj.shop_images[:6]:
            html += f'<img src="{url}" style="width:120px; height:120px; object-fit:cover; border-radius:8px; border:2px solid #ddd;">'
        if len(obj.shop_images) > 6:
            html += f"<div style='padding:10px; background:#f1f3f4; border-radius:8px;'>+ {len(obj.shop_images)-6} more</div>"
        html += "</div>"
        return format_html(html)
    images_preview.short_description = "Image Preview"

    def profile_status(self, obj):
        color = "green" if obj.is_profile_complete else "red"
        text = "Complete" if obj.is_profile_complete else "Incomplete"
        return format_html(f'<b style="color:{color}">{text}</b>')
    profile_status.short_description = "Status"




from django.contrib import admin
from .models import EmailOTP

@admin.register(EmailOTP)
class EmailOTPAdmin(admin.ModelAdmin):
    list_display = ['email', 'raw_otp', 'otp_hash', 'expires_at', 'created_at']
    readonly_fields = ['raw_otp', 'otp_hash', 'expires_at', 'created_at']


from .models import Vendor, VendorProfileUpdateRequest
# authentication/admin.py → VendorAdmin এর নিচে যোগ করো

@admin.register(VendorProfileUpdateRequest)
class VendorProfileUpdateRequestAdmin(admin.ModelAdmin):
    list_display = ('vendor_shop', 'requested_by', 'status_badge', 'created_at', 'action_buttons')
    list_filter = ('status', 'created_at')
    search_fields = ('vendor__shop_name', 'requested_by__email')
    readonly_fields = ('vendor', 'requested_by', 'new_data', 'created_at', 'reviewed_at', 'reason')

    def vendor_shop(self, obj):
        return obj.vendor.shop_name
    vendor_shop.short_description = "Shop"

    def status_badge(self, obj):
        colors = {'pending': 'orange', 'approved': 'green', 'rejected': 'red'}
        return format_html(f'<b style="color:{colors[obj.status]}">{obj.get_status_display()}</b>')
    status_badge.short_description = "Status"

        
    def action_buttons(self, obj):
        if obj.status != 'pending':
            return "Done"
        
        approve_url = reverse('admin_approve_update', args=[obj.id])
        reject_url = reverse('admin_reject_update', args=[obj.id])
        
        return format_html(
            f'<a href="{approve_url}" style="color:green; margin-right:10px;">Approve</a>'
            f'<a href="{reject_url}" style="color:red;">Reject</a>'
        )
    action_buttons.short_description = "Actions"
    action_buttons.allow_tags = True




from django.contrib import admin
from .models import FavoriteVendor

@admin.register(FavoriteVendor)
class FavoriteVendorAdmin(admin.ModelAdmin):
    list_display = (
        'id', 
        'user', 
        'get_vendor_name', 
        'get_ai_vendor_name', 
        'expiry_date', 
        'created_at'
    )
    list_filter = ('user', 'vendor', 'expiry_date')
    search_fields = ('user__email', 'vendor__shop_name', 'ai_vendor_data__shop_name', 'ai_vendor_id')
    readonly_fields = ('created_at',)
    
    def get_vendor_name(self, obj):
        return obj.vendor.shop_name if obj.vendor else "-"
    get_vendor_name.short_description = "DB Vendor"

    def get_ai_vendor_name(self, obj):
        if obj.ai_vendor_data:
            return obj.ai_vendor_data.get('shop_name', obj.ai_vendor_id or "AI Vendor")
        return "-"
    get_ai_vendor_name.short_description = "AI Vendor"
