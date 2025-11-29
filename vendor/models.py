# vendor/models.py
from django.db import models
from django.contrib.gis.db import models as gis_models
from django.contrib.gis.geos import Point
from authentication.models import Vendor as VendorProfile  # তোমার আসল Vendor মডেল


class Campaign(models.Model):
    vendor = models.ForeignKey(VendorProfile, on_delete=models.CASCADE, related_name='campaigns')
    name = models.CharField(max_length=200)
    required_visits = models.PositiveIntegerField(default=5)
    reward_name = models.CharField(max_length=200)
    reward_description = models.TextField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} - {self.vendor.shop_name}"

class Visitor(models.Model):
    vendor = models.ForeignKey(VendorProfile, on_delete=models.CASCADE, related_name='visitors')
    # max_length ১৫ → ২০ করা হলো (যাতে +880 বা স্পেস থাকলেও সমস্যা না হয়)
    phone = models.CharField(max_length=20, db_index=True)
    name = models.CharField(max_length=100, blank=True, null=True)
    total_visits = models.PositiveIntegerField(default=0)
    is_blocked = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('vendor', 'phone')

    def __str__(self):
        return f"{self.name or self.phone} ({self.total_visits} visits)"

# vendor/models.py → Visit মডেল (GeoDjango বাদ দাও)

class Visit(models.Model):
    visitor = models.ForeignKey(Visitor, on_delete=models.CASCADE, related_name='visits')
    vendor = models.ForeignKey(VendorProfile, on_delete=models.CASCADE)
    
    # GeoDjango বাদ → সিম্পল ফিল্ড
    lat = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    lng = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['timestamp']),
        ]

    def __str__(self):
        return f"Visit by {self.visitor} at {self.timestamp}"
    
class Redemption(models.Model):
    campaign = models.ForeignKey(Campaign, on_delete=models.CASCADE, related_name='redemptions')
    visitor = models.ForeignKey(Visitor, on_delete=models.CASCADE, related_name='redemptions')
    aliffited_id = models.CharField(max_length=50, blank=True, null=True)
    status = models.CharField(max_length=10, choices=[('pending', 'Pending'), ('redeemed', 'Redeemed')], default='pending')
    redeemed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.visitor} → {self.campaign.reward_name} ({self.status})"