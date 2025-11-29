# vendor/views.py
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.utils import timezone
from datetime import timedelta
from django.contrib.gis.geos import Point
from django.db.models import Count, Q
from django.shortcuts import get_object_or_404
from .models import Campaign, Visitor, Visit, Redemption


# ==================== DASHBOARD & LIST ====================
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def dashboard_overview(request):
    vendor = request.user.vendor_profile
    return Response({
        "total_visitor": Visitor.objects.filter(vendor=vendor).count(),
        "activate_campaign": Campaign.objects.filter(vendor=vendor, is_active=True).count(),
        "reward_redemptions": Redemption.objects.filter(campaign__vendor=vendor, status='redeemed').count(),
        "recent_visitor_name": list(Visitor.objects.filter(vendor=vendor).order_by('-created_at')[:10].values('name', 'phone', 'total_visits')),
        "available_campaign": list(Campaign.objects.filter(vendor=vendor, is_active=True).values('id', 'name', 'reward_name', 'required_visits'))
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_management(request):
    vendor = request.user.vendor_profile
    visitors = Visitor.objects.filter(vendor=vendor).values('id', 'name', 'phone', 'total_visits', 'is_blocked')
    return Response({"visitors": list(visitors)})


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def campaign_list(request):
    vendor = request.user.vendor_profile
    campaigns = Campaign.objects.filter(vendor=vendor).annotate(
        redemption_number=Count('redemptions', filter=Q(redemptions__status='redeemed'))
    ).values('id', 'name', 'reward_name', 'required_visits', 'reward_description', 'is_active', 'created_at', 'redemption_number')
    return Response({"campaigns": list(campaigns)})


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def redeem_history(request):
    vendor = request.user.vendor_profile
    history = Redemption.objects.filter(campaign__vendor=vendor).select_related('visitor', 'campaign').values(
        'id', 'visitor__id', 'visitor__name', 'visitor__phone', 'visitor__total_visits',
        'campaign__name', 'campaign__reward_name', 'status', 'aliffited_id', 'redeemed_at'
    )
    return Response({"history": list(history)})


# ==================== CAMPAIGN CRUD ====================
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_campaign(request):
    vendor = request.user.vendor_profile
    data = request.data

    campaign = Campaign.objects.create(
        vendor=vendor,
        name=data.get('name', 'Unnamed Campaign'),
        required_visits=int(data.get('required_visits', 5)),
        reward_name=data.get('reward_name', 'Free Item'),
        reward_description=data.get('reward_description', ''),
        is_active=data.get('is_active', True)
    )

    return Response({
        "message": "Campaign created successfully!",
        "campaign_id": campaign.id
    }, status=status.HTTP_201_CREATED)


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_campaign(request, campaign_id):
    vendor = request.user.vendor_profile
    campaign = get_object_or_404(Campaign, id=campaign_id, vendor=vendor)
    
    campaign.name = request.data.get('name', campaign.name)
    campaign.required_visits = request.data.get('required_visits', campaign.required_visits)
    campaign.reward_name = request.data.get('reward_name', campaign.reward_name)
    campaign.reward_description = request.data.get('reward_description', campaign.reward_description)
    campaign.is_active = request.data.get('is_active', campaign.is_active)
    campaign.save()

    return Response({
        "message": "Campaign updated successfully!",
        "campaign": {
            "id": campaign.id,
            "name": campaign.name,
            "reward_name": campaign.reward_name,
            "required_visits": campaign.required_visits,
            "is_active": campaign.is_active
        }
    })


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_campaign(request, campaign_id):
    vendor = request.user.vendor_profile
    campaign = get_object_or_404(Campaign, id=campaign_id, vendor=vendor)
    campaign.delete()
    return Response({"message": "Campaign deleted successfully!"})


# ==================== VISITOR ACTIONS ====================
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def block_visitor(request, visitor_id):
    visitor = get_object_or_404(Visitor, id=visitor_id, vendor=request.user.vendor_profile)
    visitor.is_blocked = not visitor.is_blocked
    visitor.save()
    return Response({"is_blocked": visitor.is_blocked})


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def confirm_redemption(request, redemption_id):
    redemption = get_object_or_404(Redemption, id=redemption_id, campaign__vendor=request.user.vendor_profile)
    if redemption.status == 'pending':
        redemption.status = 'redeemed'
        redemption.aliffited_id = request.data.get('aliffited_id', f"ALFF{redemption.id:05d}")
        redemption.redeemed_at = timezone.now()
        redemption.save()
    return Response({
        "status": "redeemed",
        "aliffited_id": redemption.aliffited_id
    })

# vendor/views.py এর শেষে যোগ করো (পুরানো checkin ফাংশনটা মুছে ফেলো)

# vendor/views.py → auto_checkin ফাংশনটা এভাবে রাখো (পুরোটা কপি-পেস্ট করো)
# vendor/views.py (শুধু auto_checkin ফাংশনটা পুরোটা রিপ্লেস করো)

from django.contrib.gis.geos import Point

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def auto_checkin(request):
    user = request.user

    # ১. lat, lng, vendor_id নেওয়া
    try:
        lat = float(request.data['lat'])
        lng = float(request.data['lng'])
        vendor_id = int(request.data['vendor_id'])
    except (KeyError, ValueError, TypeError):
        return Response({
            "error": "lat, lng and vendor_id are required and must be numbers"
        }, status=400)

    # ২. ভেন্ডর খুঁজে পাওয়া
    from authentication.models import Vendor as VendorProfile
    try:
        vendor = VendorProfile.objects.get(id=vendor_id)
    except VendorProfile.DoesNotExist:
        return Response({"error": "Shop not found"}, status=404)

    # ৩. লোকেশন আছে কিনা চেক
    if vendor.latitude is None or vendor.longitude is None:
        return Response({"error": "Shop location not set by owner"}, status=400)

    # Decimal → float সেফলি
    try:
        shop_lat = float(vendor.latitude)
        shop_lng = float(vendor.longitude)
    except (TypeError, ValueError):
        return Response({"error": "Invalid shop coordinates"}, status=500)

    # ৪. দূরত্ব হিসাব (Haversine)
    from math import radians, sin, cos, sqrt, atan2
    R = 6371000
    φ1, λ1 = radians(lat), radians(lng)
    φ2, λ2 = radians(shop_lat), radians(shop_lng)
    Δφ = φ2 - φ1
    Δλ = λ2 - λ1
    a = sin(Δφ/2)**2 + cos(φ1) * cos(φ2) * sin(Δλ/2)**2
    c = 2 * atan2(sqrt(a), sqrt(1-a))
    distance_m = R * c

    if distance_m > 100:
        return Response({
            "error": "You are too far from the shop",
            "distance_meters": round(distance_m, 1),
            "max_allowed_meters": 100
        }, status=400)

    # ৫. ফোন নম্বর ক্লিন করা (সবচেয়ে গুরুত্বপূর্ণ ফিক্স)
    try:
        raw_phone = user.profile.phone or ""
        if not raw_phone.strip():
            return Response({"error": "Please set phone number in your profile"}, status=400)

        # +880, space, -, () সব রিমুভ করো
        phone_digits = "".join(filter(str.isdigit, raw_phone.replace("+880", "0")))
        
        # শেষের ১১ ডিজিট নিয়ে 0 দিয়ে শুরু করো
        if len(phone_digits) >= 11:
            phone = "0" + phone_digits[-10:]  # 017xxxxxxxxx
        else:
            return Response({"error": "Invalid phone number"}, status=400)

    except AttributeError:
        return Response({"error": "Profile not found. Please complete your profile."}, status=400)

    # ৬. Visitor তৈরি/খুঁজে পাওয়া
    visitor, created = Visitor.objects.get_or_create(
        vendor=vendor,
        phone=phone,
        defaults={'name': user.get_full_name() or user.email.split('@')[0]}
    )

    if visitor.is_blocked:
        return Response({"error": "You are blocked from this shop"}, status=403)

    # ৭. ৫ মিনিটে একবার চেক-ইন
    five_min_ago = timezone.now() - timedelta(minutes=5)
    if Visit.objects.filter(visitor=visitor, timestamp__gte=five_min_ago).exists():
        return Response({
            "message": "Already checked in recently. Please wait 5 minutes.",
            "total_visits": visitor.total_visits
        }, status=200)

    # ৮. চেক-ইন সেভ করা (PointField দিয়ে)
    Visit.objects.create(
    visitor=visitor,
    vendor=vendor,
    lat=lat,
    lng=lng,

    )

    visitor.total_visits += 1
    visitor.save()

    # ৯. রিওয়ার্ড চেক
    campaign = Campaign.objects.filter(
        vendor=vendor,
        is_active=True,
        required_visits=visitor.total_visits
    ).first()

    reward_eligible = False
    reward_name = None
    if campaign:
        redemption, created_red = Redemption.objects.get_or_create(
            visitor=visitor,
            campaign=campaign,
            defaults={'status': 'pending'}
        )
        if created_red:
            reward_eligible = True
            reward_name = campaign.reward_name

    # ১০. সাকসেস রেসপন্স
    return Response({
        "success": True,
        "message": "Check-in successful!",
        "shop_name": vendor.shop_name,
        "your_name": visitor.name or "Guest",
        "total_visits": visitor.total_visits,
        "reward_eligible": reward_eligible,
        "reward_name": reward_name,
        "distance_meters": round(distance_m, 1)
    }, status=200)