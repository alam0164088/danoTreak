from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status

from django.utils import timezone
from datetime import timedelta
from math import radians, sin, cos, sqrt, atan2
from django.db.models import Count, Q
from django.shortcuts import get_object_or_404

from authentication.models import Vendor
from .models import Campaign, Visitor, Visit, Redemption
from vendor.utils import generate_aliffited_id








@api_view(['GET'])
@permission_classes([IsAuthenticated])
def dashboard_overview(request):
    vendor = getattr(request.user, "vendor_profile", None)
    if not vendor:
        return Response({"error": "Vendor profile not found"}, status=403)

    return Response({
        "total_visitor": Visitor.objects.filter(vendor=vendor).count(),
        "active_campaign": Campaign.objects.filter(vendor=vendor, is_active=True).count(),
        "reward_redemptions": Redemption.objects.filter(
            campaign__vendor=vendor,
            status='redeemed'
        ).count(),
        "recent_visitors": list(
            Visitor.objects.filter(vendor=vendor)
            .order_by('-created_at')[:10]
            .values('name', 'phone', 'total_visits')
        ),
        "available_campaign": list(
            Campaign.objects.filter(vendor=vendor, is_active=True)
            .values('id', 'name', 'reward_name', 'required_visits')
        )
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_management(request):
    vendor = getattr(request.user, "vendor_profile", None)
    if not vendor:
        return Response({"error": "Vendor profile not found"}, status=403)

    visitors = Visitor.objects.filter(vendor=vendor).order_by(
        '-total_visits', '-created_at'
    ).values('id', 'name', 'phone', 'total_visits', 'is_blocked')

    return Response({"visitors": list(visitors)})


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def campaign_list(request):
    vendor = getattr(request.user, "vendor_profile", None)
    if not vendor:
        return Response({"error": "Vendor profile not found"}, status=403)

    campaigns = Campaign.objects.filter(vendor=vendor).annotate(
        redemption_number=Count(
            'redemptions',
            filter=Q(redemptions__status='redeemed')
        )
    ).values(
        'id', 'name', 'reward_name', 'required_visits',
        'reward_description', 'is_active',
        'created_at', 'redemption_number'
    )

    return Response({"campaigns": list(campaigns)})



@api_view(['GET'])
@permission_classes([IsAuthenticated])
def redeem_history(request):
    vendor = getattr(request.user, "vendor_profile", None)
    if not vendor:
        return Response({"error": "Vendor profile not found"}, status=403)

    history = Redemption.objects.filter(
        campaign__vendor=vendor
    ).values(
        'id',
        'visitor__name',
        'visitor__phone',
        'visitor__total_visits',
        'campaign__name',
        'campaign__reward_name',
        'status',
        'aliffited_id',
        'redeemed_at'
    )

    return Response({"history": list(history)})



@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_campaign(request):
    vendor = getattr(request.user, "vendor_profile", None)
    if not vendor:
        return Response({"error": "Vendor profile not found"}, status=403)

    campaign = Campaign.objects.create(
        vendor=vendor,
        name=request.data.get('name'),
        required_visits=int(request.data.get('required_visits', 5)),
        reward_name=request.data.get('reward_name'),
        reward_description=request.data.get('reward_description', ''),
        is_active=request.data.get('is_active', True)
    )

    return Response(
        {"message": "Campaign created", "id": campaign.id},
        status=status.HTTP_201_CREATED
    )

@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_campaign(request, campaign_id):
    vendor = getattr(request.user, "vendor_profile", None)
    if not vendor:
        return Response({"error": "Vendor profile not found"}, status=403)

    campaign = get_object_or_404(Campaign, id=campaign_id, vendor=vendor)

    for field in ['name', 'reward_name', 'reward_description', 'is_active']:
        if field in request.data:
            setattr(campaign, field, request.data[field])

    if 'required_visits' in request.data:
        campaign.required_visits = int(request.data['required_visits'])

    campaign.save()
    return Response({"message": "Campaign updated"})


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_campaign(request, campaign_id):
    vendor = getattr(request.user, "vendor_profile", None)
    if not vendor:
        return Response({"error": "Vendor profile not found"}, status=403)

    get_object_or_404(Campaign, id=campaign_id, vendor=vendor).delete()
    return Response({"message": "Campaign deleted"})


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def block_visitor(request, visitor_id):
    vendor = getattr(request.user, "vendor_profile", None)
    if not vendor:
        return Response({"error": "Vendor profile not found"}, status=403)

    visitor = get_object_or_404(Visitor, id=visitor_id, vendor=vendor)
    visitor.is_blocked = not visitor.is_blocked
    visitor.save()

    return Response({"is_blocked": visitor.is_blocked})


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def confirm_redemption(request, redemption_id):
    vendor = getattr(request.user, "vendor_profile", None)
    if not vendor:
        return Response({"error": "Vendor profile not found"}, status=403)

    redemption = get_object_or_404(
        Redemption,
        id=redemption_id,
        campaign__vendor=vendor
    )

    if redemption.status == 'pending':
        redemption.status = 'redeemed'
        redemption.redeemed_at = timezone.now()
        redemption.save()

    return Response({
        "status": "redeemed",
        "aliffited_id": redemption.aliffited_id
    })



@api_view(['POST'])
@permission_classes([IsAuthenticated])
def auto_checkin(request):
    user = request.user

    try:
        lat = float(request.data['lat'])
        lng = float(request.data['lng'])
        vendor_id = int(request.data['vendor_id'])
    except:
        return Response({"message": "lat, lng, vendor_id required"}, status=400)

    vendor = get_object_or_404(Vendor, id=vendor_id)

    # Distance check (100m)
    R = 6371000
    φ1, λ1 = radians(lat), radians(lng)
    φ2, λ2 = radians(float(vendor.latitude)), radians(float(vendor.longitude))

    a = sin((φ2-φ1)/2)**2 + cos(φ1)*cos(φ2)*sin((λ2-λ1)/2)**2
    distance = R * 2 * atan2(sqrt(a), sqrt(1-a))

    if distance > 100:
        return Response({"message": "Too far"}, status=400)

    visitor, _ = Visitor.objects.get_or_create(
        vendor=vendor,
        user=user,
        defaults={"name": user.username}
    )

    if visitor.is_blocked:
        return Response({"message": "Blocked"}, status=403)

    if Visit.objects.filter(
        visitor=visitor,
        timestamp__gte=timezone.now() - timedelta(minutes=5)
    ).exists():
        return Response({"message": "Already checked in"})

    Visit.objects.create(visitor=visitor, vendor=vendor, lat=lat, lng=lng)
    visitor.total_visits += 1
    visitor.save()

    campaign = Campaign.objects.filter(
        vendor=vendor,
        is_active=True,
        required_visits=visitor.total_visits
    ).first()

    reward = None
    if campaign:
        redemption, created = Redemption.objects.get_or_create(
            visitor=visitor,
            campaign=campaign,
            defaults={
                "status": "pending",
                "aliffited_id": generate_aliffited_id()
            }
        )
        if created:
            reward = campaign.reward_name

    return Response({
        "message": "Check-in successful",
        "total_visits": visitor.total_visits,
        "reward": reward
    })
