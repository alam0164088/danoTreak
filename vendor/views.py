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
from .utils import generate_aliffited_id

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def dashboard_overview(request):
    vendor = getattr(request.user, "vendor_profile", None)
    if not vendor:
        return Response({"error": "Vendor profile not found"}, status=403)

    total_visitor = Visitor.objects.filter(vendor=vendor).count()

    active_campaign = Campaign.objects.filter(vendor=vendor, is_active=True).count()
    deactivate_campaign = Campaign.objects.filter(vendor=vendor, is_active=False).count()

    # Pending reward (eligible, not yet redeemed)
    pending_rewards = Redemption.objects.filter(
        campaign__vendor=vendor,
        status='pending'
    ).count()

    # Redeemed rewards
    redeemed_rewards = Redemption.objects.filter(
        campaign__vendor=vendor,
        status='redeemed'
    ).count()

    return Response({
        "total_visitor": total_visitor,
        "active_campaign": active_campaign,
        "deactivate_campaign": deactivate_campaign,
        "pending_rewards": pending_rewards,
        "redeemed_rewards": redeemed_rewards
    })




@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_management(request):
    vendor = getattr(request.user, "vendor_profile", None)
    if not vendor:
        return Response({"error": "Vendor profile not found"}, status=403)

    visitors = Visitor.objects.filter(vendor=vendor).order_by(
        '-total_visits', '-created_at'
    )

    data = []
    for visitor in visitors:
        # visitor-এর জন্য active campaign
        active_campaigns = Campaign.objects.filter(vendor=vendor, is_active=True)
        campaigns_list = []

        for campaign in active_campaigns:
            # Redemption check
            redemption = Redemption.objects.filter(visitor=visitor, campaign=campaign).first()
            if redemption:
                status = redemption.status
            else:
                # যদি Redeem entry না থাকে এবং visitor required_visits পূর্ণ করে
                if visitor.total_visits >= campaign.required_visits:
                    status = 'pending'
                else:
                    status = 'not_eligible'

            campaigns_list.append({
                "campaign_id": campaign.id,
                "campaign_name": campaign.name,
                "reward_name": campaign.reward_name,
                "status": status
            })

        data.append({
            "visitor_id": visitor.id,
            "visitor_name": visitor.name,
            "visitor_phone": visitor.phone,
            "total_visits": visitor.total_visits,
            "is_blocked": visitor.is_blocked,
            "campaigns": campaigns_list
        })

    return Response({"visitors": data})



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
def toggle_redemption_status(request, redemption_id):
    vendor = getattr(request.user, "vendor_profile", None)
    if not vendor:
        return Response({"error": "Vendor profile not found"}, status=403)

    redemption = get_object_or_404(
        Redemption,
        id=redemption_id,
        campaign__vendor=vendor
    )

    # টোগল logic
    if redemption.status == 'pending':
        redemption.status = 'redeemed'
        redemption.redeemed_at = timezone.now()
    else:
        redemption.status = 'pending'
        redemption.redeemed_at = None

    redemption.save()

    return Response({
        "id": redemption.id,
        "visitor_name": redemption.visitor.name,
        "campaign_name": redemption.campaign.name,
        "status": redemption.status,
        "redeemed_at": redemption.redeemed_at
    })



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

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def toggle_campaign_status(request, campaign_id):
    vendor = getattr(request.user, "vendor_profile", None)
    if not vendor:
        return Response({"error": "Vendor profile not found"}, status=403)

    campaign = get_object_or_404(Campaign, id=campaign_id, vendor=vendor)

    campaign.is_active = not campaign.is_active
    campaign.save()

    return Response({
        "message": "Campaign status updated",
        "is_active": campaign.is_active
    })


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
