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




# admin dashboard এর জন্য views.py এ আর কোনো কোড নেই।


# vendor/views.py (অথবা যেকোনো অ্যাপের views.py)



# vendor/views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from authentication.permissions import IsAdmin  # ← এখান থেকে ইমপোর্ট করুন
from authentication.models import User, Vendor
from .models import Campaign, Redemption

class DashboardStatsView(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]  # ← এটাই ঠিক করুন

    def get(self, request):
        total_users = User.objects.filter(role='user').count()
        total_vendors = Vendor.objects.count()
        active_campaigns = Campaign.objects.filter(is_active=True).count()
        total_reward_redemptions = Redemption.objects.filter(status='redeemed').count()

        data = {
            "total_users": total_users,
            "total_vendors": total_vendors,
            "active_campaigns": active_campaigns,
            "total_reward_redemptions": total_reward_redemptions,
        }
        return Response(data, status=200)
    

# vendor/views.py (শেষের অংশ আপডেট)
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from authentication.permissions import IsAdmin
from authentication.models import User, Vendor
from .models import Campaign, Redemption, Visitor, Visit
from django.db.models import Q

class UserAndVendorListView(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]

    def get(self, request):
        search = request.query_params.get('search', '').strip()

        # -------------------------
        # USERS QUERY
        # -------------------------
        users_qs = User.objects.filter(role='user')
        if search:
            users_qs = users_qs.filter(
                Q(email__icontains=search) | Q(full_name__icontains=search)
            )
        users = users_qs.values(
            'id', 'email', 'full_name', 'role', 'is_active', 'created_at'
        ).order_by('-created_at')

        user_ids = [u['id'] for u in users]

        # -------------------------
        # VISITS MAPPING
        # -------------------------
        visits = Visit.objects.filter(visitor__user__id__in=user_ids)
        visits_count_map = {}
        visited_vendors_map = {}

        for v in visits:
            if not v.visitor or not v.visitor.user:
                continue
            uid = v.visitor.user.id
            visits_count_map[uid] = visits_count_map.get(uid, 0) + 1
            if uid not in visited_vendors_map:
                visited_vendors_map[uid] = set()
            if v.vendor and v.vendor.id:
                visited_vendors_map[uid].add(v.vendor.id)

        # -------------------------
        # REDEMPTIONS (ALFF IDs)
        # -------------------------
        redemptions = Redemption.objects.filter(visitor__user__id__in=user_ids, status='redeemed')
        aliffited_map = {}
        for r in redemptions:
            if not r.visitor or not r.visitor.user:
                continue
            uid = r.visitor.user.id
            if uid not in aliffited_map:
                aliffited_map[uid] = []
            if r.aliffited_id:  # শুধুমাত্র জেনারেট হওয়া ALFF আইডি
                aliffited_map[uid].append(r.aliffited_id)

        # -------------------------
        # USER DATA
        # -------------------------
        user_data = []
        for u in users:
            uid = u['id']
            visited_vendors = visited_vendors_map.get(uid, set())
            active_campaigns = Campaign.objects.filter(
                vendor__id__in=visited_vendors,
                is_active=True
            ).values('id', 'name', 'reward_name', 'required_visits')

            user_data.append({
                **u,
                "total_visits": visits_count_map.get(uid, 0),
                "active_campaigns": list(active_campaigns),
                "aliffited_ids": aliffited_map.get(uid, []),
                "total_aliffited_ids": len(aliffited_map.get(uid, []))
            })

        # -------------------------
        # VENDORS DATA
        # -------------------------
        vendors_qs = Vendor.objects.select_related('user')
        if search:
            vendors_qs = vendors_qs.filter(
                Q(user__email__icontains=search) |
                Q(shop_name__icontains=search) |
                Q(vendor_name__icontains=search)
            )
        vendors = vendors_qs.values(
            'user__id',
            'user__email',
            'shop_name',
            'vendor_name',
            'phone_number',
            'is_profile_complete',
        )

        vendor_data = []
        for v in vendors:
            vendor_user_id = v['user__id']
            # ভিজিট সংখ্যা
            total_visits = Visit.objects.filter(vendor__id=vendor_user_id).count()
            # একটিভ ক্যাম্পেইন আছে কি না
            has_active_campaign = Campaign.objects.filter(vendor__id=vendor_user_id, is_active=True).exists()

            vendor_data.append({
                "user_id": v['user__id'],
                "email": v['user__email'],
                "shop_name": v['shop_name'] or "N/A",
                "vendor_name": v['vendor_name'] or "N/A",
                "phone": v['phone_number'] or "N/A",
                "profile_complete": v['is_profile_complete'],
                "has_active_campaign": "Yes" if has_active_campaign else "No",
                "total_visits": total_visits
            })

        # -------------------------
        # FINAL RESPONSE
        # -------------------------
        data = {
            "total_users": len(user_data),
            "users": user_data,
            "total_vendors": len(vendor_data),
            "vendors": vendor_data
        }

        return Response(data, status=200)

    




# vendor/views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from authentication.permissions import IsAdmin
from .models import Campaign, Redemption

class CampaignRedemptionReportView(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]

    def get(self, request):
        campaigns = Campaign.objects.select_related('vendor').all()

        report = []
        for campaign in campaigns:
            redemptions = Redemption.objects.filter(campaign=campaign)
            redeemed_ids = [r.aliffited_id for r in redemptions if r.status == 'redeemed']
            pending_ids = [r.aliffited_id or "Pending" for r in redemptions if r.status == 'pending']

            report.append({
                "campaign_id": campaign.id,
                "campaign_name": campaign.name,
                "shop_name": campaign.vendor.shop_name,
                "vendor_name": campaign.vendor.vendor_name,
                "reward_name": campaign.reward_name,
                "required_visits": campaign.required_visits,
                "total_redemptions": redemptions.count(),
                "redeemed_ids": redeemed_ids,
                "pending_ids": pending_ids
            })

        return Response({"campaign_report": report}, status=200)
