from rest_framework.decorators import api_view, permission_classes, parser_classes
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status

from django.utils import timezone
from datetime import timedelta
from math import radians, sin, cos, sqrt, atan2
from django.db.models import Count, Q
from django.shortcuts import get_object_or_404
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
import os
import uuid

from authentication.models import Vendor
from .models import Campaign, Visitor, Visit, Redemption
from .utils import generate_aliffited_id

# vendor/views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from authentication.permissions import IsAdmin
from .models import Campaign, Redemption

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.db.models import Count
from .models import Visitor, Campaign, Redemption

# vendor/views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from authentication.permissions import IsAdmin  # ← এখান থেকে ইমপোর্ট করুন
from authentication.models import User, Vendor
from .models import Campaign, Redemption

    

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from authentication.permissions import IsAdmin
from authentication.models import User, Vendor
from .models import Campaign, Redemption, Visitor, Visit
from django.db.models import Q


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def dashboard_overview(request):
    vendor = getattr(request.user, "vendor_profile", None)
    if not vendor:
        return Response({"error": "Vendor profile not found"}, status=403)

    return Response({
        "total_visitor": Visitor.objects.filter(vendor=vendor).count(),
        "active_campaign": Campaign.objects.filter(vendor=vendor, is_active=True).count(),
        "deactivate_campaign": Campaign.objects.filter(vendor=vendor, is_active=False).count(),
        "pending_rewards": Redemption.objects.filter(
            campaign__vendor=vendor, status='pending'
        ).count(),
        "redeemed_rewards": Redemption.objects.filter(
            campaign__vendor=vendor, status='redeemed'
        ).count()
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_management(request):
    vendor = getattr(request.user, "vendor_profile", None)
    if not vendor:
        return Response({"error": "Vendor profile not found"}, status=403)

    try:
        # প্রতিটি visitor এর আসল visit সংখ্যা
        visitors = Visitor.objects.filter(vendor=vendor).annotate(visit_count=Count('visits'))

        # active campaigns
        active_campaigns = Campaign.objects.filter(vendor=vendor, is_active=True)

        # =========================
        # active campaigns (reuse)
        # =========================
        active_campaigns = list(active_campaigns)  # force evaluation

        # একবারে সব redeemed counts নিয়ে ম্যাপ বানানো (visitor_id, campaign_id) -> count
        redemption_qs = Redemption.objects.filter(
            visitor__in=visitors,
            campaign__in=active_campaigns,
            status='redeemed'
        ).values('visitor_id', 'campaign_id').annotate(cnt=Count('id'))

        redemption_map = {
            (r['visitor_id'], r['campaign_id']): r['cnt'] for r in redemption_qs
        }

        data = []

        for visitor in visitors:
            visitor_name = visitor.name or visitor.phone or "Anonymous"

            for campaign in active_campaigns:
                redemption_count = redemption_map.get((visitor.id, campaign.id), 0)

                # Eligible check
                eligible = visitor.visit_count >= (campaign.required_visits or 0)

                # Reward name safe access
                reward_name = getattr(campaign, 'reward_name', None)

                data.append({
                    "visitor_id": visitor.id,
                    "visitor_name": visitor_name,
                    "user_id": visitor.user.id if getattr(visitor, 'user', None) else None,
                    "campaign_id": campaign.id,
                    "campaign_name": getattr(campaign, 'name', None),
                    "reward_name": reward_name,
                    "required_visits": getattr(campaign, 'required_visits', 0),
                    "total_visits": visitor.visit_count,
                    "redeemed_times": redemption_count,
                    "eligible": eligible
                })

        return Response({
            "vendor": getattr(vendor, 'shop_name', 'Unknown Vendor'),
            "total_visitors": visitors.count(),
            "data": data
        }, status=200)

    except Exception as e:
        # কোনো unexpected error হলে
        return Response({"error": str(e)}, status=500)




@api_view(['GET'])
@permission_classes([IsAuthenticated])
def campaign_list(request):
    vendor = getattr(request.user, "vendor_profile", None)
    if not vendor:
        return Response({"error": "Vendor profile not found"}, status=403)

    qs = Campaign.objects.filter(vendor=vendor).annotate(
        redemption_number=Count(
            'redemptions',
            filter=Q(redemptions__status='redeemed')
        ),
        pending_number=Count(
            'redemptions',
            filter=Q(redemptions__status='pending')
        ),
        total_redemptions=Count('redemptions')
    )

    campaigns = []
    for c in qs:
        campaigns.append({
            'id': c.id,
            'name': c.name,
            'reward_name': c.reward_name,
            'required_visits': c.required_visits,
            'reward_description': c.reward_description,
            'is_active': c.is_active,
            'created_at': c.created_at,
            'redemption_number': getattr(c, 'redemption_number', 0),
            'pending_number': getattr(c, 'pending_number', 0),
            'total_redemptions': getattr(c, 'total_redemptions', 0),
            'image_url': request.build_absolute_uri(c.image.url) if getattr(c, 'image', None) else None
        })

    return Response({"campaigns": campaigns})


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
        'campaign__name',
        'campaign__reward_name',
        'status',
        'aliffited_id',
        'redeemed_at'
    )

    return Response({"history": list(history)})



@api_view(['POST'])
@permission_classes([IsAuthenticated])
def redeem_once(request, redemption_id):
    vendor = getattr(request.user, "vendor_profile", None)
    if not vendor:
        return Response(
            {"error": "Vendor profile not found"},
            status=status.HTTP_403_FORBIDDEN
        )

    redemption = get_object_or_404(
        Redemption,
        id=redemption_id,
        campaign__vendor=vendor
    )

    if redemption.status == 'redeemed':
        return Response(
            {"error": "Reward already redeemed"},
            status=status.HTTP_400_BAD_REQUEST
        )

    redemption.status = 'redeemed'
    redemption.redeemed_at = timezone.now()
    redemption.save()

    return Response({
        "id": redemption.id,
        "visitor_name": redemption.visitor.name,
        "campaign_name": redemption.campaign.name,
        "status": redemption.status,
        "aliffited_id": redemption.aliffited_id,
        "redeemed_at": redemption.redeemed_at
    }, status=status.HTTP_200_OK)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
@parser_classes([MultiPartParser, FormParser])
def create_campaign(request):
    vendor = getattr(request.user, "vendor_profile", None)
    if not vendor:
        return Response({"error": "Vendor profile not found"}, status=403)

    # normalize required_visits
    rv = request.data.get('required_visits', 5)
    try:
        required_visits = int(rv)
    except Exception:
        required_visits = 5

    # normalize is_active (accept boolean or common strings)
    is_active_raw = request.data.get('is_active', True)
    if isinstance(is_active_raw, str):
        is_active = is_active_raw.strip().lower() in ('true', '1', 'yes', 'on')
    else:
        is_active = bool(is_active_raw)

    campaign = Campaign.objects.create(
        vendor=vendor,
        name=request.data.get('name'),
        required_visits=required_visits,
        reward_name=request.data.get('reward_name'),
        reward_description=request.data.get('reward_description', ''),
        is_active=is_active
    )

    # save uploaded image to Campaign.image if provided (key: 'image')
    if 'image' in request.FILES and request.FILES['image']:
        f = request.FILES['image']
        filename = f"{uuid.uuid4().hex}{os.path.splitext(f.name)[1]}"
        campaign.image.save(filename, ContentFile(f.read()), save=True)

    resp = {"message": "Campaign created", "id": campaign.id}
    if campaign.image:
        resp['image_url'] = request.build_absolute_uri(campaign.image.url)

    return Response(resp, status=status.HTTP_201_CREATED)

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



class UserAndVendorListView(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]

    def get(self, request):
        search = request.query_params.get('search', '').strip()

        # =========================
        # USERS QUERY
        # =========================
        users_qs = User.objects.filter(role='user')
        if search:
            users_qs = users_qs.filter(
                Q(email__icontains=search) |
                Q(full_name__icontains=search)
            )

        users = users_qs.values(
            'id', 'email', 'full_name',
            'role', 'is_active', 'created_at'
        ).order_by('-created_at')

        user_ids = [u['id'] for u in users]

        # =========================
        # VISITS MAPPING
        # =========================
        visits = Visit.objects.filter(visitor__user__id__in=user_ids)

        visits_count_map = {}
        visited_vendors_map = {}

        for visit in visits:
            if not visit.visitor or not visit.visitor.user:
                continue

            uid = visit.visitor.user.id
            visits_count_map[uid] = visits_count_map.get(uid, 0) + 1

            if uid not in visited_vendors_map:
                visited_vendors_map[uid] = set()

            if visit.vendor:
                visited_vendors_map[uid].add(visit.vendor.id)

        # =========================
        # REDEMPTIONS (ALFF IDs)
        # =========================
        redemptions = Redemption.objects.filter(
            visitor__user__id__in=user_ids,
            status='redeemed'
        )

        aliffited_map = {}
        for r in redemptions:
            if not r.visitor or not r.visitor.user:
                continue

            uid = r.visitor.user.id
            aliffited_map.setdefault(uid, [])

            if r.aliffited_id:
                aliffited_map[uid].append(r.aliffited_id)

        # =========================
        # VISITS MAPPING (already computed উপরে)
        # =========================
        # visited_vendors_map built earlier: user_id -> set(vendor_id)

        # একবারে সব vendor-এর active campaigns নিয়ে ম্যাপ বানানো
        vendor_ids_for_campaigns = set()
        for s in visited_vendors_map.values():
            vendor_ids_for_campaigns.update(s)

        active_campaigns_by_vendor = {}
        if vendor_ids_for_campaigns:
            qs_campaigns = Campaign.objects.filter(
                vendor__id__in=vendor_ids_for_campaigns,
                is_active=True
            ).values('vendor_id', 'name')

            for c in qs_campaigns:
                active_campaigns_by_vendor.setdefault(c['vendor_id'], []).append(c['name'])

        # =========================
        # USER DATA
        # =========================
        user_data = []
        for u in users:
            uid = u['id']
            visited_vendors = visited_vendors_map.get(uid, set())

            # vendor-wise campaigns -> flatten to unique list
            user_active_campaigns = []
            for vid in visited_vendors:
                user_active_campaigns.extend(active_campaigns_by_vendor.get(vid, []))

            user_data.append({
                **u,
                "total_visits": visits_count_map.get(uid, 0),
                "active_campaigns": list(dict.fromkeys(user_active_campaigns)),  # unique preserve order
                "aliffited_ids": aliffited_map.get(uid, []),
                "total_aliffited_ids": len(aliffited_map.get(uid, []))
            })

        # =========================
        # VENDORS QUERY
        # =========================
        vendors_qs = Vendor.objects.select_related('user')
        if search:
            vendors_qs = vendors_qs.filter(
                Q(user__email__icontains=search) |
                Q(shop_name__icontains=search) |
                Q(vendor_name__icontains=search)
            )

        vendors = vendors_qs.values(
            'id',                # ✅ Vendor ID
            'user__id',
            'user__email',
            'shop_name',
            'vendor_name',
            'phone_number',
            'is_profile_complete',
        )

        # =========================
        # VENDOR DATA (FIXED)
        # =========================
        vendor_data = []
        for v in vendors:
            vendor_id = v['id']   # ✅ CORRECT ID

            total_visits = Visit.objects.filter(
                vendor__id=vendor_id
            ).count()

            has_active_campaign = Campaign.objects.filter(
                vendor__id=vendor_id,
                is_active=True
            ).exists()

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

        # =========================
        # FINAL RESPONSE
        # =========================
        return Response({
            "total_users": len(user_data),
            "users": user_data,
            "total_vendors": len(vendor_data),
            "vendors": vendor_data
        }, status=200)



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
                "pending_ids": pending_ids,
                "image_url": request.build_absolute_uri(campaign.image.url) if getattr(campaign, 'image', None) else None
            })

        return Response({"campaign_report": report}, status=200)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def my_referral_list(request):
    """
    ভেন্ডর ড্যাশবোর্ড — আমার রেফারেল কোড ব্যবহার করে কারা একাউন্ট খুলেছে তাদের লিস্ট।
    """
    user = request.user

    # নিজের referral code
    my_code = user.referral_code
    if not my_code:
        return Response({
            "success": False,
            "message": "আপনার কোনো রেফারেল কোড নেই।"
        }, status=400)

    # যারা আমার referral code ব্যবহার করে একাউন্ট খুলেছে
    referred_users = User.objects.filter(referred_by=user).order_by('-created_at')

    referred_list = []
    for ru in referred_users:
        # এই referred user কি এই vendor এর দোকানে visit করেছে?
        vendor = getattr(request.user, "vendor_profile", None)
        total_visits = 0
        total_spent = None

        if vendor:
            total_visits = Visit.objects.filter(
                visitor__user=ru,
                vendor=vendor
            ).count()

        referred_list.append({
            "user_id": ru.id,
            "full_name": ru.full_name or "N/A",
            "email": ru.email,
            "phone": getattr(ru, 'phone', None) or "N/A",
            "joined_at": ru.created_at.strftime("%d %b %Y, %I:%M %p") if hasattr(ru, 'created_at') and ru.created_at else "N/A",
            "role": ru.role,
            "is_active": ru.is_active,
            "visits_to_my_shop": total_visits,
        })

    return Response({
        "success": True,
        "my_referral_code": my_code,
        "total_referred": len(referred_list),
        "referred_users": referred_list
    }, status=200)
