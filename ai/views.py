import requests
import hashlib
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.throttling import UserRateThrottle
from django.core.cache import cache
from .permissions import IsUser
from authentication.models import Vendor
import math
import uuid
import time
import logging
logger = logging.getLogger(__name__)

# ===============================
# Haversine distance
# ===============================
def haversine_distance(lat1, lon1, lat2, lon2):
    R = 6371
    lat1, lon1, lat2, lon2 = map(float, [lat1, lon1, lat2, lon2])
    lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c * 1000

BASE_AI_URL = "http://3.19.225.124:8005"  # use API base, not /docs

_ai_cache = {"online": None, "checked_at": 0}

def is_ai_online():
    """AI সার্ভার অনলাইন কিনা চেক (30 সেকেন্ড cache)"""
    now = time.time()
    if _ai_cache["online"] is not None and (now - _ai_cache["checked_at"]) < 30:
        return _ai_cache["online"]
    
    try:
        r = requests.get(f"{BASE_AI_URL}/", timeout=2)
        online = r.status_code < 500
    except:
        online = False
    
    _ai_cache["online"] = online
    _ai_cache["checked_at"] = now
    return online

def get_user_location(request):
    try:
        profile = request.user.profile
        lat = getattr(profile, "latitude", None)
        lng = getattr(profile, "longitude", None)
        if lat is None or lng is None:
            return None, None
        return float(lat), float(lng)
    except:
        return None, None

# ===============================
# ✅ Cache Key Generator (FIXED)
# ===============================
def get_cache_key(endpoint, payload):
    """Location + category + user_input ভিত্তিক cache key (100m precision)"""
    lat = round(payload.get('latitude', 0), 3)  # 0.001° ≈ 111m
    lng = round(payload.get('longitude', 0), 3)
    category = payload.get('category', '')
    user_input = payload.get('user_input', '')[:50]  # first 50 chars
    
    key_str = f"{endpoint}:{category}:{user_input}:{lat}:{lng}"
    return f"ai:{hashlib.md5(key_str.encode()).hexdigest()}"

# ===============================
# ✅ AI API Call with Cache (10 min)
# ===============================
def call_ai_api(endpoint, payload, token, timeout=100):
    """AI সার্ভারে POST request with 10 min cache"""
    cache_key = get_cache_key(endpoint, payload)
    cached = cache.get(cache_key)
    if cached:
        return cached, 200
    try:
        headers = {}
        if token:
            try:
                token_value = getattr(token, 'key', None) or str(token)
            except Exception:
                token_value = str(token)
            if token_value:
                headers["Authorization"] = f"Bearer {token_value}"
        url = f"{BASE_AI_URL.rstrip('/')}/{endpoint.lstrip('/')}"
        logger.info("AI CALL -> URL: %s, payload: %s", url, payload)
        r = requests.post(url, json=payload, headers=headers, timeout=timeout)
        try:
            data = r.json() if r.content else {}
        except Exception as e:
            logger.error("AI response parse error: %s ; text: %s", e, r.text)
            data = {"raw_text": r.text}
        
        if 200 <= r.status_code < 300 and data:
            cache.set(cache_key, data, timeout=600)
        
        return data, r.status_code
    except requests.Timeout:
        return {"error": "AI server timeout"}, 504
    except requests.ConnectionError:
        logger.warning("AI server connection error")
        return {"error": "AI server offline"}, 503
    except Exception as e:
        logger.exception("call_ai_api unexpected error")
        return {"error": str(e)}, 500

CATEGORY_KEY_MAP = {
    "place": "places",
    "restaurant": "restaurants",
    "beverage": "beverages",
    "lodging": "lodging",
    "activities": "activities",
}

# ===============================
# Throttle for AI requests
# ===============================
class AIThrottle(UserRateThrottle):
    rate = '15/minute'

# ===============================
# ✅ Category Nearby API (OPTIMIZED)
# ===============================
class CategoryNearbyAI(APIView):
    permission_classes = [IsUser]
    throttle_classes = [AIThrottle]
    ALLOWED_CATEGORIES = ["place", "restaurant", "beverage", "lodging", "activities"]

    def post(self, request):
        user_lat, user_lng = get_user_location(request)
        if not user_lat or not user_lng:
            return Response({"success": False, "message": "লোকেশন পাওয়া যায়নি। প্রোফাইল আপডেট করুন।"}, status=400)

        category = request.data.get("category", "").lower().strip()
        if category not in self.ALLOWED_CATEGORIES:
            return Response({
                "success": False,
                "message": f"Allowed categories: {', '.join(self.ALLOWED_CATEGORIES)}"
            }, status=400)

        vendors_list = []

        # ✅ DB vendors (always fresh)
        db_vendors = Vendor.objects.filter(
            is_profile_complete=True,
            latitude__isnull=False,
            longitude__isnull=False,
            category__iexact=category
        ).select_related('user')

        for vendor in db_vendors:
            distance = haversine_distance(user_lat, user_lng, vendor.latitude, vendor.longitude)
            if distance <= 5000:
                vendors_list.append({
                    "id": vendor.id,
                    "vendor_name": vendor.vendor_name or "N/A",
                    "shop_name": vendor.shop_name or "N/A",
                    "phone_number": vendor.phone_number or "N/A",
                    "email": vendor.user.email if vendor.user else "N/A",
                    "shop_address": vendor.shop_address or "N/A",
                    "category": vendor.category or category,
                    "description": vendor.description or "",
                    "activities": vendor.activities or [],
                    "rating": float(vendor.rating) if vendor.rating else 0.0,
                    "review_count": vendor.review_count or 0,
                    "shop_images": vendor.shop_images or [],
                    "distance_meters": round(distance, 1),
                    "location": {"latitude": float(vendor.latitude), "longitude": float(vendor.longitude)},
                    "source": "db"
                })

        # ✅ AI vendors (cached 10 min)
        ai_info = {"status": "skipped"}

        if is_ai_online():
            try:
                payload = {"category": category, "latitude": user_lat, "longitude": user_lng}
                data, code = call_ai_api("/get_location", payload, request.auth, timeout=100)  # timeout 100 করা হলো
                
                if code == 200 and data and isinstance(data, dict):
                    ai_items = data.get(CATEGORY_KEY_MAP.get(category, category), [])
                    ai_info = {"status": "success", "count": len(ai_items)}
                    
                    for ai in ai_items:
                        ai_id = ai.get("id") or str(uuid.uuid4())
                        vendors_list.append({
                            "id": ai_id,
                            "vendor_name": ai.get("name") or "N/A",
                            "shop_name": ai.get("name") or "N/A",
                            "phone_number": ai.get("phone") or "Phone not available",
                            "email": "",
                            "shop_address": ai.get("address") or "No address available",
                            "category": category,
                            "description": ai.get("description") or "No description available",
                            "activities": ai.get("features", "").split(", ") if ai.get("features") else [],
                            "rating": float(str(ai.get("rating", "0")).split("/")[0]) if ai.get("rating") else 0.0,
                            "review_count": ai.get("total_reviews", 0),
                            "shop_images": [p.get("photo_url") for p in ai.get("photos", []) if p.get("photo_url")],
                            "distance_meters": round(float(ai.get("distance_km", 0)) * 1000, 1),
                            "location": {
                                "latitude": ai.get("location", {}).get("lat", 0),
                                "longitude": ai.get("location", {}).get("lng", 0)
                            },
                            "source": "ai"
                        })
                else:
                    ai_info = {"status": "error", "message": data.get("error", "Unknown")}
            except Exception as e:
                ai_info = {"status": "error", "message": str(e)}
        else:
            ai_info = {"status": "offline"}

        # ✅ Sort: DB first, then AI by distance
        vendors_list.sort(key=lambda x: (0 if x.get("source") == "db" else 1, x.get("distance_meters", 1e9)))

        return Response({
            "success": True,
            "your_location": {"lat": user_lat, "lng": user_lng},
            "search_radius_meters": 5000,
            "category": category,
            "total_found": len(vendors_list),
            "vendors": vendors_list,
            "ai_server": ai_info
        }, status=200)


# ===============================
# Chat APIs (all cached)
# ===============================
class ChatNormalAPI(APIView):
    permission_classes = [IsUser]
    throttle_classes = [AIThrottle]

    def post(self, request):
        token = request.auth
        user_lat, user_lng = get_user_location(request)
        if not user_lat or not user_lng:
            return Response({"success": False, "message": "location could not be found. Please update your profile."}, status=400)

        message = request.data.get("message")
        if not message:
            return Response({"success": False, "message": "message প্রয়োজন"}, status=400)

        final_payload = {"user_input": message, "latitude": user_lat, "longitude": user_lng}
        data, code = call_ai_api("/chat/normal", final_payload, token)
        return Response(data, status=code)


class ChatPlacesAPI(APIView):
    permission_classes = [IsUser]
    throttle_classes = [AIThrottle]

    def post(self, request):
        token = request.auth
        user_lat, user_lng = get_user_location(request)
        if not user_lat or not user_lng:
            return Response({"success": False, "message": "location could not be found."}, status=400)

        message = request.data.get("message")
        if not message:
            return Response({"success": False, "message": "message প্রয়োজন"}, status=400)

        final_payload = {"user_input": message, "latitude": user_lat, "longitude": user_lng}
        data, code = call_ai_api("/chat/places", final_payload, token)
        return Response(data, status=code)


class ChatRestaurantAPI(APIView):
    permission_classes = [IsUser]
    throttle_classes = [AIThrottle]

    def post(self, request):
        token = request.auth
        user_lat, user_lng = get_user_location(request)
        if not user_lat or not user_lng:
            return Response({"success": False, "message": "location could not be found."}, status=400)

        message = request.data.get("message")
        if not message:
            return Response({"success": False, "message": "message required"}, status=400)

        final_payload = {"user_input": message, "latitude": user_lat, "longitude": user_lng}
        data, code = call_ai_api("/chat/restaurant", final_payload, token)
        return Response(data, status=code)


class ChatBeverageAPI(APIView):
    permission_classes = [IsUser]
    throttle_classes = [AIThrottle]

    def post(self, request):
        token = request.auth
        user_lat, user_lng = get_user_location(request)
        if not user_lat or not user_lng:
            return Response({"success": False, "message": "location could not be found."}, status=400)

        message = request.data.get("message")
        if not message:
            return Response({"success": False, "message": "message required"}, status=400)

        final_payload = {"user_input": message, "latitude": user_lat, "longitude": user_lng}
        data, code = call_ai_api("/chat/beverage", final_payload, token)
        return Response(data, status=code)


class ChatLodgingAPI(APIView):
    permission_classes = [IsUser]
    throttle_classes = [AIThrottle]

    def post(self, request):
        token = request.auth
        user_lat, user_lng = get_user_location(request)
        if not user_lat or not user_lng:
            return Response({"success": False, "message": "location could not be found."}, status=400)

        message = request.data.get("message")
        if not message:
            return Response({"success": False, "message": "message required"}, status=400)

        final_payload = {"user_input": message, "latitude": user_lat, "longitude": user_lng}
        data, code = call_ai_api("/chat/lodging", final_payload, token)
        return Response(data, status=code)


class ChatActivitiesAPI(APIView):
    permission_classes = [IsUser]
    throttle_classes = [AIThrottle]

    def post(self, request):
        token = request.auth
        user_lat, user_lng = get_user_location(request)
        if not user_lat or not user_lng:
            return Response({"success": False, "message": "location could not be found."}, status=400)

        message = request.data.get("message")
        if not message:
            return Response({"success": False, "message": "message required"}, status=400)

        final_payload = {"user_input": message, "latitude": user_lat, "longitude": user_lng}
        data, code = call_ai_api("/chat/activities", final_payload, token)
        return Response(data, status=code)


class ChatItineraryAPI(APIView):
    permission_classes = [IsUser]
    throttle_classes = [AIThrottle]

    def post(self, request):
        token = request.auth
        user_lat, user_lng = get_user_location(request)
        if not user_lat or not user_lng:
            return Response({"success": False, "message": "location could not be found. Please update your profile."}, status=400)

        message = request.data.get("message")
        preferences = request.data.get("preferences", {})

        if not message:
            return Response({"success": False, "message": "message required"}, status=400)

        final_payload = {"user_input": message, "latitude": user_lat, "longitude": user_lng, "preferences": preferences}
        data, code = call_ai_api("/chat/itinerary", final_payload, token)
        return Response(data, status=code)


class GetLocationAPI(APIView):
    permission_classes = [IsUser]
    throttle_classes = [AIThrottle]

    def post(self, request):
        token = getattr(request, 'auth', None)
        user_lat, user_lng = get_user_location(request)

        if user_lat is None or user_lng is None:
            return Response({"success": False, "message": "location could not be found. Please update your profile."}, status=status.HTTP_400_BAD_REQUEST)

        category = request.data.get("category")
        if not category:
            return Response({"success": False, "message": "category required"}, status=status.HTTP_400_BAD_REQUEST)

        payload = {"category": category, "latitude": user_lat, "longitude": user_lng}
        data, code = call_ai_api("/get_location", payload, token)
        return Response(data, status=code)


import math
from uuid import UUID
from datetime import timedelta
from django.utils import timezone
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

from authentication.models import Vendor, FavoriteVendor, Profile

# ============================
# Haversine distance function
# ============================
def calculate_distance(lat1, lon1, lat2, lon2):
    """Returns distance in kilometers using Haversine formula"""
    R = 6371  # Earth radius in KM
    lat1, lon1, lat2, lon2 = map(float, [lat1, lon1, lat2, lon2])
    d_lat = math.radians(lat2 - lat1)
    d_lon = math.radians(lon2 - lon1)
    a = (math.sin(d_lat / 2) ** 2 +
         math.cos(math.radians(lat1)) *
         math.cos(math.radians(lat2)) *
         math.sin(d_lon / 2) ** 2)
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c

# ============================
# Helper to extract vendor info
# ============================
def get_vendor_info(fav):
    if fav.vendor:
        v = fav.vendor
        if not v.latitude or not v.longitude:
            return None
        return {
            "id": str(v.id),
            "shop_name": v.shop_name or "name not available",
            "vendor_name": v.vendor_name or "unknown",
            "category": getattr(v, 'category', 'unknown'),
            "rating": float(v.rating) if v.rating else 0.0,
            "review_count": getattr(v, 'review_count', 0),
            "shop_image": v.shop_images[0] if v.shop_images else None,
            "phone": v.phone_number or "phone not available",
            "latitude": float(v.latitude),
            "longitude": float(v.longitude),
            "is_ai_vendor": False,
            "has_full_data": True
        }
    elif fav.ai_vendor_id and fav.ai_vendor_data:
        data = fav.ai_vendor_data
        location = data.get("location", {})
        lat, lng = location.get("latitude"), location.get("longitude")
        if lat is None or lng is None:
            return None
        return {
            "id": fav.ai_vendor_id,
            "shop_name": data.get("shop_name", "AI shop"),
            "vendor_name": data.get("vendor_name", "unknown"),
            "category": data.get("category", "place"),
            "rating": data.get("rating", 0.0),
            "review_count": data.get("review_count", 0),
            "shop_image": data.get("shop_images", [None])[0],
            "phone": data.get("phone_number", "phone not available"),
            "latitude": float(lat),
            "longitude": float(lng),
            "is_ai_vendor": True,
            "has_full_data": bool(data)
        }
    return None
# Toggle Favorite Vendor
class ToggleFavoriteVendor(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        vendor_id = request.data.get('vendor_id')
        if not vendor_id:
            return Response({"success": False, "message": "vendor_id required"}, status=400)

        user = request.user
        # AI vendor check
        try:
            UUID(str(vendor_id))
            is_ai = True
        except ValueError:
            is_ai = False

        if is_ai:
            favorite = FavoriteVendor.objects.filter(user=user, ai_vendor_id=str(vendor_id)).first()
            if favorite:
                vendor_data = favorite.ai_vendor_data
                favorite.delete()
                return Response({"success": True, "message": "Removed from favorites", "is_favorite": False, "vendor": vendor_data})

            ai_data = request.data.get("ai_vendor_data", {})
            favorite = FavoriteVendor.objects.create(
                user=user,
                ai_vendor_id=str(vendor_id),
                expiry_date=timezone.now() + timedelta(days=7),
                ai_vendor_data=ai_data
            )
            return Response({"success": True, "message": "Added to favorites (for 7 days)", "is_favorite": True, "vendor": ai_data})
        else:
            try:
                vendor = Vendor.objects.get(id=vendor_id)
            except Vendor.DoesNotExist:
                return Response({"success": False, "message": "Vendor not found"}, status=404)

            favorite = FavoriteVendor.objects.filter(user=user, vendor=vendor).first()
            if favorite:
                favorite.delete()
                return Response({"success": True, "message": "Removed from favorites", "is_favorite": False, "vendor": None})

            favorite = FavoriteVendor.objects.create(user=user, vendor=vendor)
            vendor_data = get_vendor_info(favorite)  # fresh instance
            return Response({"success": True, "message": "Added to favorites", "is_favorite": True, "vendor": vendor_data})
# My Favorite Vendors
class MyFavoriteVendorsAPI(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        profile = getattr(request.user, "profile", None)
        if not profile or not profile.latitude or not profile.longitude:
            return Response({"success": False, "message": "Your profile does not have location information. Please update it."}, status=400)

        user_lat, user_lng = profile.latitude, profile.longitude
        now = timezone.now()
        favorites = FavoriteVendor.objects.filter(user=request.user).select_related('vendor')
        vendor_list = []

        for fav in favorites:
            if fav.ai_vendor_id and fav.expiry_date and fav.expiry_date < now:
                continue

            info = get_vendor_info(fav)
            if not info:
                continue

            distance_km = calculate_distance(user_lat, user_lng, info['latitude'], info['longitude'])
            if distance_km > 5:  # 5 KM radius
                continue

            info.update({
                "distance": {"kilometer": round(distance_km, 2), "meter": int(distance_km * 1000)},
                "added_at": fav.created_at.strftime("%d %b %Y")
            })
            vendor_list.append(info)

        return Response({"success": True, "total_favorites_within_5km": len(vendor_list), "my_favorites": vendor_list})




from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone
from authentication.models import Vendor
from vendor.models import Campaign
import math

# Haversine distance
def calculate_distance(lat1, lon1, lat2, lon2):
    R = 6371
    lat1, lon1, lat2, lon2 = map(float, [lat1, lon1, lat2, lon2])
    d_lat = math.radians(lat2 - lat1)
    d_lon = math.radians(lon2 - lon1)
    a = math.sin(d_lat/2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(d_lon/2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
    return R * c  # KM

class NearbyCampaignVendorsAPI(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        profile = getattr(request.user, "profile", None)
        if not profile or not profile.latitude or not profile.longitude:
            return Response({"success": False, "message": "Your profile does not have location information. Please update it."}, status=400)
        
        user_lat, user_lng = profile.latitude, profile.longitude
        max_distance_km = 5  # প্রয়োজনমতো পরিবর্তন করা যাবে

        # Active campaign vendors
        vendors = Vendor.objects.filter(
            campaigns__is_active=True,  # Campaign relation থেকে filter
            latitude__isnull=False,
            longitude__isnull=False
        ).distinct()  # Duplicate vendors দূর করার জন্য

        vendor_list = []

        for v in vendors:
            distance = calculate_distance(user_lat, user_lng, v.latitude, v.longitude)
            if distance > max_distance_km:
                continue

            # Active campaigns নিয়ে আসা
            active_campaigns = v.campaigns.filter(is_active=True)
            campaigns_info = [
                {
                    "name": c.name,
                    "reward_name": c.reward_name,
                    "reward_description": c.reward_description,
                    "required_visits": c.required_visits,
                    "campaign_id": c.id
                } for c in active_campaigns
            ]

            vendor_list.append({
                "id": v.id,
                "vendor_name": v.vendor_name or "N/A",
                "shop_name": v.shop_name or "N/A",
                "phone_number": v.phone_number or "N/A",
                "email": v.user.email if hasattr(v, 'user') and v.user else "N/A",
                "shop_address": v.shop_address or "N/A",
                "category": v.category or "N/A",
                "description": v.description or "",
                "activities": v.activities or [],
                "rating": float(v.rating) if v.rating else 0.0,
                "review_count": v.review_count or 0,
                "shop_images": v.shop_images or [],
                "distance_km": round(distance, 2),
                "location": {"latitude": v.latitude, "longitude": v.longitude},
                "active_campaigns": campaigns_info
            })

        # Distance অনুযায়ী sort
        vendor_list.sort(key=lambda x: x['distance_km'])

        return Response({
            "success": True,
            "your_location": {"lat": user_lat, "lng": user_lng},
            "total_vendors": len(vendor_list),
            "vendors": vendor_list
        })