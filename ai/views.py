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

from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# shared requests session with retries
_session = None
def _get_session():
    global _session
    if _session is None:
        s = requests.Session()
        retries = Retry(total=2, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504], allowed_methods=["HEAD","GET","POST"])
        s.mount("https://", HTTPAdapter(max_retries=retries))
        s.mount("http://", HTTPAdapter(max_retries=retries))
        _session = s
    return _session

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

BASE_AI_URL = "https://ai.trekbotai.com"  # API base (no /docs)

_ai_cache = {"online": None, "checked_at": 0}

def is_ai_online():
    """Check AI server quickly (30s cache)."""
    now = time.time()
    if _ai_cache["online"] is not None and (now - _ai_cache["checked_at"]) < 30:
        return _ai_cache["online"]
    try:
        s = _get_session()
        r = s.get(f"{BASE_AI_URL.rstrip('/')}/", timeout=3)
        online = r.status_code < 500
    except requests.RequestException:
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
    # Cache disabled
    return None

# ===============================
# ✅ AI API Call (Cache DISABLED)
# ===============================
def call_ai_api(endpoint, payload, token, timeout=100):
    """POST to AI server with retries and robust error handling."""
    headers = {}
    if token:
        try:
            token_value = getattr(token, "key", None) or str(token)
        except Exception:
            token_value = str(token)
        if token_value:
            headers["Authorization"] = f"Bearer {token_value}"
    url = f"{BASE_AI_URL.rstrip('/')}/{endpoint.lstrip('/')}"
    logger.info("AI CALL -> URL: %s, payload: %s", url, payload)
    try:
        s = _get_session()
        r = s.post(url, json=payload, headers=headers, timeout=timeout)
        text = r.text or ""
        # try parse JSON, otherwise return reasonable raw_text
        try:
            data = r.json() if r.content else {}
        except Exception as e:
            logger.debug("AI response parse error: %s", e)
            data = {"raw_text": text[:2000]}

        # If upstream returned HTML 5xx (gateway/timeouts) convert to structured error
        if r.status_code >= 500:
            return {"error": f"AI server returned {r.status_code}", "raw_text": text[:2000]}, r.status_code

        return data, r.status_code
    except requests.Timeout:
        logger.warning("AI request timed out")
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
    ALLOWED_CATEGORIES = ["place", "restaurant", "beverage", "lodging", "activities", "itinerary"]

    def post(self, request):
        user_lat, user_lng = get_user_location(request)
        if not user_lat or not user_lng:
            return Response({"success": False, "message": "Location not found. Please update your profile."}, status=400)

        category = request.data.get("category", "").lower().strip()
        user_input = request.data.get("user_input", "")

        if category not in self.ALLOWED_CATEGORIES:
            return Response({
                "success": False,
                "message": f"Allowed categories: {', '.join(self.ALLOWED_CATEGORIES)}"
            }, status=400)

        # ============================================================
        # 🔥 SPECIAL HANDLING FOR ITINERARY (DIRECT AI RESPONSE)
        # ============================================================
        if category == "itinerary":
            if not is_ai_online():
                return Response({"success": False, "message": "AI server is offline, please try again later."}, status=503)
            
            payload = {
                "category": category,
                "latitude": user_lat,
                "longitude": user_lng,
                "user_input": user_input
            }

            data, code = call_ai_api("/get_location", payload, request.auth, timeout=120)

            if code == 200:
                return Response({
                    "success": True,
                    "category": category,
                    "itinerary_data": data
                }, status=200)
            else:
                return Response({
                    "success": False, 
                    "message": "AI Itinerary জেনারেট করতে ব্যর্থ হয়েছে।",
                    "error_details": data
                }, status=code)

        # ============================================================
        # ⬇️ EXISTING LOGIC FOR OTHER VENDORS (Restaurant, Place, etc.)
        # ============================================================
        
        vendors_list = []

        # ✅ DB vendors
        db_vendors = Vendor.objects.filter(
            is_profile_complete=True,
            latitude__isnull=False,
            longitude__isnull=False,
            category__iexact=category
        ).select_related('user')

        for vendor in db_vendors:
            distance = haversine_distance(user_lat, user_lng, vendor.latitude, vendor.longitude)
            if distance <= 5000:
                # ✅ thumbnail_image বের করা
                thumbnail_url = None
                if hasattr(vendor, 'thumbnail_image') and vendor.thumbnail_image:
                    try:
                        thumbnail_url = request.build_absolute_uri(vendor.thumbnail_image.url)
                    except Exception:
                        thumbnail_url = None

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
                    "thumbnail_image": thumbnail_url,
                    "shop_images": vendor.shop_images or [],
                    "distance_meters": round(distance, 1),
                    "location": {"latitude": float(vendor.latitude), "longitude": float(vendor.longitude)},
                    "source": "db"
                })

        # ✅ AI vendors
        ai_info = {"status": "skipped"}
        ai_city_history = None

        if is_ai_online():
            try:
                payload = {"category": category, "latitude": user_lat, "longitude": user_lng, "user_input": user_input}
                data, code = call_ai_api("/get_location", payload, request.auth, timeout=100)
                
                if code == 200 and data and isinstance(data, dict):
                    ai_items = data.get(CATEGORY_KEY_MAP.get(category, category), [])
                    ai_info = {"status": "success", "count": len(ai_items)}
                    ai_city_history = data.get("cityHistory") or data.get("city_history")
                    
                    for ai in ai_items:
                        ai_id = ai.get("id") or str(uuid.uuid4())
                        ai_photos = [p.get("photo_url") for p in ai.get("photos", []) if p.get("photo_url")]

                        ai_payload = {
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
                            "thumbnail_image": ai_photos[0] if ai_photos else None,
                            "shop_images": ai_photos,
                            "distance_meters": round(float(ai.get("distance_km", 0)) * 1000, 1),
                            "location": {
                                "latitude": ai.get("location", {}).get("lat", 0),
                                "longitude": ai.get("location", {}).get("lng", 0)
                            },
                            "source": "ai"
                        }

                        _cache_ai_vendor(ai_id, ai_payload)

                        vendors_list.append(ai_payload)
                else:
                    ai_info = {"status": "error", "message": data.get("error", "Unknown")}
            except Exception as e:
                ai_info = {"status": "error", "message": str(e)}
        else:
            ai_info = {"status": "offline"}

        # ✅ Sort
        vendors_list.sort(key=lambda x: (0 if x.get("source") == "db" else 1, x.get("distance_meters", 1e9)))

        response_payload = {
            "success": True,
            "your_location": {"lat": user_lat, "lng": user_lng},
            "search_radius_meters": 5000,
            "category": category,
            "total_found": len(vendors_list),
            **({"cityHistory": ai_city_history} if category == "place" and ai_city_history else {}),
            "vendors": vendors_list,
            "ai_server": ai_info
        }

        return Response(response_payload, status=200)


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
            return Response({"success": False, "message": "message required"}, status=400)

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
            return Response({"success": False, "message": "message required"}, status=400)

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
        # resolve token (request.auth, Authorization header, or access_token in body)
        token = getattr(request, "auth", None)
        if not token:
            auth_hdr = request.headers.get("Authorization") or request.data.get("access_token")
            if auth_hdr:
                v = auth_hdr.strip()
                token = v.split(" ", 1)[1].strip() if v.lower().startswith("bearer ") else v

        # resolve coordinates: user profile first, then request body
        user_lat, user_lng = get_user_location(request)
        if user_lat is None or user_lng is None:
            try:
                body_lat = request.data.get("latitude")
                body_lng = request.data.get("longitude")
                if body_lat is not None and body_lng is not None:
                    user_lat, user_lng = float(body_lat), float(body_lng)
            except Exception:
                user_lat, user_lng = None, None

        if user_lat is None or user_lng is None:
            return Response({"success": False, "message": "Location could not be found. Provide latitude & longitude or update profile."}, status=400)

        message = (request.data.get("message") or "").strip()
        preferences = request.data.get("preferences", {}) or {}
        if not message:
            return Response({"success": False, "message": "Message is required"}, status=400)

        # strong instruction to return ONLY structured JSON
        DEFAULT_ITINERARY_INSTRUCTION = (
            "Return ONLY valid JSON with top-level keys: 'destination','trip_overview','daily_itinerary',"
            "'additional_recommendations','packing_suggestions','best_photo_spots'. Do NOT ask follow-up questions."
        )
        prompt = f"{message}\n\n{DEFAULT_ITINERARY_INSTRUCTION}"

        final_payload = {
            "user_input": prompt,
            "latitude": user_lat,
            "longitude": user_lng,
            "preferences": preferences
        }

        ai_data, code = call_ai_api("/chat/itinerary", final_payload, token, timeout=120)

        # normalize AI response: accept dict result or parse raw_text
        import json
        def extract_structured(d):
            """Return dict with keys destination, trip_overview, daily_itinerary if present in d or nested 'data'"""
            if not isinstance(d, dict):
                return None
            # direct
            if {"destination", "trip_overview", "daily_itinerary"}.issubset(set(d.keys())):
                return d
            # nested under 'data'
            inner = d.get("data") if isinstance(d.get("data"), dict) else None
            if inner and {"destination", "trip_overview", "daily_itinerary"}.issubset(set(inner.keys())):
                return inner
            # if items + data pattern (items is day list, data has meta)
            if isinstance(d.get("items"), list) and inner:
                merged = dict(inner)
                merged["daily_itinerary"] = d.get("items")
                return merged
            return None

        # handle dict response
        if isinstance(ai_data, dict):
            structured = extract_structured(ai_data)
            if structured:
                destination_info = structured.get("destination", {})
                city_name = destination_info.get("city", "Destination")
                trip_days = structured.get("trip_overview", {}).get("duration_days", "N/A")
                daily_itinerary = structured.get("daily_itinerary", [])
                formatted_response = {
                    "status": "success",
                    "category": "itinerary",
                    "reply": f"Here's your personalized {trip_days}-day itinerary for {city_name}!",
                    "count": len(daily_itinerary),
                    "items": daily_itinerary,
                    "data": ai_data.get("data") or structured or ai_data
                }
                return Response(formatted_response, status=200)
            # try parsing raw text fields
            raw = ai_data.get("raw_text") or ai_data.get("raw") or ai_data.get("text")
            if isinstance(raw, str):
                try:
                    parsed = json.loads(raw)
                    return Response(parsed, status=200)
                except Exception:
                    return Response({"success": False, "message": "AI returned non-JSON itinerary", "raw": raw}, status=502)
        # handle string response
        if isinstance(ai_data, str):
            try:
                parsed = json.loads(ai_data)
                structured = extract_structured(parsed)
                if structured:
                    destination_info = structured.get("destination", {})
                    city_name = destination_info.get("city", "Destination")
                    trip_days = structured.get("trip_overview", {}).get("duration_days", "N/A")
                    daily_itinerary = structured.get("daily_itinerary", [])
                    return Response({
                        "status": "success",
                        "category": "itinerary",
                        "reply": f"Here's your personalized {trip_days}-day itinerary for {city_name}!",
                        "count": len(daily_itinerary),
                        "items": daily_itinerary,
                        "data": parsed
                    }, status=200)
                return Response(parsed, status=200)
            except Exception:
                return Response({"success": False, "message": "AI returned non-JSON text", "raw": ai_data}, status=502)

        return Response({"success": False, "message": "Invalid AI response", "raw": ai_data}, status=502)

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
        # ✅ thumbnail_image বের করা
        thumbnail_url = None
        if hasattr(v, 'thumbnail_image') and v.thumbnail_image:
            try:
                thumbnail_url = v.thumbnail_image.url
            except Exception:
                thumbnail_url = None
        return {
            "id": str(v.id),
            "shop_name": v.shop_name or "name not available",
            "vendor_name": v.vendor_name or "unknown",
            "category": getattr(v, 'category', 'unknown'),
            "rating": float(v.rating) if v.rating else 0.0,
            "review_count": getattr(v, 'review_count', 0),
            "thumbnail_image": thumbnail_url,
            "shop_image": v.shop_images[0] if v.shop_images else None,
            "shop_images": v.shop_images or [],
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
        ai_images = data.get("shop_images", [])
        return {
            "id": fav.ai_vendor_id,
            "shop_name": data.get("shop_name", "AI shop"),
            "vendor_name": data.get("vendor_name", "unknown"),
            "category": data.get("category", "place"),
            "rating": data.get("rating", 0.0),
            "review_count": data.get("review_count", 0),
            "thumbnail_image": ai_images[0] if ai_images else None,
            "shop_image": ai_images[0] if ai_images else None,
            "shop_images": ai_images,
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

            ai_data = request.data.get("ai_vendor_data") or request.data.get("vendor") or {}
            if not ai_data:
                ai_data = cache.get(f"ai_vendor:{vendor_id}") or {}

            loc = ai_data.get("location") or {}
            lat = loc.get("latitude") or loc.get("lat") or ai_data.get("latitude") or ai_data.get("lat")
            lng = loc.get("longitude") or loc.get("lng") or ai_data.get("longitude") or ai_data.get("lng")
            if lat is None or lng is None:
                return Response({"success": False, "message": "ai_vendor_data not found in cache"}, status=400)

            ai_data["location"] = {"latitude": float(lat), "longitude": float(lng)}
            ai_data.setdefault("shop_images", [])
            ai_data.setdefault("thumbnail_image", ai_data["shop_images"][0] if ai_data["shop_images"] else None)

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
        max_distance_km = 5

        vendors = Vendor.objects.filter(
            campaigns__is_active=True,
            latitude__isnull=False,
            longitude__isnull=False
        ).distinct()

        vendor_list = []

        for v in vendors:
            distance = calculate_distance(user_lat, user_lng, v.latitude, v.longitude)
            if distance > max_distance_km:
                continue

            active_campaigns = v.campaigns.filter(is_active=True)
            campaigns_info = []
            for c in active_campaigns:
                img_url = None
                try:
                    if getattr(c, "image", None):
                        img_field = c.image
                        if hasattr(img_field, "url"):
                            img_url = request.build_absolute_uri(img_field.url)
                        else:
                            img_url = str(img_field)
                    elif getattr(c, "image_url", None):
                        raw = c.image_url
                        img_url = request.build_absolute_uri(raw) if not str(raw).startswith("http") else raw
                except Exception:
                    img_url = None

                campaigns_info.append({
                    "name": c.name,
                    "reward_name": c.reward_name,
                    "reward_description": c.reward_description,
                    "required_visits": c.required_visits,
                    "campaign_id": c.id,
                    "image_url": img_url
                })

            # ✅ thumbnail_image যোগ করা
            thumbnail_url = None
            if hasattr(v, 'thumbnail_image') and v.thumbnail_image:
                try:
                    thumbnail_url = request.build_absolute_uri(v.thumbnail_image.url)
                except Exception:
                    thumbnail_url = None

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
                "thumbnail_image": thumbnail_url,
                "shop_images": v.shop_images or [],
                "distance_km": round(distance, 2),
                "location": {"latitude": v.latitude, "longitude": v.longitude},
                "active_campaigns": campaigns_info,
                "active_campaign_images": [c.get("image_url") for c in campaigns_info if c.get("image_url")]
            })

        vendor_list.sort(key=lambda x: x['distance_km'])

        return Response({
            "success": True,
            "your_location": {"lat": user_lat, "lng": user_lng},
            "total_vendors": len(vendor_list),
            "vendors": vendor_list
        })

        #