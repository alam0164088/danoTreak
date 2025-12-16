


import requests
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .permissions import IsUser  # তোমার permission ফাইল থেকে import কর
from authentication.models import Vendor
import math

# ===============================
# Haversine distance (DB vendors distance গণনার জন্য)
# ===============================
def haversine_distance(lat1, lon1, lat2, lon2):
    R = 6371  # পৃথিবীর ব্যাসার্ধ (কিমি)
    lat1, lon1, lat2, lon2 = map(float, [lat1, lon1, lat2, lon2])
    lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c * 1000  # মিটারে কনভার্ট

# ===============================
# AI সার্ভার URL
# ===============================
BASE_AI_URL = "http://10.10.7.82:8005"

# ===============================
# Helper: Get user location
# ===============================
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
# Helper: Call AI API
# ===============================
def call_ai_api(endpoint, payload, token):
    """
    AI সার্ভারে POST request পাঠানোর helper
    """
    try:
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        url = f"{BASE_AI_URL}{endpoint}"
        r = requests.post(url, json=payload, headers=headers, timeout=1000)
        return r.json(), r.status_code
    except Exception as e:
        return {"error": str(e)}, 500

# ===============================
# Category mapping
# ===============================
CATEGORY_KEY_MAP = {
    "place": "places",
    "restaurant": "restaurants",
    "beverage": "beverages",
    "lodging": "lodging",
    "activities": "activities",
}
import uuid 
# ===============================
# API: Get nearby vendors (DB + AI)
# ===============================
class CategoryNearbyAI(APIView):
    permission_classes = [IsUser]
    ALLOWED_CATEGORIES = ["place", "restaurant", "beverage", "lodging", "activities"]

    def post(self, request):
        # ইউজারের লোকেশন
        user_lat, user_lng = get_user_location(request)
        if not user_lat or not user_lng:
            return Response({"success": False, "message": "লোকেশন পাওয়া যায়নি। প্রোফাইল আপডেট করুন।"}, status=400)

        # Category validation
        category = request.data.get("category", "").lower().strip()
        if category not in self.ALLOWED_CATEGORIES:
            return Response({
                "success": False,
                "message": f"Allowed categories: {', '.join(self.ALLOWED_CATEGORIES)}"
            }, status=400)

        vendors_list = []

        # ===============================
        # DB vendors
        # ===============================
        db_vendors = Vendor.objects.filter(
            is_profile_complete=True,
            latitude__isnull=False,
            longitude__isnull=False,
            category__iexact=category
        )

        for vendor in db_vendors:
            distance = haversine_distance(user_lat, user_lng, vendor.latitude, vendor.longitude)
            if distance <= 2000:
                vendors_list.append({
                    "id": vendor.id or str(uuid.uuid4()),  # <-- এখানে ঠিক করা হলো
                    "vendor_name": vendor.vendor_name or "N/A",
                    "shop_name": vendor.shop_name or "N/A",
                    "phone_number": vendor.phone_number or "N/A",
                    "email": vendor.user.email if hasattr(vendor, 'user') and vendor.user else "N/A",
                    "shop_address": vendor.shop_address or "N/A",
                    "category": vendor.category or category,
                    "description": vendor.description or "",
                    "activities": vendor.activities or [],
                    "rating": float(vendor.rating) if vendor.rating else 0.0,
                    "review_count": vendor.review_count or 0,
                    "shop_images": vendor.shop_images or [],
                    "distance_meters": round(distance, 1),
                    "location": {
                        "latitude": vendor.latitude,
                        "longitude": vendor.longitude
                    }
                })


        # ===============================
        # AI vendors
        # ===============================

        try:
            payload = {"category": category, "latitude": user_lat, "longitude": user_lng}
            data, code = call_ai_api("/get_location", payload, request.auth)
            
            if data and isinstance(data, dict):
                ai_items = data.get(CATEGORY_KEY_MAP.get(category, category), [])
                
                for ai in ai_items:
                    # AI থেকে id না থাকলে UUID জেনারেট করো
                    ai_id = ai.get("id")
                    if not ai_id:  # None, null, "", False ইত্যাদি
                        ai_id = str(uuid.uuid4())
                    
                    vendors_list.append({
                        "id": ai_id,
                        "vendor_name": ai.get("name") or "N/A",
                        "shop_name": ai.get("name") or "N/A",
                        "phone_number": ai.get("phone") or "Phone not available",
                        "email": "",
                        "shop_address": ai.get("address") or "No address available",
                        "category": category,
                        "description": ai.get("description") or "No description available",
                        "activities": (
                            ai.get("features", "").split(", ") 
                            if ai.get("features") else []
                        ),
                        "rating": (
                            float(str(ai.get("rating", "0")).split("/")[0]) 
                            if ai.get("rating") else 0.0
                        ),
                        "review_count": ai.get("total_reviews", 0),
                        "shop_images": [
                            p.get("photo_url") for p in ai.get("photos", []) 
                            if p.get("photo_url")
                        ],
                        "distance_meters": round(float(ai.get("distance_km", 0)) * 1000, 1),
                        "location": {
                            "latitude": ai.get("location", {}).get("lat", 0),
                            "longitude": ai.get("location", {}).get("lng", 0)
                        }
                    })
        except Exception as e:
            # AI API ফেল করলেও ভিউ ক্র্যাশ করবে না, শুধু লগ হবে
            print("AI API error:", e)
            # vendors_list খালি থাকবে, কিন্তু DB-এর ডাটা (যদি থাকে) রিটার্ন হবে

        # Sort by distance (যদি কোনো vendor থাকে)
        vendors_list.sort(key=lambda x: x['distance_meters'])

        # অবশ্যই রিটার্ন করতে হবে (try-except এর বাইরে)
        return Response({
            "success": True,
            "your_location": {"lat": user_lat, "lng": user_lng},
            "search_radius_meters": 2000,
            "category": category,
            "total_found": len(vendors_list),
            "vendors": vendors_list
        }, status=200)




class ChatNormalAPI(APIView):
    permission_classes = [IsUser]

    def post(self, request):
        token = request.auth
        
        user_lat, user_lng = get_user_location(request)
        if not user_lat or not user_lng:
            return Response({
                "success": False,
                "message": "লোকেশন পাওয়া যায়নি। প্রোফাইল আপডেট করুন।"
            }, status=400)

        message = request.data.get("message")  # ফ্রন্টএন্ড থেকে message নেওয়া
        if not message:
            return Response({"success": False, "message": "message প্রয়োজন"}, status=400)

        final_payload = {
            "user_input": message,   # AI সার্ভারের জন্য user_input ফিল্ডে পাঠানো হচ্ছে
            "latitude": user_lat,
            "longitude": user_lng
        }

        data, code = call_ai_api("/chat/normal", final_payload, token)
        return Response(data, status=code)


class ChatPlacesAPI(APIView):
    permission_classes = [IsUser]

    def post(self, request):
        token = request.auth
        user_lat, user_lng = get_user_location(request)

        if not user_lat or not user_lng:
            return Response({"success": False, "message": "লোকেশন পাওয়া যায়নি।"}, status=400)

        message = request.data.get("message")
        if not message:
            return Response({"success": False, "message": "message প্রয়োজন"}, status=400)

        final_payload = {
            "user_input": message,   # এখানে message কে user_input হিসেবে পাঠাচ্ছি
            "latitude": user_lat,
            "longitude": user_lng
        }

        data, code = call_ai_api("/chat/places", final_payload, token)
        return Response(data, status=code)
    



class ChatRestaurantAPI(APIView):
    permission_classes = [IsUser]

    def post(self, request):
        token = request.auth
        user_lat, user_lng = get_user_location(request)

        if not user_lat or not user_lng:
            return Response({"success": False, "message": "লোকেশন পাওয়া যায়নি।"}, status=400)

        message = request.data.get("message")
        if not message:
            return Response({"success": False, "message": "message প্রয়োজন"}, status=400)

        final_payload = {
            "user_input": message,   # message কে user_input হিসেবে পাঠানো হচ্ছে
            "latitude": user_lat,
            "longitude": user_lng
        }

        data, code = call_ai_api("/chat/restaurant", final_payload, token)
        return Response(data, status=code)


class ChatBeverageAPI(APIView):
    permission_classes = [IsUser]

    def post(self, request):
        token = request.auth
        user_lat, user_lng = get_user_location(request)

        if not user_lat or not user_lng:
            return Response({"success": False, "message": "লোকেশন পাওয়া যায়নি।"}, status=400)

        message = request.data.get("message")
        if not message:
            return Response({"success": False, "message": "message প্রয়োজন"}, status=400)

        final_payload = {
            "user_input": message,
            "latitude": user_lat,
            "longitude": user_lng
        }

        data, code = call_ai_api("/chat/beverage", final_payload, token)
        return Response(data, status=code)


class ChatLodgingAPI(APIView):
    permission_classes = [IsUser]

    def post(self, request):
        token = request.auth
        user_lat, user_lng = get_user_location(request)

        if not user_lat or not user_lng:
            return Response({"success": False, "message": "লোকেশন পাওয়া যায়নি।"}, status=400)

        message = request.data.get("message")
        if not message:
            return Response({"success": False, "message": "message প্রয়োজন"}, status=400)

        final_payload = {
            "user_input": message,
            "latitude": user_lat,
            "longitude": user_lng
        }

        data, code = call_ai_api("/chat/lodging", final_payload, token)
        return Response(data, status=code)


class ChatActivitiesAPI(APIView):
    permission_classes = [IsUser]

    def post(self, request):
        token = request.auth
        user_lat, user_lng = get_user_location(request)

        if not user_lat or not user_lng:
            return Response({"success": False, "message": "লোকেশন পাওয়া যায়নি।"}, status=400)

        message = request.data.get("message")
        if not message:
            return Response({"success": False, "message": "message প্রয়োজন"}, status=400)

        final_payload = {
            "user_input": message,
            "latitude": user_lat,
            "longitude": user_lng
        }

        data, code = call_ai_api("/chat/activities", final_payload, token)
        return Response(data, status=code)
    

class ChatItineraryAPI(APIView):
    permission_classes = [IsUser]

    def post(self, request):
        token = request.auth  # ফ্রন্টএন্ড থেকে access token

        # ইউজারের লোকেশন ব্যাকএন্ড থেকে নেওয়া
        user_lat, user_lng = get_user_location(request)
        if not user_lat or not user_lng:
            return Response({
                "success": False,
                "message": "লোকেশন পাওয়া যায়নি। প্রোফাইল আপডেট করুন।"
            }, status=400)

        # ফ্রন্টএন্ড থেকে message ও preferences নাও
        message = request.data.get("message")
        preferences = request.data.get("preferences", {})  # ডিফল্ট খালি ডিকশনারি

        if not message:
            return Response({"success": False, "message": "message প্রয়োজন"}, status=400)

        # AI সার্ভারে পাঠানোর ফাইনাল পে-লোড
        final_payload = {
            "user_input": message,
            "latitude": user_lat,
            "longitude": user_lng,
            "preferences": preferences  # ফ্রন্টএন্ড থেকে যেকোন অতিরিক্ত ডেটা
        }

        # AI সার্ভারে কল
        data, code = call_ai_api("/chat/itinerary", final_payload, token)

        # ফ্রন্টএন্ডকে AI এর রেসপন্স 그대로 পাঠাও
        return Response(data, status=code)
    

class GetLocationAPI(APIView):
    permission_classes = [IsUser]

    def post(self, request):
        token = getattr(request, 'auth', None)
        user_lat, user_lng = get_user_location(request)

        if user_lat is None or user_lng is None:
            return Response({
                "success": False,
                "message": "লোকেশন পাওয়া যায়নি। প্রোফাইল আপডেট করুন।"
            }, status=status.HTTP_400_BAD_REQUEST)

        category = request.data.get("category")
        if not category:
            return Response({
                "success": False,
                "message": "category প্রয়োজন"
            }, status=status.HTTP_400_BAD_REQUEST)

        payload = {
            "category": category,
            "latitude": user_lat,
            "longitude": user_lng
        }

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
            "shop_name": v.shop_name or "নাম নেই",
            "vendor_name": v.vendor_name or "অজানা",
            "category": getattr(v, 'category', 'অজানা'),
            "rating": float(v.rating) if v.rating else 0.0,
            "review_count": getattr(v, 'review_count', 0),
            "shop_image": v.shop_images[0] if v.shop_images else None,
            "phone": v.phone_number or "ফোন নেই",
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
            "shop_name": data.get("shop_name", "AI দোকান"),
            "vendor_name": data.get("vendor_name", "অজানা"),
            "category": data.get("category", "place"),
            "rating": data.get("rating", 0.0),
            "review_count": data.get("review_count", 0),
            "shop_image": data.get("shop_images", [None])[0],
            "phone": data.get("phone_number", "ফোন পাওয়া যায়নি"),
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
            return Response({"success": False, "message": "vendor_id দিন"}, status=400)

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
                return Response({"success": True, "message": "ফেভারিট থেকে সরানো হয়েছে", "is_favorite": False, "vendor": vendor_data})

            ai_data = request.data.get("ai_vendor_data", {})
            favorite = FavoriteVendor.objects.create(
                user=user,
                ai_vendor_id=str(vendor_id),
                expiry_date=timezone.now() + timedelta(days=7),
                ai_vendor_data=ai_data
            )
            return Response({"success": True, "message": "ফেভারিটে যোগ করা হয়েছে (৭ দিনের জন্য)", "is_favorite": True, "vendor": ai_data})
        else:
            try:
                vendor = Vendor.objects.get(id=vendor_id)
            except Vendor.DoesNotExist:
                return Response({"success": False, "message": "দোকান পাওয়া যায়নি"}, status=404)

            favorite = FavoriteVendor.objects.filter(user=user, vendor=vendor).first()
            if favorite:
                favorite.delete()
                return Response({"success": True, "message": "ফেভারিট থেকে সরানো হয়েছে", "is_favorite": False, "vendor": None})

            favorite = FavoriteVendor.objects.create(user=user, vendor=vendor)
            vendor_data = get_vendor_info(favorite)  # fresh instance
            return Response({"success": True, "message": "ফেভারিটে যোগ করা হয়েছে", "is_favorite": True, "vendor": vendor_data})

# My Favorite Vendors
class MyFavoriteVendorsAPI(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        profile = getattr(request.user, "profile", None)
        if not profile or not profile.latitude or not profile.longitude:
            return Response({"success": False, "message": "তোমার প্রোফাইলে লোকেশন নেই। অনুগ্রহ করে আপডেট করো।"}, status=400)

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
