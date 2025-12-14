# import requests
# from rest_framework.views import APIView
# from rest_framework.response import Response
# from rest_framework import status
# from .permissions import IsUser
#  # তোমার permission ফাইল থেকে import কর
 

# BASE_AI_URL = "http://10.10.7.82:8005"


# def get_user_location(request):
#     """
#     User model-এর সাথে থাকা Profile থেকে latitude/longitude তুলে আনে।
#     """
#     try:
#         profile = request.user.profile

#         lat = getattr(profile, "latitude", None)
#         lng = getattr(profile, "longitude", None)

#         if lat is None or lng is None:
#             return None, None

#         return float(lat), float(lng)

#     except:
#         return None, None


# def call_ai_api(endpoint, payload, token):
#     """ Helper function """
#     try:
#         headers = {"Authorization": f"Bearer {token}"}
#         url = f"{BASE_AI_URL}{endpoint}"

#         r = requests.post(url, json=payload, headers=headers, timeout=1000)
#         return r.json(), r.status_code

#     except Exception as e:
#         return {"error": str(e)}, 500

# class GetLocationAPI(APIView):
#     permission_classes = [IsUser]

#     def post(self, request):
#         token = request.auth   # JWT token

#         # Get user location from profile
#         user_lat, user_lng = get_user_location(request)

#         if not user_lat or not user_lng:
#             return Response({
#                 "success": False,
#                 "message": "লোকেশন পাওয়া যায়নি। প্রোফাইল আপডেট করুন।"
#             }, status=400)

#         # frontend থেকে শুধু category নিলেই হবে
#         category = request.data.get("category")

#         if not category:
#             return Response({"success": False, "message": "category প্রয়োজন"}, status=400)

#         # create final payload (এটাই AI সার্ভারে যাবে)
#         final_payload = {
#             "category": category,
#             "latitude": user_lat,
#             "longitude": user_lng
#         }

#         # এখন AI সার্ভারে পাঠাও
#         data, code = call_ai_api("/get_location", final_payload, token)

#         return Response(data, status=code)
    
 

# # from rest_framework.permissions import IsAuthenticated
# # from rest_framework.views import APIView
# # from rest_framework.response import Response
# # from rest_framework import status

# # class CategoryNearbyAI(APIView):
# #     permission_classes = [IsAuthenticated]

# #     # Allowed categories
# #     ALLOWED_CATEGORIES = ["place", "restaurant", "beverage", "lodging", "activities"]

# #     # Map request category to AI response key
# #     CATEGORY_KEY_MAP = {
# #         "place": "places",
# #         "restaurant": "restaurants",
# #         "beverage": "beverages",
# #         "lodging": "lodging",
# #         "activities": "activities",
        
# #     }

# #     def post(self, request):
# #         token = request.auth
# #         user_lat, user_lng = get_user_location(request)

# #         if not user_lat or not user_lng:
# #             return Response(
# #                 {"success": False, "message": "লোকেশন পাওয়া যায়নি। প্রোফাইল আপডেট করুন।"},
# #                 status=400
# #             )

# #         # Normalize category input
# #         category = request.data.get("category", "").lower().strip()
# #         if not category:
# #             return Response({"success": False, "message": "category প্রয়োজন"}, status=400)

# #         # Validate category
# #         if category not in self.ALLOWED_CATEGORIES:
# #             return Response(
# #                 {"success": False, "message": f"Invalid category. Allowed: {', '.join(self.ALLOWED_CATEGORIES)}"},
# #                 status=400
# #             )

# #         # Prepare payload for AI API
# #         payload = {"category": category, "latitude": user_lat, "longitude": user_lng}
# #         ai_vendors_list = []

# #         try:
# #             data, code = call_ai_api("/get_location", payload, token)

# #             # Get AI response key based on category
# #             key = self.CATEGORY_KEY_MAP.get(category)
# #             ai_items = data.get(key, [])

# #             for ai in ai_items:
# #                 ai_vendors_list.append({
# #                     "id": ai.get("id", None),
# #                     "vendor_name": ai.get("name"),
# #                     "shop_name": ai.get("name"),
# #                     "phone_number": ai.get("phone", ""),
# #                     "email": "",
# #                     "shop_address": ai.get("address", ""),
# #                     "category": category,
# #                     "description": ai.get("description", ""),
# #                     "activities": ai.get("features", "").split(", ") if ai.get("features") else [],
# #                     "rating": float(str(ai.get("rating", "0")).split("/")[0]) if ai.get("rating") else 0,
# #                     "review_count": ai.get("total_reviews", 0),
# #                     "shop_images": [p.get("photo_url") for p in ai.get("photos", [])] if ai.get("photos") else [],
# #                     "distance_meters": round(float(ai.get("distance_km", 0)) * 1000, 1),
# #                     "location": {
# #                         "latitude": ai.get("location", {}).get("lat", 0),
# #                         "longitude": ai.get("location", {}).get("lng", 0)
# #                     }
# #                 })

# #         except Exception as e:
# #             return Response({"success": False, "error": str(e)}, status=500)

# #         # Sort vendors by distance
# #         ai_vendors_list.sort(key=lambda x: x.get("distance_meters", 99999))

# #         return Response({
# #             "success": True,
# #             "your_location": {"lat": user_lat, "lng": user_lng},
# #             "search_radius_meters": 2000,
# #             "total_found": len(ai_vendors_list),
# #             "vendors": ai_vendors_list
# #         }, status=200)




# from rest_framework.permissions import IsAuthenticated
# from rest_framework.views import APIView
# from rest_framework.response import Response
# from authentication.models import Vendor
# import math

# # ===============================
# # Haversine distance
# # ===============================
# def haversine_distance(lat1, lon1, lat2, lon2):
#     R = 6371  # পৃথিবীর ব্যাসার্ধ (কিমি)
#     lat1, lon1, lat2, lon2 = map(float, [lat1, lon1, lat2, lon2])
#     lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])
#     dlat = lat2 - lat1
#     dlon = lon2 - lon1
#     a = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
#     c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
#     return R * c * 1000  # মিটারে কনভার্ট

# # ===============================
# # Category to AI key mapping
# # ===============================
# CATEGORY_KEY_MAP = {
#     "place": "places",
#     "restaurant": "restaurants",
#     "beverage": "beverages",
#     "lodging": "lodging",
#     "activities": "activities",
# }

# # ===============================
# # Helper: Call AI API
# # ===============================
# import requests

# BASE_AI_URL = "http://10.10.7.82:8005"

# def call_ai_api(endpoint, payload, token):
#     try:
#         headers = {"Authorization": f"Bearer {token}"}
#         url = f"{BASE_AI_URL}{endpoint}"
#         response = requests.post(url, json=payload, headers=headers, timeout=1000)
#         return response.json(), response.status_code
#     except Exception as e:
#         return {"error": str(e)}, 500

# # ===============================
# # API View
# # ===============================
# class CategoryNearbyAI(APIView):
#     permission_classes = [IsAuthenticated]
#     ALLOWED_CATEGORIES = ["place", "restaurant", "beverage", "lodging", "activities"]

#     def post(self, request):
#         # ইউজারের লোকেশন
#         try:
#             profile = request.user.profile
#             user_lat = getattr(profile, 'latitude', None)
#             user_lng = getattr(profile, 'longitude', None)
#         except:
#             user_lat = None
#             user_lng = None

#         if user_lat is None or user_lng is None:
#             return Response({
#                 "success": False,
#                 "message": "প্রোফাইলে তোমার লোকেশন নেই। অনুগ্রহ করে আপডেট করো।"
#             }, status=400)

#         # category validation
#         category = request.data.get("category", "").lower().strip()
#         if category not in self.ALLOWED_CATEGORIES:
#             return Response({
#                 "success": False,
#                 "message": f"Allowed categories: {', '.join(self.ALLOWED_CATEGORIES)}"
#             }, status=400)

#         vendors_list = []

#         # ===============================
#         # ডাটাবেস থেকে vendors
#         # ===============================
#         db_vendors = Vendor.objects.filter(
#             is_profile_complete=True,
#             latitude__isnull=False,
#             longitude__isnull=False,
#             category__iexact=category
#         )

#         for vendor in db_vendors:
#             distance = haversine_distance(user_lat, user_lng, vendor.latitude, vendor.longitude)
#             if distance <= 2000:
#                 vendors_list.append({
#                     "id": vendor.id,
#                     "vendor_name": vendor.vendor_name or "N/A",
#                     "shop_name": vendor.shop_name or "N/A",
#                     "phone_number": vendor.phone_number or "N/A",
#                     "email": vendor.user.email if hasattr(vendor, 'user') and vendor.user else "N/A",
#                     "shop_address": vendor.shop_address or "N/A",
#                     "category": vendor.category or category,
#                     "description": vendor.description or "",
#                     "activities": vendor.activities or [],
#                     "rating": float(vendor.rating) if vendor.rating else 0.0,
#                     "review_count": vendor.review_count or 0,
#                     "shop_images": vendor.shop_images or [],
#                     "distance_meters": round(distance, 1),
#                     "location": {
#                         "latitude": vendor.latitude,
#                         "longitude": vendor.longitude
#                     }
#                 })

#         # ===============================
#         # AI থেকে vendors
#         # ===============================
#         try:
#             payload = {"category": category, "latitude": user_lat, "longitude": user_lng}
#             data, code = call_ai_api("/get_location", payload, request.auth)
#             ai_items = data.get(CATEGORY_KEY_MAP.get(category, category), [])

#             for ai in ai_items:
#                 vendors_list.append({
#                     "id": ai.get("id"),
#                     "vendor_name": ai.get("name"),
#                     "shop_name": ai.get("name"),
#                     "phone_number": ai.get("phone", ""),
#                     "email": "",
#                     "shop_address": ai.get("address", ""),
#                     "category": category,
#                     "description": ai.get("description", ""),
#                     "activities": ai.get("features", "").split(", ") if ai.get("features") else [],
#                     "rating": float(str(ai.get("rating", "0")).split("/")[0]) if ai.get("rating") else 0,
#                     "review_count": ai.get("total_reviews", 0),
#                     "shop_images": [p.get("photo_url") for p in ai.get("photos", [])] if ai.get("photos") else [],
#                     "distance_meters": round(float(ai.get("distance_km", 0)) * 1000, 1),
#                     "location": {
#                         "latitude": ai.get("location", {}).get("lat", 0),
#                         "longitude": ai.get("location", {}).get("lng", 0)
#                     }
#                 })
#         except Exception as e:
#             print("AI API error:", e)

#         # distance-wise sort
#         vendors_list.sort(key=lambda x: x['distance_meters'])

#         return Response({
#             "success": True,
#             "your_location": {"lat": user_lat, "lng": user_lng},
#             "search_radius_meters": 2000,
#             "category": category,
#             "total_found": len(vendors_list),
#             "vendors": vendors_list
#         }, status=200)


# class ChatNormalAPI(APIView):
#     permission_classes = [IsUser]

#     def post(self, request):
#         token = request.auth
        
#         user_lat, user_lng = get_user_location(request)
#         if not user_lat or not user_lng:
#             return Response({
#                 "success": False,
#                 "message": "লোকেশন পাওয়া যায়নি। প্রোফাইল আপডেট করুন।"
#             }, status=400)

#         message = request.data.get("message")  # ফ্রন্টএন্ড থেকে message নেওয়া
#         if not message:
#             return Response({"success": False, "message": "message প্রয়োজন"}, status=400)

#         final_payload = {
#             "user_input": message,   # AI সার্ভারের জন্য user_input ফিল্ডে পাঠানো হচ্ছে
#             "latitude": user_lat,
#             "longitude": user_lng
#         }

#         data, code = call_ai_api("/chat/normal", final_payload, token)
#         return Response(data, status=code)


# class ChatPlacesAPI(APIView):
#     permission_classes = [IsUser]

#     def post(self, request):
#         token = request.auth
#         user_lat, user_lng = get_user_location(request)

#         if not user_lat or not user_lng:
#             return Response({"success": False, "message": "লোকেশন পাওয়া যায়নি।"}, status=400)

#         message = request.data.get("message")
#         if not message:
#             return Response({"success": False, "message": "message প্রয়োজন"}, status=400)

#         final_payload = {
#             "user_input": message,   # এখানে message কে user_input হিসেবে পাঠাচ্ছি
#             "latitude": user_lat,
#             "longitude": user_lng
#         }

#         data, code = call_ai_api("/chat/places", final_payload, token)
#         return Response(data, status=code)



# class ChatRestaurantAPI(APIView):
#     permission_classes = [IsUser]

#     def post(self, request):
#         token = request.auth
#         user_lat, user_lng = get_user_location(request)

#         if not user_lat or not user_lng:
#             return Response({"success": False, "message": "লোকেশন পাওয়া যায়নি।"}, status=400)

#         message = request.data.get("message")
#         if not message:
#             return Response({"success": False, "message": "message প্রয়োজন"}, status=400)

#         final_payload = {
#             "user_input": message,   # message কে user_input হিসেবে পাঠানো হচ্ছে
#             "latitude": user_lat,
#             "longitude": user_lng
#         }

#         data, code = call_ai_api("/chat/restaurant", final_payload, token)
#         return Response(data, status=code)


# class ChatBeverageAPI(APIView):
#     permission_classes = [IsUser]

#     def post(self, request):
#         token = request.auth
#         user_lat, user_lng = get_user_location(request)

#         if not user_lat or not user_lng:
#             return Response({"success": False, "message": "লোকেশন পাওয়া যায়নি।"}, status=400)

#         message = request.data.get("message")
#         if not message:
#             return Response({"success": False, "message": "message প্রয়োজন"}, status=400)

#         final_payload = {
#             "user_input": message,
#             "latitude": user_lat,
#             "longitude": user_lng
#         }

#         data, code = call_ai_api("/chat/beverage", final_payload, token)
#         return Response(data, status=code)


# class ChatLodgingAPI(APIView):
#     permission_classes = [IsUser]

#     def post(self, request):
#         token = request.auth
#         user_lat, user_lng = get_user_location(request)

#         if not user_lat or not user_lng:
#             return Response({"success": False, "message": "লোকেশন পাওয়া যায়নি।"}, status=400)

#         message = request.data.get("message")
#         if not message:
#             return Response({"success": False, "message": "message প্রয়োজন"}, status=400)

#         final_payload = {
#             "user_input": message,
#             "latitude": user_lat,
#             "longitude": user_lng
#         }

#         data, code = call_ai_api("/chat/lodging", final_payload, token)
#         return Response(data, status=code)


# class ChatActivitiesAPI(APIView):
#     permission_classes = [IsUser]

#     def post(self, request):
#         token = request.auth
#         user_lat, user_lng = get_user_location(request)

#         if not user_lat or not user_lng:
#             return Response({"success": False, "message": "লোকেশন পাওয়া যায়নি।"}, status=400)

#         message = request.data.get("message")
#         if not message:
#             return Response({"success": False, "message": "message প্রয়োজন"}, status=400)

#         final_payload = {
#             "user_input": message,
#             "latitude": user_lat,
#             "longitude": user_lng
#         }

#         data, code = call_ai_api("/chat/activities", final_payload, token)
#         return Response(data, status=code)




# class ChatItineraryAPI(APIView):
#     permission_classes = [IsUser]

#     def post(self, request):
#         token = request.auth  # ফ্রন্টএন্ড থেকে access token

#         # ইউজারের লোকেশন ব্যাকএন্ড থেকে নেওয়া
#         user_lat, user_lng = get_user_location(request)
#         if not user_lat or not user_lng:
#             return Response({
#                 "success": False,
#                 "message": "লোকেশন পাওয়া যায়নি। প্রোফাইল আপডেট করুন।"
#             }, status=400)

#         # ফ্রন্টএন্ড থেকে message ও preferences নাও
#         message = request.data.get("message")
#         preferences = request.data.get("preferences", {})  # ডিফল্ট খালি ডিকশনারি

#         if not message:
#             return Response({"success": False, "message": "message প্রয়োজন"}, status=400)

#         # AI সার্ভারে পাঠানোর ফাইনাল পে-লোড
#         final_payload = {
#             "user_input": message,
#             "latitude": user_lat,
#             "longitude": user_lng,
#             "preferences": preferences  # ফ্রন্টএন্ড থেকে যেকোন অতিরিক্ত ডেটা
#         }

#         # AI সার্ভারে কল
#         data, code = call_ai_api("/chat/itinerary", final_payload, token)

#         # ফ্রন্টএন্ডকে AI এর রেসপন্স 그대로 পাঠাও
#         return Response(data, status=code)


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
            if distance <= 2000:  # 2km radius
                vendors_list.append({
                    "id": vendor.id,
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
            ai_items = data.get(CATEGORY_KEY_MAP.get(category, category), [])

            for ai in ai_items:
                vendors_list.append({
                    "id": ai.get("id"),
                    "vendor_name": ai.get("name"),
                    "shop_name": ai.get("name"),
                    "phone_number": ai.get("phone", ""),
                    "email": "",
                    "shop_address": ai.get("address", ""),
                    "category": category,
                    "description": ai.get("description", ""),
                    "activities": ai.get("features", "").split(", ") if ai.get("features") else [],
                    "rating": float(str(ai.get("rating", "0")).split("/")[0]) if ai.get("rating") else 0,
                    "review_count": ai.get("total_reviews", 0),
                    "shop_images": [p.get("photo_url") for p in ai.get("photos", [])] if ai.get("photos") else [],
                    "distance_meters": round(float(ai.get("distance_km", 0)) * 1000, 1),
                    "location": {
                        "latitude": ai.get("location", {}).get("lat", 0),
                        "longitude": ai.get("location", {}).get("lng", 0)
                    }
                })
        except Exception as e:
            print("AI API error:", e)

        # Sort by distance
        vendors_list.sort(key=lambda x: x['distance_meters'])

        return Response({
            "success": True,
            "your_location": {"lat": user_lat, "lng": user_lng},
            "search_radius_meters": 2000,
            "category": category,
            "total_found": len(vendors_list),
            "vendors": vendors_list
        }, status=200)


# Generic Chat API class

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
    

    
# from rest_framework.views import APIView
# from rest_framework.response import Response
# from rest_framework import status
# from .permissions import IsUser
# import requests

# BASE_AI_URL = "http://10.10.7.82:8005"

# # ইউজারের লোকেশন নেওয়ার helper ফাংশন
# def get_user_location(request):
#     try:
#         profile = request.user.profile
#         lat = getattr(profile, "latitude", None)
#         lng = getattr(profile, "longitude", None)
#         if lat is None or lng is None:
#             return None, None
#         return float(lat), float(lng)
#     except AttributeError:
#         return None, None

# # AI API কল করার helper ফাংশন
# def call_ai_api(endpoint, payload, token=None):
#     try:
#         headers = {"Authorization": f"Bearer {token}"} if token else {}
#         url = f"{BASE_AI_URL}{endpoint}"
#         response = requests.post(url, json=payload, headers=headers, timeout=100)  # Timeout 10 সেকেন্ড
#         return response.json(), response.status_code
#     except requests.RequestException as e:
#         return {"error": str(e)}, 500

# API ভিউ
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
