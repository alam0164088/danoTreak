import requests
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .permissions import IsUser
 # তোমার permission ফাইল থেকে import কর
 

BASE_AI_URL = "http://10.10.7.82:8005"


def get_user_location(request):
    """
    User model-এর সাথে থাকা Profile থেকে latitude/longitude তুলে আনে।
    """
    try:
        profile = request.user.profile

        lat = getattr(profile, "latitude", None)
        lng = getattr(profile, "longitude", None)

        if lat is None or lng is None:
            return None, None

        return float(lat), float(lng)

    except:
        return None, None


def call_ai_api(endpoint, payload, token):
    """ Helper function """
    try:
        headers = {"Authorization": f"Bearer {token}"}
        url = f"{BASE_AI_URL}{endpoint}"

        r = requests.post(url, json=payload, headers=headers, timeout=1000)
        return r.json(), r.status_code

    except Exception as e:
        return {"error": str(e)}, 500

class GetLocationAPI(APIView):
    permission_classes = [IsUser]

    def post(self, request):
        token = request.auth   # JWT token

        # Get user location from profile
        user_lat, user_lng = get_user_location(request)

        if not user_lat or not user_lng:
            return Response({
                "success": False,
                "message": "লোকেশন পাওয়া যায়নি। প্রোফাইল আপডেট করুন।"
            }, status=400)

        # frontend থেকে শুধু category নিলেই হবে
        category = request.data.get("category")

        if not category:
            return Response({"success": False, "message": "category প্রয়োজন"}, status=400)

        # create final payload (এটাই AI সার্ভারে যাবে)
        final_payload = {
            "category": category,
            "latitude": user_lat,
            "longitude": user_lng
        }

        # এখন AI সার্ভারে পাঠাও
        data, code = call_ai_api("/get_location", final_payload, token)

        return Response(data, status=code)


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
