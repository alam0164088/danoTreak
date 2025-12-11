import requests
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .permissions import IsUser
 # তোমার permission ফাইল থেকে import কর

BASE_AI_URL = "http://10.10.7.82:8005"


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
        data, code = call_ai_api("/get_location", request.data, token)
        return Response(data, status=code)


class ChatNormalAPI(APIView):
    permission_classes = [IsUser]

    def post(self, request):
        token = request.auth
        data, code = call_ai_api("/chat/normal", request.data, token)
        return Response(data, status=code)


class ChatPlacesAPI(APIView):
    permission_classes = [IsUser]

    def post(self, request):
        token = request.auth
        data, code = call_ai_api("/chat/places", request.data, token)
        return Response(data, status=code)


class ChatRestaurantAPI(APIView):
    permission_classes = [IsUser]

    def post(self, request):
        token = request.auth
        data, code = call_ai_api("/chat/restaurant", request.data, token)
        return Response(data, status=code)


class ChatBeverageAPI(APIView):
    permission_classes = [IsUser]

    def post(self, request):
        token = request.auth
        data, code = call_ai_api("/chat/beverage", request.data, token)
        return Response(data, status=code)


class ChatLodgingAPI(APIView):
    permission_classes = [IsUser]

    def post(self, request):
        token = request.auth
        data, code = call_ai_api("/chat/lodging", request.data, token)
        return Response(data, status=code)


class ChatActivitiesAPI(APIView):
    permission_classes = [IsUser]

    def post(self, request):
        token = request.auth
        data, code = call_ai_api("/chat/activities", request.data, token)
        return Response(data, status=code)


class ChatItineraryAPI(APIView):
    permission_classes = [IsUser]

    def post(self, request):
        token = request.auth
        data, code = call_ai_api("/chat/itinerary", request.data, token)
        return Response(data, status=code)
