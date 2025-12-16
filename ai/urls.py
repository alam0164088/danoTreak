from django.urls import path
from .views import (
    GetLocationAPI, ChatNormalAPI, ChatPlacesAPI, ChatBeverageAPI,
    ChatLodgingAPI, ChatActivitiesAPI,ChatRestaurantAPI, CategoryNearbyAI,ChatItineraryAPI,ToggleFavoriteVendor,MyFavoriteVendorsAPI
)

urlpatterns = [
     
    path('toggle-favorite/', ToggleFavoriteVendor.as_view(), name='toggle-favorite'),
    path('my-favorites-vendor/', MyFavoriteVendorsAPI.as_view(), name='my-favorites'),
   
    # Nearby & Favorites
    path("location/", GetLocationAPI.as_view(), name="get_location"),
    path("chat/normal/", ChatNormalAPI.as_view()),
    path("chat/places/", ChatPlacesAPI.as_view()),
    path("chat/restaurant/", ChatRestaurantAPI.as_view(), name="chat_restaurant"),
    path("chat/beverage/", ChatBeverageAPI.as_view()),
    path("chat/lodging/", ChatLodgingAPI.as_view()),
    path("chat/activities/", ChatActivitiesAPI.as_view()),
    path("chat/itinerary/", ChatItineraryAPI.as_view()),
    path("chat/CategoryNearbyAI/", CategoryNearbyAI.as_view())
]
