# authentication/routing.py
from django.urls import re_path
from .consumers import LiveLocationConsumer

websocket_urlpatterns = [
    re_path(r'ws/location/$', LiveLocationConsumer.as_asgi()),
]
