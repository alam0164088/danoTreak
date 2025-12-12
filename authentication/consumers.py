# authentication/consumers.py
import json
from channels.generic.websocket import AsyncWebsocketConsumer
from datetime import datetime
from asgiref.sync import sync_to_async

LIVE_USERS = {}

class LiveLocationConsumer(AsyncWebsocketConsumer):

    async def connect(self):
        self.user = self.scope.get("user")
        print("Connecting user:", self.user)

        if not self.user or self.user.is_anonymous:
            print("Anonymous or no user, closing connection")
            await self.close()
            return

        self.group_name = "live_location_group"
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

        await self.send(text_data=json.dumps({
            "status": "connected",
            "message": "Live location streaming started",
            "user_id": self.user.id
        }))

    async def disconnect(self, close_code):
        print(f"Disconnecting user: {self.user}")
        if hasattr(self, "group_name"):
            await self.channel_layer.group_discard(self.group_name, self.channel_name)
            if self.user.id in LIVE_USERS:
                del LIVE_USERS[self.user.id]

    async def receive(self, text_data):
        from authentication.models import Profile, Vendor

        try:
            data = json.loads(text_data)
            lat = data.get("latitude")
            lng = data.get("longitude")

            if lat is not None and lng is not None:
                lat = float(lat)
                lng = float(lng)

                # LIVE_USERS আপডেট
                LIVE_USERS[self.user.id] = {
                    "user_id": self.user.id,
                    "email": self.user.email,
                    "full_name": getattr(self.user, "full_name", "User"),
                    "latitude": lat,
                    "longitude": lng,
                    "last_seen": datetime.now().strftime("%H:%M:%S")
                }

                # ডাটাবেজে লোকেশন আপডেট
                await self.update_user_location(lat, lng)

                # গ্রুপে সবাইকে পাঠানো
                await self.channel_layer.group_send(
                    self.group_name,
                    {
                        "type": "location_update",  # triggers location_update method
                        "location": LIVE_USERS[self.user.id]
                    }
                )

                print(f"Location updated for user {self.user.id}: {lat}, {lng}")

        except Exception as e:
            print(f"Location error: {e}")

    # ==============================
    # Async safe DB update method
    # ==============================
    async def update_user_location(self, lat, lng):
        from authentication.models import Profile, Vendor
        try:
            # Profile update
            profile = await sync_to_async(lambda: self.user.profile)()
            profile.latitude = lat
            profile.longitude = lng
            await sync_to_async(profile.save)()
        except Profile.DoesNotExist:
            print("Profile not found for user:", self.user.id)

        try:
            # Vendor update
            vendor = await sync_to_async(lambda: self.user.vendor_profile)()
            vendor.latitude = lat
            vendor.longitude = lng
            await sync_to_async(vendor.save)()
        except Vendor.DoesNotExist:
            pass

    # ==============================
    # Group message handler
    # ==============================
    async def location_update(self, event):
        location_data = event.get("location")
        await self.send(text_data=json.dumps({
            "type": "location.update",
            "data": location_data
        }))
