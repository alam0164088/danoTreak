import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from datetime import datetime, timedelta
from math import radians, sin, cos, sqrt, atan2
from django.utils import timezone

ONLINE_USERS = set()


class LiveLocationConsumer(AsyncWebsocketConsumer):

    async def connect(self):
        self.user = self.scope.get("user")
        if not self.user or self.user.is_anonymous:
            print("Anonymous user tried to connect. Closing WS.")
            await self.close()
            return

        # Group names
        self.location_group_name = "live_location_group"
        self.online_group_name = "live_users"

        # Add to groups
        await self.channel_layer.group_add(self.location_group_name, self.channel_name)
        await self.channel_layer.group_add(self.online_group_name, self.channel_name)

        # Track online users
        ONLINE_USERS.add(self.user.id)
        await self.accept()

        # প্রোফাইল থেকে প্রাথমিক লোকেশন
        lat, lng = None, None
        try:
            profile = await database_sync_to_async(lambda: self.user.profile)()
            lat = float(profile.latitude) if profile.latitude is not None else None
            lng = float(profile.longitude) if profile.longitude is not None else None
        except Exception:
            pass

        print(f"WS Connected: user_id={self.user.id}, email={self.user.email}, lat={lat}, lng={lng}")

        await self.send(json.dumps({
            "status": "connected",
            "message": "Live location streaming started",
            "user_id": self.user.id,
            "email": self.user.email,
            "latitude": lat,
            "longitude": lng
        }))

        await self.broadcast_online_users()

    async def disconnect(self, close_code):
        # Safely discard from groups if attributes exist
        if hasattr(self, 'location_group_name'):
            await self.channel_layer.group_discard(self.location_group_name, self.channel_name)
        if hasattr(self, 'online_group_name'):
            await self.channel_layer.group_discard(self.online_group_name, self.channel_name)

        # Remove from online list
        if hasattr(self, 'user') and self.user and not self.user.is_anonymous:
            ONLINE_USERS.discard(self.user.id)

        print(f"WS Disconnected: user_id={getattr(self, 'user', None) and getattr(self.user, 'id', None)}, email={getattr(self, 'user', None) and getattr(self.user, 'email', None)}")

        # Broadcast online users safely
        if hasattr(self, 'online_group_name'):
            await self.broadcast_online_users()

    async def receive(self, text_data):
        try:
            data = json.loads(text_data)

            # Support both new wrapped format and legacy plain payload
            if data.get("type") == "location.update" and isinstance(data.get("data"), dict):
                lat = float(data["data"]["latitude"])
                lng = float(data["data"]["longitude"])
            elif "latitude" in data and "longitude" in data:
                lat = float(data["latitude"])
                lng = float(data["longitude"])
            else:
                return

            print(f"Received location from user {self.user.id} ({self.user.email}): lat={lat}, lng={lng}")

            await self.update_user_location(lat, lng)

            # Broadcast location to group
            await self.channel_layer.group_send(
                self.location_group_name,
                {
                    "type": "location_update",
                    "location": {
                        "user_id": self.user.id,
                        "email": self.user.email,
                        "full_name": getattr(self.user, "full_name", self.user.email.split("@")[0]),
                        "latitude": float(lat),
                        "longitude": float(lng),
                        "last_seen": datetime.now().strftime("%H:%M:%S")
                    }
                }
            )

            # Check-in & Redemption logic
            if getattr(self.user, "role", None) == "user":
                checkin_result = await database_sync_to_async(self.perform_auto_checkin)(self.user, lat, lng)
                print("Check-in result:", checkin_result)
                if checkin_result:
                    await self.send(json.dumps({
                        "type": "vendor_distance_info",
                        "data": checkin_result
                    }))

        except Exception as e:
            print("WS Receive Error:", e)

    async def update_user_location(self, lat, lng):
        from authentication.models import Profile
        try:
            profile, _ = await database_sync_to_async(Profile.objects.get_or_create)(user=self.user)
            profile.latitude = lat
            profile.longitude = lng
            await database_sync_to_async(profile.save)()
        except Exception:
            pass

    async def location_update(self, event):
        await self.send(json.dumps({
            "type": "location.update",
            "data": event["location"]
        }))

    async def broadcast_online_users(self):
        online_users_list = list(ONLINE_USERS)
        if hasattr(self, 'online_group_name'):
            await self.channel_layer.group_send(
                self.online_group_name,
                {
                    "type": "online_users_update",
                    "online_users": online_users_list
                }
            )

    async def online_users_update(self, event):
        await self.send(json.dumps({
            "type": "online_users_update",
            "online_users": event["online_users"],
            "total_online": len(event["online_users"])
        }))

    async def user_online(self, event):
        try:
            payload = event.get("data") or {"total_online": event.get("total_online")}
            await self.send(text_data=json.dumps({
                "type": "user_online",
                "data": payload
            }))
        except Exception:
            return

    @staticmethod
    def haversine(lat1, lon1, lat2, lon2):
        R = 6371000
        φ1, φ2 = radians(lat1), radians(lat2)
        Δφ = radians(lat2 - lat1)
        Δλ = radians(lon2 - lon1)
        a = sin(Δφ / 2)**2 + cos(φ1) * cos(φ2) * sin(Δλ / 2)**2
        return R * (2 * atan2(sqrt(a), sqrt(1 - a)))

    def perform_auto_checkin(self, user, lat, lng):
        from vendor.models import Visitor, Visit, Campaign, Redemption
        from authentication.models import Vendor, Notification
        from vendor.utils import generate_aliffited_id

        vendors = Vendor.objects.filter(latitude__isnull=False, longitude__isnull=False)
        matched_vendors = []

        for v in vendors:
            try:
                distance = self.haversine(lat, lng, float(v.latitude), float(v.longitude))
            except:
                continue

            if distance <= 100 and v.campaigns.filter(is_active=True).exists():
                matched_vendors.append((v, round(distance, 2)))

        if not matched_vendors:
            return {"success": False, "message": "No nearby vendor"}

        results = []

        for vendor, distance in matched_vendors:

            visitor, _ = Visitor.objects.get_or_create(
                user=user,
                vendor=vendor,
                defaults={"name": user.get_full_name() or user.email.split("@")[0]}
            )

            if visitor.is_blocked:
                continue

            # ✅ ALWAYS CREATE VISIT
            Visit.objects.create(
                visitor=visitor,
                vendor=vendor,
                lat=lat,
                lng=lng
            )

            visitor.total_visits += 1
            visitor.save(update_fields=["total_visits"])

            rewards = []
            aliffited_ids = []

            campaigns = Campaign.objects.filter(vendor=vendor, is_active=True)

            for campaign in campaigns:
                if visitor.total_visits >= campaign.required_visits:
                    redemption = Redemption.objects.create(
                        visitor=visitor,
                        campaign=campaign,
                        status="pending",
                        aliffited_id=generate_aliffited_id()
                    )

                    rewards.append(campaign.reward_name)
                    aliffited_ids.append(redemption.aliffited_id)

                    Notification.objects.create(
                        user=user,
                        title="🎉 Redeem Unlocked!",
                        message=f"You unlocked {campaign.reward_name}",
                        aliffited_id=redemption.aliffited_id,
                        shop_name=vendor.shop_name,
                        reward_name=campaign.reward_name
                    )

            results.append({
                "vendor_id": vendor.id,
                "vendor_name": vendor.shop_name,
                "distance": distance,
                "total_visits": visitor.total_visits,
                "rewards": rewards,
                "aliffited_ids": aliffited_ids
            })

        return {
            "success": True,
            "message": "Check-in successful",
            "checkins": results
        }
