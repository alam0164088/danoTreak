import asyncio
import websockets
import json

# =================== টোকেন ===================
TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoiYWNjZXNzIiwiZXhwIjoxNzk4MzMxNjU1LCJpYXQiOjE3NjY3OTU2NTUsImp0aSI6ImQxYjAxZjcwNGQyNjRmNjU4NmZhNDkzN2Q2NGY1MWRjIiwidXNlcl9pZCI6IjE1MiJ9.75rt5nOkV7W31Bx6B190j0Kl7K7YBA2HR3ryT5stwzw"


# =================== WebSocket URL ===================
WS_URL = f"ws://127.0.0.1:8000/ws/location/?token={TOKEN}"

# =================== লোকেশন ===================
LATITUDE = 23.810331
LONGITUDE = 90.412518



async def main():
    try:
        # WebSocket connect
        async with websockets.connect(
            WS_URL,
            ping_interval=10,  # ping প্রতি ১০ সেকেন্ডে
            ping_timeout=20    # timeout ২০ সেকেন্ড
        ) as ws:
            print("✅ Connected to WebSocket server")

            while True:
                # ------------------- লোকেশন পাঠানো -------------------
                payload = {
                    "type": "location.update",
                    "data": {
                        "latitude": LATITUDE,
                        "longitude": LONGITUDE
                    }
                }
                await ws.send(json.dumps(payload))
                print("📍 Location sent")

                # ------------------- রেসপন্স চেক করা -------------------
                try:
                    response = await asyncio.wait_for(ws.recv(), timeout=5)  # ৫ সেকেন্ড timeout
                    response_data = json.loads(response)

                    msg_type = response_data.get("type")

                    # Vendor distance info handle
                    if msg_type == "vendor_distance_info":
                        print("🎯 Vendor Distance Info:")
                        vendors = response_data["data"].get("vendors", [])  # data dict থেকে vendors list নাও
                        for vendor in vendors:
                            print(f"- {vendor['vendor_name']} | {vendor['distance_m']}m | Active Campaign: {vendor['has_active_campaign']} | Matched: {vendor['matched']}")
                        # success/message info
                        if any(v.get("matched") for v in vendors):
                            print("✅ Auto Check-in: Already visited recently or reward unlocked")
                        else:
                            print("⚠️ Info: No nearby vendor matched")


                    else:
                        # অন্য response যেমন location.update, online_users_update
                        print("Response:", json.dumps(response_data, indent=4))

                except asyncio.TimeoutError:
                    # যদি response না আসে, শুধু skip করো
                    pass
                except Exception as e:
                    print("❌ Error processing response:", e)

                # প্রতি ৫ সেকেন্ডে আপডেট
                await asyncio.sleep(5)

    except websockets.ConnectionClosed as e:
        print("❌ WebSocket closed:", e)
    except Exception as e:
        print("❌ Error:", e)

# =================== স্ক্রিপ্ট রান ===================
if __name__ == "__main__":
    asyncio.run(main())
