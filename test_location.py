import asyncio
import websockets
import json

# =================== টোকেন ===================
TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoiYWNjZXNzIiwiZXhwIjoxNzk3NDUzODU5LCJpYXQiOjE3NjU5MTc4NTksImp0aSI6IjY4YmEzMmZkMTI0NjQxYjE4Y2Q2ODIyNzg0YjY5NmZiIiwidXNlcl9pZCI6IjEyOCJ9.N7Rbl6TfTxPAbFepgbIN9FEQ2xH6OxBNrvkdrGOqPVA" 
# =================== WebSocket URL ===================
WS_URL = f"ws://127.0.0.1:8000/ws/location/?token={TOKEN}"

async def main():
    try:
        async with websockets.connect(WS_URL) as ws:
            print("✅ Connected to WebSocket server")

            while True:
                # ------------------- লোকেশন পাঠানো -------------------
                payload = {
                    "type": "location.update",
                    "data": {
                        "latitude": 23.810331,
                        "longitude": 90.412518
                    }
                }
                await ws.send(json.dumps(payload))
                print("📍 Location sent")

                # ------------------- রেসপন্স চেক করা -------------------
                try:
                    response = await asyncio.wait_for(ws.recv(), timeout=2)
                    response_data = json.loads(response)

                    msg_type = response_data.get("type")

                    if msg_type == "vendor_distance_info":
                        print("🎯 Vendor Distance Info:")
                        for vendor in response_data["data"]["vendors"]:
                            print(f"- {vendor['vendor_name']} | {vendor['distance_m']}m | Active Campaign: {vendor['has_active_campaign']} | Matched: {vendor['matched']}")
                        if response_data["data"].get("success"):
                            print("✅ Auto Check-in:", response_data["data"].get("message"))
                        else:
                            print("⚠️ Info:", response_data["data"].get("message"))

                    else:
                        # অন্য response যেমন location.update, online_users_update
                        print("Response:", json.dumps(response_data, indent=4))

                except asyncio.TimeoutError:
                    # যদি কোনো রেসপন্স না আসে, শুধু পাশ করো
                    pass

                # প্রতি ৫ সেকেন্ডে আপডেট
                await asyncio.sleep(5)

    except Exception as e:
        print("❌ Error:", e)

# =================== স্ক্রিপ্ট রান ===================
asyncio.run(main())
