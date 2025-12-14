import asyncio
import websockets
import json

TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoiYWNjZXNzIiwiZXhwIjoxNzk3MTgwMTgwLCJpYXQiOjE3NjU2NDQxODAsImp0aSI6IjRiY2NhMjFkMzE2OTRiYjViY2Y4YTNmMzRjZTkxMDAwIiwidXNlcl9pZCI6IjEyOSJ9.X8MVrPv0HGXfDdyJBHLCbbQ9b03YtDzyKidJwuP2XTg"
async def main():
    uri = f"ws://127.0.0.1:8000/ws/location/?token={TOKEN}"
    try:
        async with websockets.connect(uri) as ws:
            print("connected")
            while True:  # persistent connection
                await ws.send(json.dumps({
                    "latitude": 23.810331,
                    "longitude": 90.412518
                }))
                print("location sent")
                
                # WebSocket থেকে রেসপন্স চেক করতে চাইলে
                try:
                    response = await asyncio.wait_for(ws.recv(), timeout=1)
                    print("response:", response)
                except asyncio.TimeoutError:
                    pass

                await asyncio.sleep(20)  # প্রতি ৫ সেকেন্ডে update
    except Exception as e:
        print("Error:", e)

asyncio.run(main())
