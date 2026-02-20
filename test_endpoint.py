import uuid
import json
import asyncio
import httpx
from app.main import app

async def run_tests():
    print("🚀 Running Startup-Grade REST API Verification (FastAPI)...")
    
    # API KEY for authentication
    API_KEY = "ScamPatch_ftw2026Guvi"
    HEADERS = {"x-api-key": API_KEY}

    # Use httpx with ASGITransport for modern testing
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        # 1. Health Check
        try:
            response = await client.get("/")
            assert response.status_code == 200
            print("✅ Health Check Passed")
        except Exception as e:
            print(f"❌ Health Check Failed: {e}")

        # 2. Admin Report
        try:
            response = await client.get("/admin/report", headers=HEADERS)
            assert response.status_code == 200
            print("✅ Admin Auth & Persistence Passed")
        except Exception as e:
            print(f"❌ Admin Report Failed: {e}")

        # 2.1 Syndicate Graph
        try:
            response = await client.get("/syndicate/graph", headers=HEADERS)
            assert response.status_code == 200
            data = response.json()
            assert "nodes" in data
            print("✅ Syndicate Graph API Passed")
        except Exception as e:
            print(f"❌ Syndicate Graph Failed: {e}")

        # 3. Webhook (Agentic Loop - First Message)
        try:
            session_id = f"test_{uuid.uuid4().hex[:8]}"
            payload = {
                "sessionId": session_id,
                "message": {
                    "sender": "scammer",
                    "text": "Your bank account will be blocked today. Verify immediately.",
                    "timestamp": 1770005528731
                },
                "conversationHistory": [],
                "apiKey": API_KEY
            }
            
            print(f"   📤 Sending First Message: {payload['message']['text']}")
            response = await client.post("/webhook", json=payload, headers=HEADERS)
            
            if response.status_code != 200:
                print(f"❌ Webhook failed with status {response.status_code}: {response.text}")
            else:
                data = response.json()
                assert data["status"] == "success"
                print("✅ First Message Loop Passed")
                print(f"   🤖 Agent Reply: {data['reply']}")

            # 4. Webhook (Follow-up Message)
            follow_up_payload = {
                "sessionId": session_id,
                "message": {
                    "sender": "scammer",
                    "text": "Share your UPI ID to avoid account suspension.",
                    "timestamp": 1770005528731
                },
                "conversationHistory": [
                    {
                        "sender": "scammer",
                        "text": "Your bank account will be blocked today. Verify immediately.",
                        "timestamp": 1770005528731
                    },
                    {
                        "sender": "user",
                        "text": data["reply"],
                        "timestamp": 1770005528731
                    }
                ],
                "apiKey": API_KEY
            }

            print(f"   📤 Sending Follow-up Message: {follow_up_payload['message']['text']}")
            response = await client.post("/webhook", json=follow_up_payload, headers=HEADERS)
            
            if response.status_code != 200:
                print(f"❌ Follow-up Webhook failed: {response.text}")
            else:
                data = response.json()
                assert data["status"] == "success"
                print("✅ Follow-up Message Loop Passed")
                print(f"   🤖 Agent Reply: {data['reply']}")
                
                if "metadata" in data:
                    print(f"   📊 Syndicate Score: {data['metadata'].get('syndicate_score', 0)}")
                    print(f"   🔍 Scam Detected: {data['metadata'].get('scam_detected')}")
        except Exception as e:
            print(f"❌ Webhook Test Error: {e}")

    print("\n🎉 PROJECT STATUS: EVALUATION READY")

if __name__ == "__main__":
    asyncio.run(run_tests())
