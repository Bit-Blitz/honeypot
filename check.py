import os
import requests
from dotenv import load_dotenv

# Load env vars
load_dotenv()
api_key = os.getenv("GOOGLE_API_KEY")

if not api_key:
    print("❌ ERROR: No GOOGLE_API_KEY found in .env")
    exit()

print(f"🔑 Testing Key: {api_key[:10]}...")

# URL to list models directly from Google's servers
url = f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"

try:
    response = requests.get(url)
    data = response.json()
    
    if "error" in data:
        print(f"\n❌ API Error: {data['error']['message']}")
        print("This usually means the API Key is invalid or the 'Generative Language API' is not enabled in Google Cloud Console.")
    elif "models" in data:
        print("\n✅ SUCCESS! Your key works. Here are the EXACT model names you can use:")
        print("-" * 50)
        found_flash = False
        for m in data["models"]:
            # We filter for models that support 'generateContent'
            if "generateContent" in m.get("supportedGenerationMethods", []):
                print(f"MODEL ID: {m['name']}")
                if "flash" in m['name']:
                    found_flash = True
        print("-" * 50)
        
        if found_flash:
            print("\n💡 TIP: Copy one of the 'gemini-1.5-flash' names above into your nodes.py file.")
    else:
        print(f"\n⚠️ Unexpected response: {data}")

except Exception as e:
    print(f"\n❌ Connection Error: {e}")