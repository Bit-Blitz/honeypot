import requests
import uuid
import json
import time

def run_simulation():
    session_id = f"sim_{uuid.uuid4().hex[:6]}"
    url = "http://localhost:8000/webhook"
    
    print("="*50)
    print(f"🕵️  Honeypot Simulation Started (Session: {session_id})")
    print("Type 'exit' to end or 'report' to toggle PDF generation.")
    print("="*50)
    
    generate_report = False

    while True:
        user_input = input("\n😈 Scammer: ")
        
        if user_input.lower() == 'exit':
            break
        if user_input.lower() == 'report':
            generate_report = not generate_report
            print(f"📊 PDF Report Generation: {'ON' if generate_report else 'OFF'}")
            continue

        payload = {
            "session_id": session_id,
            "message": user_input,
            "generate_report": generate_report
        }

        try:
            start_time = time.time()
            response = requests.post(url, json=payload)
            elapsed = time.time() - start_time
            
            if response.status_code == 200:
                data = response.json()
                
                # Print Agent Response
                print(f"\n🤖 Agent ({data.get('metrics', {}).get('selected_persona', 'Rajesh')}): {data['response']}")
                
                # Print Forensics if detected
                if data['scam_detected']:
                    print("\n🚨 [SCAM DETECTED]")
                    intel = data['extracted_intelligence']
                    if any([intel['upi_ids'], intel['bank_details'], intel['phishing_links']]):
                        print(f"   📍 Intel: {json.dumps(intel, indent=2)}")
                
                # Print Metrics
                metrics = data.get('metrics', {})
                print(f"\n📈 Metrics: Turns={metrics.get('conversation_turns')} | Frustration={metrics.get('scammer_frustration')}/10 | Match={metrics.get('syndicate_match')}%")
                
                if data.get('report_url'):
                    print(f"📄 Report: http://localhost:8000{data['report_url']}")
                
                print(f"⏱️  Latency: {elapsed:.2f}s")
                
            else:
                print(f"❌ Error: {response.status_code} - {response.text}")
                
        except Exception as e:
            print(f"💥 Failed to connect: {e}")

if __name__ == "__main__":
    run_simulation()
