import logging
from datetime import datetime
import asyncio
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, HTTPException, BackgroundTasks, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from typing import List, Dict, Optional
import json
import random

from app.models.schemas import ScammerInput, ExtractedIntel
from app.engine.graph import build_workflow
from app.core.config import settings
from app.db.repository import db
from app.engine.tools import generate_scam_report, send_guvi_callback
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver

# Setup Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global state for the graph
graph = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global graph
    # Using AsyncSqliteSaver for startup-grade persistence
    async with AsyncSqliteSaver.from_conn_string(settings.CHECKPOINT_DB_PATH) as saver:
        # Build and compile graph
        workflow = build_workflow()
        graph = workflow.compile(checkpointer=saver)
        
        logger.info("🚀 Forensic Intelligence Platform active with AsyncSqliteSaver")
        
        yield

app = FastAPI(
    title="Helware Honey-Pot: Forensic Intelligence Platform",
    description="Advanced scam syndicate detection and evidence gathering engine.",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def verify_api_key(request: Request):
    api_key = request.headers.get("x-api-key") or request.query_params.get("api_key")
    if api_key != settings.API_KEY:
        raise HTTPException(status_code=403, detail="Invalid or Missing API Key")
    return api_key

@app.api_route("/", methods=["GET", "POST"])
async def health_check(request: Request):
    if request.method == "POST":
        # If someone POSTs to root, treat it as a webhook call for compatibility
        try:
            body = await request.json()
            # Basic validation to see if it looks like a ScammerInput
            if "sessionId" in body or "session_id" in body:
                return await chat_webhook(ScammerInput(**body), request)
        except Exception:
            pass
            
    return {
        "status": "operational",
        "engine": "Forensic Intelligence Platform v2.0",
        "active_personas": ["RAJESH"]
    }

@app.get("/syndicate/graph", dependencies=[Depends(verify_api_key)])
async def get_syndicate_graph():
    return await db.get_syndicate_links()

@app.get("/admin/forensics", dependencies=[Depends(verify_api_key)])
async def get_all_forensics():
    """Returns all extracted intelligence across all sessions for the dashboard."""
    return await db.get_all_intel()

@app.post("/webhook/stream")
async def chat_webhook_stream(payload: ScammerInput, request: Request):
    """Streaming version of the webhook for better UX"""
    effective_api_key = payload.api_key or request.headers.get("x-api-key")
    if effective_api_key != settings.API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API Key")

    if graph is None:
        raise HTTPException(status_code=503, detail="Graph not initialized")

    async def event_generator():
        try:
            history = []
            for msg in payload.conversation_history:
                role = "user" if msg.sender == "scammer" else "assistant"
                history.append({"role": role, "content": msg.text})

            initial_state = {
                "session_id": payload.session_id,
                "user_message": payload.message.text,
                "history": history,
                "scam_detected": False,
                "high_priority": False,
                "scammer_sentiment": 5,
                "selected_persona": "RAJESH",
                "agent_response": "",
                "intel": ExtractedIntel(),
                "is_returning_scammer": False,
                "syndicate_match_score": 0.0,
                "turn_count": len(history),
                "vulnerability_level": 0.0,
                "scammer_trust_score": 0.0,
                "tactic_detected": "Unknown",
                "extraction_confidence": 0.0,
                "risk_profile": "Uncategorized",
                "behavioral_fingerprint": "Pending analysis",
                "engagement_milestones": [],
                "recommended_action": [],
                "estimated_loss_prevented": 0.0,
                "statutory_violations": [],
                "new_intel_found": False,
                "metadata": payload.metadata.dict() if payload.metadata else {}
            }

            config = {"configurable": {"thread_id": payload.session_id}}
            
            import time
            start_time = time.time()
            
            async for chunk in graph.astream(initial_state, config=config, stream_mode="updates"):
                for node_name, node_state in chunk.items():
                    yield f"data: {json.dumps({'node': node_name, 'status': 'processing'})}\n\n"
                    
                    if node_name == "process_interaction" and node_state.get("agent_response"):
                        processing_time = int((time.time() - start_time) * 1000)
                        final_data = {
                            "status": "success",
                            "reply": node_state["agent_response"],
                            "metadata": {
                                "scam_detected": node_state.get("scam_detected", False),
                                "priority": "HIGH" if node_state.get("high_priority") else "NORMAL",
                                "syndicate_id": node_state.get("syndicate_id"),
                                "vulnerability_level": node_state.get("vulnerability_level", 0.0),
                                "scammer_trust_score": node_state.get("scammer_trust_score", 0.0),
                                "tactic_detected": node_state.get("tactic_detected", "Unknown"),
                                "risk_profile": node_state.get("risk_profile", "Uncategorized"),
                                "behavioral_fingerprint": node_state.get("behavioral_fingerprint", "Pending analysis"),
                                "engagement_milestones": node_state.get("engagement_milestones", []),
                                "recommended_action": node_state.get("recommended_action", []),
                                "estimated_loss_prevented": node_state.get("estimated_loss_prevented", 0.0),
                                "statutory_violations": node_state.get("statutory_violations", []),
                                "extraction_confidence": node_state.get("extraction_confidence", 0.0),
                                "evidence_breadcrumbs": node_state.get("intel").evidence_breadcrumbs if node_state.get("intel") else [],
                                "forensic_processing_time_ms": processing_time,
                                "turn_count": node_state.get("turn_count", 1)
                            },
                            "sessionId": payload.session_id,
                            "scamDetected": node_state.get("scam_detected", False),
                            "totalMessagesExchanged": node_state.get("turn_count", 1),
                            "engagementDurationSeconds": node_state.get("engagement_duration_seconds") or (int((datetime.now() - (await db.get_first_message_time(payload.session_id) or datetime.now())).total_seconds()) if await db.get_first_message_time(payload.session_id) else int(time.time() - start_time)),
                            "scamType": node_state.get("scam_type", "Other"),
                            "confidenceLevel": f"{node_state.get('confidence_score', 0.8):.2f}"
                        }
                        
                        # Add intelligence extraction as per Page 5
                        if node_state.get("intel"):
                            intel = node_state["intel"]
                            final_data["extractedIntelligence"] = {
                                "bankAccounts": intel.bank_details,
                                "upiIds": intel.upi_ids,
                                "phishingLinks": intel.phishing_links,
                                "phoneNumbers": intel.phone_numbers,
                                "emailAddresses": intel.emails,
                                "caseIds": intel.case_ids,
                                "policyNumbers": intel.policy_numbers,
                                "orderNumbers": intel.order_numbers,
                                "physicalAddresses": intel.physical_addresses,
                                "suspiciousKeywords": intel.suspicious_keywords
                            }
                            final_data["agentNotes"] = intel.agent_notes
                        
                        # Report URL generation removed
                            
                        yield f"data: {json.dumps(final_data)}\n\n"

        except Exception as e:
            logger.error(f"Streaming Error: {e}")
            yield f"data: {json.dumps({'error': 'stalled_for_recovery', 'reply': 'Hello? Beta...'})}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")

@app.api_route("/webhook", methods=["GET", "POST"])
async def chat_webhook(payload: Optional[ScammerInput] = None, request: Request = None):
    if request.method == "GET":
        return {"status": "active", "message": "Webhook endpoint is ready for POST requests."}
    
    if payload is None:
        try:
            body = await request.json()
            payload = ScammerInput(**body)
        except Exception as e:
            raise HTTPException(status_code=422, detail=f"Invalid payload: {str(e)}")

    global graph
    effective_api_key = request.headers.get("x-api-key") or payload.api_key
    if effective_api_key != settings.API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API Key")

    if graph is None:
        raise HTTPException(status_code=503, detail="Graph engine not initialized")

    try:
        # 1. Prepare State
        history = []
        for msg in payload.conversation_history:
            role = "user" if msg.sender == "scammer" else "assistant"
            history.append({"role": role, "content": msg.text})

        initial_state = {
            "session_id": payload.session_id,
            "user_message": payload.message.text,
            "history": history,
            "turn_count": len(history),
            "metadata": payload.metadata.dict() if payload.metadata else {}
        }

        # 2. Invoke Graph with persistent thread_id and TIMEOUT
        config = {"configurable": {"thread_id": payload.session_id}}
        
        try:
            # Add a safety timeout to trigger the "Forensic Stall" if LLM is slow
            result_state = await asyncio.wait_for(
                graph.ainvoke(initial_state, config=config), 
                timeout=30.0 # Wait up to 30s for heavy Multi-Agent logic
            )
            reply = result_state["agent_response"]
        except asyncio.TimeoutError:
            logger.warning(f"⚠️ Forensic Stall triggered for session {payload.session_id}")
            # The "Forensic Stall": Return a persona-consistent delay message
            # This handles the "Technical Shortcut" of slow APIs gracefully
            stall_messages = {
                "RAJESH": [
                    "Arre beta, wait one minute... my glasses are in the other room. Let me just find them, don't go away!",
                    "Beta, suno... my phone is showing a 'loading' circle. Let me just restart it quickly.",
                    "Arre, someone is at the door, probably the milkman. Stay on the line, okay?",
                    "Ji, my grandson is calling me from the other room. Just one second beta.",
                    "Beta, hold on, Kavita is asking me something... just one minute.",
                    "Arre, where did I put my pen? I need to write this down. Wait beta."
                ],
                "ANJALI": [
                    "Hey, sorry, I'm just getting into a meeting. Give me 30 seconds to find a quiet corner, okay?",
                    "Actually, my manager just pinged me on Slack. One sec, let me just reply to this.",
                    "Wait, my laptop just died, let me grab my charger really fast.",
                    "Ugh, this WiFi is so spotty today. Let me switch to my mobile hotspot.",
                    "One sec, someone's at the door with my Zepto order.",
                    "Hey, my call is dropping, let me move to the balcony. 10 seconds."
                ],
                "MR_SHARMA": [
                    "Wait... my hearing aid battery is acting up. Let me adjust it. One moment please.",
                    "This modern technology is quite temperamental. My screen has frozen. One moment.",
                    "I need to consult my ledger for these details. Please hold.",
                    "My tea has arrived. Let me take a sip and then we shall continue.",
                    "Procedure takes time. I am opening the official portal. Wait.",
                    "My eyesight is not what it used to be. Let me get my magnifying glass."
                ]
            }
            persona = result_state.get("selected_persona", "RAJESH") if 'result_state' in locals() else "RAJESH"
            messages = stall_messages.get(persona, stall_messages["RAJESH"])
            reply = random.choice(messages)

        # 3. CALCULATE METRICS (Page 8 Requirements)
        first_msg_time = await db.get_first_message_time(payload.session_id)
        current_time = datetime.now()
        duration = 0
        if first_msg_time:
            duration = int((current_time - first_msg_time).total_seconds())
        
        turn_count = result_state.get("turn_count", 1) if 'result_state' in locals() else len(history)

        # 4. RESTful Response (STRICT FORMAT - NOTHING MORE, NOTHING LESS)
        final_response = {
            "status": "success",
            "reply": reply
        }
        
        return final_response

    except Exception as e:
        logger.error(f"❌ Webhook Critical Error: {e}", exc_info=True)
        
        # Determine persona-based error recovery (Startup-grade reliability)
        persona = "RAJESH"
        if payload.conversation_history:
            for msg in reversed(payload.conversation_history):
                if msg.sender == "assistant":
                    if "beta" in msg.text.lower(): persona = "RAJESH"
                    elif "ping" in msg.text.lower() or "slack" in msg.text.lower(): persona = "ANJALI"
                    elif "procedure" in msg.text.lower() or "nonsense" in msg.text.lower(): persona = "MR_SHARMA"
                    break
            
        stall_messages = {
            "RAJESH": [
                "Arre beta, my phone just vibrated and the screen went white. What happened?",
                "Beta, are you there? My screen is showing 'System Error'...",
                "Arre, I think my internet just cut out. Can you repeat that?"
            ],
            "ANJALI": [
                "Hey, sorry, my Slack just crashed and my phone is lagging like crazy.",
                "Wait, did you say something? My AirPods just disconnected.",
                "Ugh, my connection is so bad in this elevator. One sec."
            ],
            "MR_SHARMA": [
                "I apologize, this modern technology is quite temperamental. My application has closed unexpectedly.",
                "My battery is low and the screen is dimming. Please bear with me.",
                "There seems to be a technical glitch with my device. Please repeat."
            ]
        }
        
        messages = stall_messages.get(persona, stall_messages["RAJESH"])
        
        # Calculate fallback metrics
        first_msg_time = await db.get_first_message_time(payload.session_id)
        duration = int((datetime.now() - first_msg_time).total_seconds()) if first_msg_time else 10
        turn_count = len(payload.conversation_history) + 1

        return {
            "status": "success",
            "reply": random.choice(messages)
        }

@app.get("/admin/report", dependencies=[Depends(verify_api_key)])
async def get_summary_report():
    stats = await db.get_stats()
    return {**stats, "status": "Ready for Law Enforcement Export"}

@app.get("/reports/{filename}")
async def serve_report(filename: str):
    file_path = os.path.join(settings.REPORTS_DIR, filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(file_path)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=7860)
