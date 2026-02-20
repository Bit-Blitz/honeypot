from langgraph.graph import StateGraph, END
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
from app.engine.nodes import (
    AgentState, load_history, detect_scam, 
    extract_forensics, save_state, finalize_report,
    enrich_intel, fingerprint_scammer, submit_to_blacklist,
    guvi_reporting
)

def route_after_detection(state: AgentState):
    """
    Dynamic routing for True Agency:
    - If High Priority Intel detected: Skip small talk, go straight to forensics & enrichment.
    - If Scam detected: Go to forensics.
    - Otherwise: Persist state and wait for next message.
    """
    if state.get("high_priority"):
        return "extract_forensics"
    if state.get("scam_detected"):
        return "extract_forensics"
    return "persist_state"

def should_trigger_reporting(state: AgentState):
    """
    Only report to GUVI if:
    1. We reached the target turn count (10)
    2. The scammer has quit (Sentiment < 2)
    This prevents 'partial score overwrites' and confusion.
    """
    turn_count = state.get("turn_count", 0)
    sentiment = state.get("scammer_sentiment", 5)
    
    if turn_count >= 10 or sentiment < 2:
        return "guvi_reporting"
    return END

def build_workflow():
    workflow = StateGraph(AgentState)

    workflow.add_node("load_history", load_history)
    workflow.add_node("process_interaction", detect_scam)
    workflow.add_node("extract_forensics", extract_forensics)
    workflow.add_node("enrich_intelligence", enrich_intel)
    workflow.add_node("fingerprint_scammer", fingerprint_scammer)
    workflow.add_node("submit_to_blacklist", submit_to_blacklist)
    workflow.add_node("persist_state", save_state)
    workflow.add_node("guvi_reporting", guvi_reporting)

    workflow.set_entry_point("load_history")
    
    workflow.add_edge("load_history", "process_interaction")
    
    # Conditional Edge: Decide path based on detection
    workflow.add_conditional_edges(
        "process_interaction",
        route_after_detection,
        {
            "extract_forensics": "extract_forensics",
            "enrich_intelligence": "enrich_intelligence",
            "persist_state": "persist_state"
        }
    )
    
    workflow.add_edge("extract_forensics", "enrich_intelligence")
    workflow.add_edge("enrich_intelligence", "fingerprint_scammer")
    workflow.add_edge("fingerprint_scammer", "submit_to_blacklist")
    workflow.add_edge("submit_to_blacklist", "persist_state")
    
    # Conditional Reporting Logic
    workflow.add_conditional_edges(
        "persist_state",
        should_trigger_reporting,
        {
            "guvi_reporting": "guvi_reporting",
            END: END
        }
    )
    
    workflow.add_edge("guvi_reporting", END)

    return workflow