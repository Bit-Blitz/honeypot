from pydantic import BaseModel, Field, ConfigDict, AliasChoices
from typing import List, Dict, Optional, Any

class Message(BaseModel):
    sender: str
    text: str
    timestamp: Optional[int] = None

class Metadata(BaseModel):
    channel: Optional[str] = "SMS"
    language: Optional[str] = "English"
    locale: Optional[str] = "IN"

class ScammerInput(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    api_key: Optional[str] = Field(None, alias="apiKey") 
    session_id: str = Field(..., alias="sessionId")
    message: Message
    conversation_history: List[Message] = Field(default=[], alias="conversationHistory")
    metadata: Optional[Metadata] = Field(default_factory=Metadata)
    
    # Internal flags removed as per request
class ExtractedIntel(BaseModel):
    upi_ids: List[str] = []
    bank_details: List[str] = []
    ifsc_codes: List[str] = []
    emails: List[str] = []
    phone_numbers: List[str] = []
    crypto_wallets: List[str] = []
    phishing_links: List[str] = []
    physical_addresses: List[str] = []
    suspicious_keywords: List[str] = [] 
    
    # NEW: Requirements from Feb 19 Documentation
    case_ids: List[str] = []
    policy_numbers: List[str] = []
    order_numbers: List[str] = []
    
    agent_notes: Optional[str] = None 
    extraction_confidence: float = 0.0
    risk_profile: Optional[str] = "ANALYZING_BEHAVIOR"
    tactic_detected: Optional[str] = "IDENTIFYING_TACTIC"
    behavioral_fingerprint: Optional[str] = "FINGERPRINT_PENDING"
    evidence_breadcrumbs: List[Dict[str, str]] = []
    recommended_actions: List[Dict[str, Any]] = [] # New structured field
    estimated_loss_prevented: float = 0.0
    confidence_score: float = 0.0
    scam_type: Optional[str] = "Unknown" # Align with page 8 reqs

class AgentResponse(BaseModel):
    status: str = "success"
    reply: str
    metadata: Optional[Dict] = None # Added for syndicate scoring/extra info

class CallbackPayload(BaseModel):
    sessionId: str
    scamDetected: bool
    totalMessagesExchanged: int
    extractedIntelligence: Dict[str, List[str]]
    agentNotes: str