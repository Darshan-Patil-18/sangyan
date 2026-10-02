"""
Pydantic schemas for SANGYAN Shield.
Defines input and output structures for scam and claim analysis.
"""
from typing import List, Literal, Optional
from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=4000, description="The message or tip text to analyze")
    lang: Literal["en", "hi", "gu"] = Field(default="en", description="Target language: en, hi, or gu")


class RedFlag(BaseModel):
    rule_id: str = Field(..., description="Matched rule identifier")
    title: str = Field(..., description="Short title of the red flag")
    why_it_matters: str = Field(..., description="Plain-language explanation of the danger")
    evidence_quote: str = Field(..., description="Exact phrase or excerpt detected from input")
    severity: Literal["low", "medium", "high"] = Field(..., description="Severity level")


class ClaimEvidence(BaseModel):
    claim: str = Field(..., description="Extracted claim from message")
    evidence_status: Literal["verifiable", "unverifiable", "contradicted"] = Field(
        ..., description="Verification status of the claim"
    )
    note: str = Field(..., description="Plain-language context or instruction")


class HighlightSpan(BaseModel):
    text: str
    is_flagged: bool
    rule_id: Optional[str] = None
    severity: Optional[Literal["low", "medium", "high"]] = None


class SebiCheckResult(BaseModel):
    detected: bool = False
    reg_number: Optional[str] = None
    category: Optional[str] = None
    format_valid: bool = False
    verification_guidance: str = ""


class AnalysisReport(BaseModel):
    risk_level: Literal["Low", "Medium", "High"]
    confidence: Literal["Low", "Medium", "High"]
    score: int = Field(..., ge=0, le=100, description="Risk score 0-100")
    summary: str
    red_flags: List[RedFlag] = Field(default_factory=list)
    things_that_look_ok: List[str] = Field(default_factory=list)
    uncertainty_note: str
    promotion_vs_education: Literal["education", "mixed", "promotion"]
    claim_evidence: List[ClaimEvidence] = Field(default_factory=list)
    next_steps: List[str] = Field(default_factory=list)
    highlighted_spans: List[HighlightSpan] = Field(default_factory=list)
    sebi_registration_check: Optional[SebiCheckResult] = None
    ai_enhanced: bool = False
    ai_note: Optional[str] = None
    disclaimer: str = "This is a risk indicator, not proof. Always verify intermediaries independently on sebi.gov.in."


class LLMStructuredOutput(BaseModel):
    """Schema expected from LLM JSON response"""
    risk_level: Literal["Low", "Medium", "High", "None"] = "None"
    confidence: Literal["Low", "Medium", "High"] = "Medium"
    red_flags: List[dict] = Field(default_factory=list)
    things_that_look_ok: List[str] = Field(default_factory=list)
    uncertainty_note: str = ""
    promotion_vs_education: Literal["education", "mixed", "promotion"] = "education"
    claim_evidence: List[dict] = Field(default_factory=list)
    next_steps: List[str] = Field(default_factory=list)


class LLMChatOutput(BaseModel):
    """Schema for chat endpoint responses"""
    intent: Literal["greeting", "question", "check_message", "image"] = "check_message"
    risk_level: Literal["Low", "Medium", "High", "None"] = "None"
    reply: str


class ChatMessage(BaseModel):
    role: Literal["user", "assistant", "system"] = "user"
    content: str = ""


class ChatRequest(BaseModel):
    messages: List[ChatMessage] = Field(default_factory=list)
    image_base64: Optional[str] = None


class ChatResponse(BaseModel):
    reply: str
    risk_level: Literal["Low", "Medium", "High", "None"]
    intent: Literal["greeting", "question", "check_message", "image"] = "check_message"
    ai_enhanced: bool = False
    model_used: Optional[str] = None


