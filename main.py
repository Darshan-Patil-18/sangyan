"""
SANGYAN Shield Main Application (main.py)
Stateless Scam & Claim Verifier for Indian Retail Investors.
Privacy-by-Design: 100% Stateless, zero persistent storage or logging of user text or IPs.
"""

import os
import time
import base64
import asyncio
from typing import Dict, List
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException, UploadFile, File, Form, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from schemas import (
    AnalyzeRequest,
    AnalysisReport,
    ChatRequest,
    ChatResponse,
    ChatMessage,
)
from rules import build_rules_report, evaluate_rules
from llm import (
    analyze_with_llm,
    chat_with_llm,
    extract_text_from_image,
    detect_script_and_lang,
    refresh_openrouter_free_models,
)

# Load environment variables (.env) safely without reading or printing secrets
load_dotenv()

# In-memory rolling rate limiter: 10 requests/minute per client
# Holds only short-lived timestamps in RAM, never writes to disk
_rate_limits: Dict[str, List[float]] = {}
RATE_LIMIT_MAX = 10
RATE_LIMIT_WINDOW = 60.0  # seconds

MAX_TEXT_LENGTH = 4000
MAX_IMAGE_SIZE_BYTES = 4 * 1024 * 1024  # 4 MB


def is_rate_limited(client_id: str) -> bool:
    """Checks rolling rate limit and prunes old timestamps in RAM."""
    now = time.time()
    cutoff = now - RATE_LIMIT_WINDOW

    timestamps = _rate_limits.get(client_id, [])
    # Prune timestamps older than 60s
    recent = [t for t in timestamps if t > cutoff]

    if len(recent) >= RATE_LIMIT_MAX:
        _rate_limits[client_id] = recent
        return True

    recent.append(now)
    _rate_limits[client_id] = recent

    # Occasional cleanup to keep RAM tiny
    if len(_rate_limits) > 500:
        keys_to_delete = [k for k, v in _rate_limits.items() if not v or v[-1] < cutoff]
        for k in keys_to_delete:
            del _rate_limits[k]

    return False


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and hourly background refresh for OpenRouter free models."""
    try:
        await refresh_openrouter_free_models()
    except Exception:
        pass

    async def periodic_refresh():
        while True:
            await asyncio.sleep(3600)  # every 1 hour
            try:
                await refresh_openrouter_free_models()
            except Exception:
                pass

    task = asyncio.create_task(periodic_refresh())
    yield
    task.cancel()


app = FastAPI(
    title="SANGYAN Shield",
    description="Investor Scam & Claim Verifier for Indian Retail Investors",
    version="2.0.0",
    lifespan=lifespan,
    docs_url=None,  # Disabled for privacy and security
    redoc_url=None,
)

# Static files directory
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")


@app.middleware("http")
async def rate_limit_and_privacy_middleware(request: Request, call_next):
    # Pass through health and root assets
    if request.url.path in ("/health", "/", "/favicon.ico") or request.url.path.startswith("/static"):
        return await call_next(request)

    # Rate-limit by the first IP in X-Forwarded-For (fallback request.client.host)
    forwarded = request.headers.get("x-forwarded-for") or request.headers.get("X-Forwarded-For")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()
    else:
        client_ip = request.client.host if request.client else "unknown"

    if is_rate_limited(client_ip):
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={
                "error": "Rate limit exceeded (10 requests/minute). Please pause a moment before trying again.",
                "error_hi": "अनुरोध सीमा समाप्त (10 प्रति मिनट)। कृपया थोड़ी देर बाद पुनः प्रयास करें।",
                "error_gu": "વિનંતી મર્યાદા વટાવી ગઈ (૧૦ પ્રતિ મિનિટ). કૃપા કરીને થોડીવાર પછી પ્રયાસ કરો.",
                "detail": "Rate limit exceeded (10 requests/minute). Please pause a moment before trying again."
            }
        )

    response = await call_next(request)
    # Add security & privacy headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    return response


@app.get("/health")
def health():
    """Instant health check with zero external dependencies."""
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
def serve_index():
    """Serves the single-file UI."""
    index_file = os.path.join(STATIC_DIR, "index.html")
    if not os.path.exists(index_file):
        raise HTTPException(status_code=404, detail="UI index file not found")
    with open(index_file, "r", encoding="utf-8") as f:
        content = f.read()
    return HTMLResponse(content=content)


@app.post("/api/chat", response_model=ChatResponse)
async def chat_endpoint(req: ChatRequest):
    """
    Stateless chat endpoint for SANGYAN Shield.
    Accepts up to 6 turns of conversation and optional base64 image.
    Never stores or logs user messages or images.
    """
    user_messages = [m for m in req.messages if m.role == "user"]
    latest_user_text = user_messages[-1].content.strip() if user_messages else ""

    if len(latest_user_text) > MAX_TEXT_LENGTH:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Message exceeds maximum allowed character length of {MAX_TEXT_LENGTH}."
        )

    extracted_text = None
    if req.image_base64:
        try:
            b64_data = req.image_base64
            mime_type = "image/jpeg"
            if "," in b64_data:
                header, b64_data = b64_data.split(",", 1)
                if "image/png" in header:
                    mime_type = "image/png"
                elif "image/webp" in header:
                    mime_type = "image/webp"

            img_bytes = base64.b64decode(b64_data)
            if len(img_bytes) > MAX_IMAGE_SIZE_BYTES:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Image size exceeds the 4 MB limit."
                )

            extracted_text = await extract_text_from_image(img_bytes, mime_type)
            if not extracted_text or not extracted_text.strip():
                _, lang = detect_script_and_lang(latest_user_text)
                fail_msgs = {
                    "hi": "तस्वीर से टेक्स्ट नहीं पढ़ा जा सका, कृपया टेक्स्ट पेस्ट करें।",
                    "gu": "છબીમાંથી ટેક્સ્ટ વાંચી શકાયો નથી, કૃપા કરીને ટેક્સ્ટ પેસ્ટ કરો.",
                    "hinglish": "Image se text nahi padh sake, kripya text paste karein.",
                    "en": "Could not read the image, please paste the text."
                }
                return ChatResponse(
                    reply=fail_msgs.get(lang, fail_msgs["en"]),
                    risk_level="None",
                    ai_enhanced=False,
                    model_used=None
                )
        except HTTPException:
            raise
        except Exception:
            _, lang = detect_script_and_lang(latest_user_text)
            fail_msgs = {
                "hi": "तस्वीर से टेक्स्ट नहीं पढ़ा जा सका, कृपया टेक्स्ट पेस्ट करें।",
                "gu": "છબીમાંથી ટેક્સ્ટ વાંચી શકાયો નથી, કૃપા કરીને ટેક્સ્ટ પેસ્ટ કરો.",
                "hinglish": "Image se text nahi padh sake, kripya text paste karein.",
                "en": "Could not read the image, please paste the text."
            }
            return ChatResponse(
                reply=fail_msgs.get(lang, fail_msgs["en"]),
                risk_level="None",
                ai_enhanced=False,
                model_used=None
            )

    if not latest_user_text and not extracted_text:
        return ChatResponse(
            reply="Hi! I'm SANGYAN Shield. Paste any investment message or screenshot and I'll check it for you.",
            risk_level="None",
            ai_enhanced=False,
            model_used=None
        )

    # Process with LLM engine
    return await chat_with_llm(
        conversation_history=req.messages,
        latest_user_text=latest_user_text,
        extracted_image_text=extracted_text
    )


@app.post("/api/analyze", response_model=AnalysisReport)
async def analyze_message(req: AnalyzeRequest):
    """
    Analyzes an investment message or tip in English, Hindi, or Gujarati.
    Stateless processing: never logged, never stored.
    """
    clean_text = req.text.strip()
    if not clean_text:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Message text cannot be empty."
        )

    if len(clean_text) > MAX_TEXT_LENGTH:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Message exceeds maximum allowed character length of {MAX_TEXT_LENGTH}."
        )

    lang = req.lang if req.lang in ("en", "hi", "gu") else "en"

    # Step 1: Core deterministic rules evaluation
    base_report = build_rules_report(clean_text, lang)

    # Step 2: AI Enhancement via OpenRouter free models
    matched_flags, _, _, _, _ = evaluate_rules(clean_text, lang)
    final_report = await analyze_with_llm(clean_text, lang, matched_flags, base_report)

    return final_report


@app.post("/api/analyze-image", response_model=AnalysisReport)
async def analyze_screenshot(
    image: UploadFile = File(...),
    lang: str = Form(default="en")
):
    """
    Accepts an uploaded screenshot, extracts text with a free vision model,
    and processes the extracted text through the detection pipeline.
    """
    clean_lang = lang if lang in ("en", "hi", "gu") else "en"

    image_bytes = await image.read()
    if not image_bytes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded image file is empty."
        )

    if len(image_bytes) > MAX_IMAGE_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Image size exceeds the 4 MB limit."
        )

    content_type = image.content_type or "image/jpeg"
    extracted_text = await extract_text_from_image(image_bytes, content_type)

    if not extracted_text or not extracted_text.strip():
        notices = {
            "en": "Could not read the image, please paste the text.",
            "hi": "तस्वीर से टेक्स्ट नहीं पढ़ा जा सका, कृपया टेक्स्ट पेस्ट करें।",
            "gu": "છબીમાંથી ટેક્સ્ટ વાંચી શકાયો નથી, કૃપા કરીને ટેક્સ્ટ પેસ્ટ કરો.",
        }
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=notices.get(clean_lang, notices["en"])
        )

    # Process extracted text
    base_report = build_rules_report(extracted_text, clean_lang)
    matched_flags, _, _, _, _ = evaluate_rules(extracted_text, clean_lang)
    final_report = await analyze_with_llm(extracted_text, clean_lang, matched_flags, base_report)

    return final_report


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    """Safely intercepts unhandled exceptions to prevent stack traces leaking."""
    return JSONResponse(
        status_code=500,
        content={
            "error": "A temporary processing error occurred. Please try again.",
            "error_hi": "एक अस्थायी त्रुटि हुई। कृपया पुनः प्रयास करें।",
            "error_gu": "એક અસ્થાયી ક્ષતિ આવી. કૃપા કરીને ફરી પ્રયાસ કરો."
        }
    )
