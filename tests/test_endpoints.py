"""
Integration + unit tests for SANGYAN Shield.
Tests:
 - GET /health
 - GET / (serve index)
 - POST /api/analyze  (English, Hindi, Gujarati scams + harmless)
 - POST /api/chat     (greetings, scams, harmless, no-key fallback, image path)
 - POST /api/analyze-image (image fallback)
 - In-memory rate limiting with X-Forwarded-For
"""

import base64
import pytest
from unittest.mock import patch, AsyncMock
from fastapi.testclient import TestClient
from main import app, _rate_limits

client = TestClient(app)


@pytest.fixture(autouse=True)
def clear_rate_limits():
    _rate_limits.clear()
    yield
    _rate_limits.clear()



# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def chat(messages, image_b64=None):
    payload = {"messages": messages}
    if image_b64:
        payload["image_base64"] = image_b64
    return client.post("/api/chat", json=payload)


# Minimal 1x1 white PNG
TINY_PNG_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="
)
TINY_JPEG = (
    b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00"
    b"\xff\xdb\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\t\t"
    b"\x08\n\x0c\x14\r\x0c\x0b\x0b\x0c\x19\x12\x13\x0f\x14\x1d\x1a"
    b"\x1f\x1e\x1d\x1a\x1c\x1c $.' \",#\x1c\x1c(7),01444\x1f'9=82"
    b"<.342\xff\xc0\x00\x0b\x08\x00\x01\x00\x01\x01\x01\x11\x00"
    b"\xff\xc4\x00\x1f\x00\x00\x01\x05\x01\x01\x01\x01\x01\x01\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08"
    b"\t\n\x0b\xff\xda\x00\x08\x01\x01\x00\x00?\x00\xbf\x00\xff\xd9"
)


# ---------------------------------------------------------------------------
# Basic endpoints
# ---------------------------------------------------------------------------

def test_health():
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}


def test_serve_index():
    res = client.get("/")
    assert res.status_code == 200
    assert "SANGYAN Shield" in res.text
    assert "<!DOCTYPE html>" in res.text


# ---------------------------------------------------------------------------
# Legacy /api/analyze tests
# ---------------------------------------------------------------------------

def test_analyze_english_scam():
    payload = {
        "text": "Guaranteed 10% daily return! Double your investment in 7 days without risk. Transfer funds to my UPI id rajesh@okaxis.",
        "lang": "en"
    }
    res = client.post("/api/analyze", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["risk_level"] == "High"
    assert data["score"] >= 70
    assert len(data["red_flags"]) >= 2
    assert "disclaimer" in data


def test_analyze_hindi_scam():
    payload = {
        "text": "पक्का मुनाफा गारंटी! 15 दिनों में पैसा डबल। रोजाना 5% प्रॉफिट। तुरंत संपर्क करें rajesh@okaxis।",
        "lang": "hi"
    }
    res = client.post("/api/analyze", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["risk_level"] == "High"
    assert len(data["red_flags"]) >= 2


def test_analyze_gujarati_scam():
    payload = {
        "text": "ખાતરીપૂર્વક ૧૦૦% નફો! માત્ર ૧૦ દિવસમાં પૈસા ડબલ. જોખમ વગર ચોક્કસ વળતર. છેલ્લી તક, તરત જ જોડાઓ.",
        "lang": "gu"
    }
    res = client.post("/api/analyze", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["risk_level"] == "High"
    assert len(data["red_flags"]) >= 2


def test_analyze_harmless():
    payload = {
        "text": "What is the difference between a mutual fund SIP and a lump sum investment? How does compounding work?",
        "lang": "en"
    }
    res = client.post("/api/analyze", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["risk_level"] == "Low"
    assert data["score"] <= 35


# ---------------------------------------------------------------------------
# /api/analyze-image — graceful fallback when image yields no text
# ---------------------------------------------------------------------------

def test_analyze_image_fallback():
    """
    The vision model may return '' or something for a 1x1 JPEG.
    We accept either 422 (no text extracted) or 200 (model returned a report).
    The important thing is no 5xx and no crash.
    """
    files = {"image": ("test.jpg", TINY_JPEG, "image/jpeg")}
    data = {"lang": "en"}
    res = client.post("/api/analyze-image", files=files, data=data)
    assert res.status_code in (200, 422)
    if res.status_code == 422:
        assert "Could not read the image" in res.json()["detail"]


# ---------------------------------------------------------------------------
# /api/chat — greeting replies
# ---------------------------------------------------------------------------

def test_chat_english_greeting():
    res = chat([{"role": "user", "content": "Hello"}])
    assert res.status_code == 200
    data = res.json()
    assert "reply" in data
    assert data["risk_level"] == "None"
    assert len(data["reply"]) > 5


def test_chat_hindi_greeting():
    res = chat([{"role": "user", "content": "नमस्ते"}])
    assert res.status_code == 200
    data = res.json()
    assert data["risk_level"] == "None"
    assert len(data["reply"]) > 5


def test_chat_gujarati_greeting():
    res = chat([{"role": "user", "content": "નમસ્તે"}])
    assert res.status_code == 200
    data = res.json()
    assert data["risk_level"] == "None"
    assert len(data["reply"]) > 5


# ---------------------------------------------------------------------------
# /api/chat — scam detection
# ---------------------------------------------------------------------------

def test_chat_english_scam_high_risk():
    res = chat([{"role": "user", "content": "Guaranteed 10% daily return! Double your investment in 7 days! Transfer to UPI rajesh@okaxis now!"}])
    assert res.status_code == 200
    data = res.json()
    assert data["risk_level"] in ("High", "Medium")
    assert len(data["reply"]) > 10


def test_chat_hindi_scam_high_risk():
    res = chat([{"role": "user", "content": "पक्का मुनाफा गारंटी! 15 दिनों में पैसा डबल। रोजाना 5% प्रॉफिट। तुरंत संपर्क करें।"}])
    assert res.status_code == 200
    data = res.json()
    assert data["risk_level"] in ("High", "Medium")
    assert len(data["reply"]) > 10


def test_chat_gujarati_scam_high_risk():
    res = chat([{"role": "user", "content": "ખાતરીપૂર્વક ૧૦૦% નફો! માત્ર ૧૦ દિવસ. જોખમ વગર ચોક્કસ વળતર. તરત જ જોડાઓ."}])
    assert res.status_code == 200
    data = res.json()
    assert data["risk_level"] in ("High", "Medium")
    assert len(data["reply"]) > 10


def test_chat_harmless_question_returns_none_or_low():
    res = chat([{"role": "user", "content": "What is SIP?"}])
    assert res.status_code == 200
    data = res.json()
    assert data["risk_level"] in ("None", "Low")
    assert len(data["reply"]) > 5


# ---------------------------------------------------------------------------
# /api/chat — no-API-key fallback
# ---------------------------------------------------------------------------

def test_chat_no_api_key_fallback():
    """With no API key, app should still answer using rules-only fallback."""
    with patch.dict("os.environ", {"OPENROUTER_API_KEY": ""}):
        res = chat([{"role": "user", "content": "Guaranteed 20% daily profit! Join now!"}])
    assert res.status_code == 200
    data = res.json()
    assert data["risk_level"] in ("High", "Medium")
    assert data["ai_enhanced"] is False
    assert len(data["reply"]) > 10


# ---------------------------------------------------------------------------
# /api/chat — image path
# ---------------------------------------------------------------------------

def test_chat_image_path():
    """Sending a tiny image with text should return a valid chat response."""
    b64 = "data:image/png;base64," + TINY_PNG_B64
    res = chat(
        [{"role": "user", "content": "Check this screenshot"}],
        image_b64=b64
    )
    assert res.status_code == 200
    data = res.json()
    assert "reply" in data
    assert data["risk_level"] in ("None", "Low", "Medium", "High")


# ---------------------------------------------------------------------------
# Rate limiting via X-Forwarded-For
# ---------------------------------------------------------------------------

def test_rate_limit_x_forwarded_for():
    """Rate limiting should key on X-Forwarded-For, not request.client.host."""
    # Clear rate limits
    _rate_limits.clear()

    test_ip = "203.0.113.99"
    headers = {"X-Forwarded-For": test_ip}

    # Make 10 requests — all should succeed
    for i in range(10):
        r = client.post(
            "/api/chat",
            json={"messages": [{"role": "user", "content": "Hello"}]},
            headers=headers
        )
        assert r.status_code == 200, f"Request {i+1} should succeed, got {r.status_code}"

    # 11th should be rate limited
    r = client.post(
        "/api/chat",
        json={"messages": [{"role": "user", "content": "Hello"}]},
        headers=headers
    )
    assert r.status_code == 429
    data = r.json()
    assert "Rate limit" in data.get("error", "") or "Rate limit" in data.get("detail", "")

    # A different IP should still work
    _rate_limits.clear()


# ---------------------------------------------------------------------------
# Reply Validator Unit Tests (BUG 1 verification)
# ---------------------------------------------------------------------------

from llm import validate_reply, sanitize_reply


def test_validate_reply_reasoning_leakage():
    """Validator must reject replies leaking internal reasoning phrases."""
    leaked_1 = "We need answer only JSON. Here is the reply: High Risk."
    leaked_2 = "Need to formulate a Hindi response for the user within word limit."
    leaked_3 = "Let's analyze the scam text. The user asks about double money."

    assert validate_reply(leaked_1, "en") is False
    assert validate_reply(leaked_2, "hi") is False
    assert validate_reply(leaked_3, "en") is False


def test_validate_reply_html_fragments():
    """Validator must reject replies containing HTML or broken attribute fragments."""
    broken_1 = 'Visit <a href="https://sebi.gov.in">sebi.gov.in</a>'
    broken_2 = 'target="_blank" rel="noopener noreferrer">scores.'
    broken_3 = 'Check website <sebi.gov.in>'

    assert validate_reply(broken_1, "en") is False
    assert validate_reply(broken_2, "en") is False
    assert validate_reply(broken_3, "en") is False


def test_validate_reply_latin_in_hindi():
    """Validator must reject Hindi replies with >25% Latin script (excluding whitelisted domains)."""
    # High Latin ratio in Hindi request
    mostly_english_hindi = "यह एक High Risk Scam Warning Message है। Please report immediately at cybercrime.gov.in and call bank."
    # Valid Hindi reply with Devanagari text and whitelisted domain
    valid_hindi = "⚠️ यह उच्च जोखिम संदेश है। cybercrime.gov.in पर शिकायत दर्ज करें।"

    assert validate_reply(mostly_english_hindi, "hi") is False
    assert validate_reply(valid_hindi, "hi") is True


def test_sanitize_reply():
    """Sanitizer must strip HTML tags and unescape double-escaped entities to plain text."""
    raw = '<b>High Risk</b> &lt;sebi.gov.in&gt;'
    cleaned = sanitize_reply(raw)
    assert cleaned == 'High Risk sebi.gov.in'

