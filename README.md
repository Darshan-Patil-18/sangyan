# SANGYAN Shield 🛡️
### AI & Rules-Based Investor Scam & Claim Verifier for Indian Retail Investors
**Built for the SANGYAN Investor Resilience Hackathon (SEBI x NSDL x IIT BHU)**  
*Tracks A + E: Scam & Claim Verification, Behavioural Resilience, Multilingual Accessibility*

---

## 📌 Executive Summary

**Target User:** A first-time retail investor from a Tier-2 or Tier-3 city in India, who may be more comfortable in **Hindi (हिन्दी)** or **Gujarati (ગુજરાતી)** than English, operating a budget Android smartphone on low-bandwidth connectivity. They receive suspicious investment tips, "paisa double" claims, and VIP Telegram invitations on WhatsApp and need an instant, plain-language risk assessment before transferring money.

**SANGYAN Shield** provides an instantaneous, transparent, and multi-layered analysis that detects predatory patterns, checks registration claims against SEBI statutory formats, translates regulatory hazards into simple regional language explanations, and guides investors on official verification pathways.

---

## 🔒 Hackathon Guardrail Compliance Matrix

| Hackathon Hard Rule | Implementation in SANGYAN Shield | Status |
| :--- | :--- | :--- |
| **No Stock Tips / Predictions** | Strictly prohibited in both the rule engine and system prompt. Never gives buy/sell/hold ratings or target prices. | ✅ Compliant |
| **No Monetisation / Accounts** | Zero ads, no fees, no premium tiers, no user authentication or logins. | ✅ Compliant |
| **Privacy by Design (Stateless)** | **Never stores or logs** user messages, images, or IP addresses. Visible *"Nothing you enter is saved"* notice. Ephemeral rolling memory only for 1-minute rate limit. | ✅ Compliant |
| **No Live SEBI Verification Claim** | Never claims to verify registration live. Checks structural formatting (`INA`, `INH`, `INZ`) and explicitly instructs the user to cross-check on `sebi.gov.in`. | ✅ Compliant |
| **Uncertainty Communication** | Strictly avoids binary "scam / not scam". Every report contains confidence level, score (0–100), and the disclaimer: *"This is a risk indicator, not proof."* | ✅ Compliant |
| **100% Free Stack** | Python 3.11/3.13, FastAPI, OpenRouter free models (`:free` with zero prompt/completion pricing), zero paid dependencies. | ✅ Compliant |
| **Aesthetic Constraints** | Dark/Light theme with cool navy, teal, cyan, and blue-grey. **Strictly zero purple, violet, or orange**. Risk badges use green, yellow-gold, and red only. | ✅ Compliant |

---

## 🏗️ System Architecture

```mermaid
flowchart TD
    User([User: Phone / Web]) -->|Text / Compressed Screenshot / Voice| Frontend[Single-File Lightweight UI <150KB]
    Frontend -->|POST /api/analyze or /api/analyze-image| FastAPI[FastAPI Stateless Backend]
    
    subgraph Privacy & Safety Layer
        FastAPI --> RateLimiter[In-Memory Rolling Limiter: 10 req/min]
        RateLimiter --> InputSanitizer[Length & Mime Validator: Max 4000 chars / 4MB]
    end

    subgraph Core Detection Engine [rules.py - Ground Truth]
        InputSanitizer --> RulesEngine[26+ Deterministic Multilingual Rules]
        RulesEngine --> RegexScanner[Pattern Matching: EN / HI / GU / Hinglish]
        RulesEngine --> SebiFormatParser[SEBI Formats: INA, INH, INZ Check]
        RulesEngine --> WeightedScorer[Weighted Scoring & Highlighting Engine]
    end

    subgraph OpenRouter LLM Enhancement [llm.py]
        FastAPI --> ModelDiscovery[Startup & Hourly Auto-Discovery: Free :free Models]
        ModelDiscovery --> LLMEnhancer[Structured JSON Extraction with Guardrails]
        LLMEnhancer --> FallbackController{API Key / Model Available?}
        FallbackController -->|Yes (Tries up to 4 models)| OpenRouterAPI[OpenRouter Free Tier API]
        FallbackController -->|No / Timeout / 429| BaseRulesReport[Deterministic Rule-Based Report]
    end

    WeightedScorer --> ReportSynthesizer[Report Synthesizer]
    OpenRouterAPI --> ReportSynthesizer
    BaseRulesReport --> ReportSynthesizer
    ReportSynthesizer --> FrontendResult[Interactive Risk Gauge + Red Flags + Action Steps]
```

---

## 🔍 Core Detection Rules (rules.py)

SANGYAN Shield incorporates **26+ regulatory and behavioural detection rules**, covering:
1. **Guaranteed / Fixed / Daily Returns:** "100% guarantee", "fixed 5% daily", "पक्का मुनाफा", "ખાતરીપૂર્વક નફો".
2. **"Double Your Money" Schemes:** "2x in 7 days", "पैसा डबल", "25 din me paisa double", "પૈસા ડબલ".
3. **Astronomical Gains:** "1000% multibagger", "100% labh", "૧૦૦% નફો".
4. **Urgency & Artificial FOMO:** "limited seats", "last chance", "join in 10 minutes", "आखिरी मौका".
5. **Insider & Operator Tips:** "sure shot call", "operator buying leak", "ऑपरेटर कॉल", "પાકી બાતમી".
6. **Pump-and-Dump Language:** "rocket banega", "buy aggressively now", "upper circuit hit".
7. **Guaranteed Price Targets:** "target 100% achieved", "टारगेट पक्का".
8. **Unregulated Messaging Groups:** Lures to VIP Telegram or WhatsApp premium channels.
9. **Shortened & Phishing URLs:** bit.ly, tinyurl, wa.me redirects, `.xyz`, `.top`, `.vip`, lookalike broker domains.
10. **False SEBI Claims:** "SEBI approved scheme" (SEBI never approves/guarantees any return!).
11. **SEBI Registration Format Checks:** Extracts `INA` (Adviser), `INH` (Analyst), `INZ` (Broker) formats; warns that valid format does not equal genuine credentials.
12. **Credential Theft:** Requests for OTP, UPI PIN, or passwords ("enter UPI PIN to receive money").
13. **Remote-Access Malware:** Requests to install AnyDesk, TeamViewer, QuickSupport, or RustDesk.
14. **Upfront Registration Fees:** Demands for advance payments to join tips channels.
15. **Exit Extortion / Withdrawal Fees:** "Pay 20% tax to unlock profits" (pig-butchering trap).
16. **Deepfake / Celebrity Impersonations:** Fake Mukesh Ambani, Ratan Tata, or Narayana Murthy schemes.
17. **AI Trading Bot Promises:** "100% automated AI bot guaranteed profit".
18. **Misleading Demat Inducements:** Cash bonus or lottery gifts prohibited under SEBI norms.
19. **Guaranteed IPO Allotment:** "100% IPO allotment in HNI quota".
20. **Crypto / Forex Arbitrage:** Unauthorized forex portal schemes violating FEMA / RBI Alert List.
21. **Personal UPI Account Routing:** Asking for payments to individual savings handles rather than registered corporate clearing accounts.
22. **Pyramid / Multi-Level Referral:** "Refer 5 friends to earn daily".
23. **Malicious APK Downloads:** Direct installation of rogue Android `.apk` files via Telegram.
24. **Secondary Recovery Scams:** "Recover your lost scam money for a fee".
25. **Unsolicited Cold Outreach:** "Part time trading job" greetings from unknown foreign numbers.
26. **Unauthorized Account Handling:** Asking for trading account ID and password to trade on 50-50 profit sharing.

---

## 💻 Local Development Setup

### Prerequisites
- Python 3.11 or Python 3.13
- Git

### 1. Clone & Set Up Virtual Environment
```bash
git clone <repo-url>
cd static
python -m venv venv

# On Windows:
.\venv\Scripts\activate

# On Linux/macOS:
source venv/bin/activate
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Environment Variables (Optional)
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
Add your free OpenRouter API key if you want AI enhancements:
```env
OPENROUTER_API_KEY=your_openrouter_free_key_here
# Optional overrides:
TEXT_MODEL=
VISION_MODEL=
```
> **Note:** The app works **100% fully without any API key**. When no key is set, the deterministic 26+ rule engine runs transparently with full multi-lingual reporting.

### 4. Run Automated Test Suite
```bash
python -m pytest tests/test_rules.py -v
```

### 5. Launch Local Server
```bash
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```
Open your browser at `http://127.0.0.1:8000`.

---

## 🚀 Deployment on Render

This repository is configured for one-click deployment on Render's Web Service:

- **Environment:** Python
- **Build Command:** `pip install -r requirements.txt`
- **Start Command:** `uvicorn main:app --host 0.0.0.0 --port $PORT`
- **Health Check Path:** `/health`

### Environment Variables on Render:
- `OPENROUTER_API_KEY`: *(Optional)* Your OpenRouter key for free model inference.
- `TEXT_MODEL`: *(Optional)* E.g. `meta-llama/llama-3.3-70b-instruct:free`
- `VISION_MODEL`: *(Optional)* E.g. `google/gemini-2.0-flash-exp:free`

---

## ⚠️ Render Free Tier Operational Considerations & Mitigations

| Potential Free Tier Risk | Root Cause | SANGYAN Shield Mitigation |
| :--- | :--- | :--- |
| **Cold Starts (Spindown)** | Render free instances spin down after 15 minutes of inactivity. First request can take 30–50s. | `/health` responds synchronously with `{"status":"ok"}` without blocking on model discovery. Model discovery runs as an asynchronous background task. |
| **Memory Ceiling (512 MB RAM)** | Exceeding 512 MB triggers OOM crash. | Page assets are single-file inline (<75 KB total). Python memory footprint is under 60 MB. Image compression happens **client-side in Canvas** (max 1280px, JPEG 0.7) before upload. |
| **OpenRouter Free Model Rate Limits (429s)** | Free `:free` models on OpenRouter can encounter transient traffic spikes or concurrency limits. | Automatic candidate fallback pipeline (tries up to 4 distinct free models with 20s timeouts). If all free models fail, smoothly falls back to the deterministic rule report with a clear notice. |
| **Ephemeral Filesystem** | Render wipes local disk on restart. | SANGYAN Shield is **100% stateless by design**. Zero files are written to disk; rate limiting uses an in-memory timestamp queue pruned every 60s. |

---

## 🏛️ Official Indian Investor Grievance Channels

SANGYAN Shield directs investors exclusively to authentic, verified root regulatory domains:
- **Intermediary Verification:** [sebi.gov.in](https://sebi.gov.in)
- **National Cyber Crime Helpline:** Call **1930** or visit [cybercrime.gov.in](https://cybercrime.gov.in)
- **SEBI Complaints Redress System (SCORES):** [scores.sebi.gov.in](https://scores.sebi.gov.in)
- **RBI Sachet Portal:** [sachet.rbi.org.in](https://sachet.rbi.org.in)
