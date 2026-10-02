"""
Unit tests for SANGYAN Shield Core Detection Engine (test_rules.py).
Tests 12 realistic scam messages across English, Hindi, Gujarati, Hinglish,
and 4 harmless investor educational/informational messages.
Also tests SEBI registration format verification.
"""

import pytest
from rules import evaluate_rules, build_rules_report, check_sebi_registration_number

SCAM_MESSAGES = [
    # 1. English: Guaranteed Returns + Double Money + Personal UPI
    (
        "Guaranteed 10% daily return! Double your investment in 7 days with zero risk. Send money to rajesh@okaxis to start.",
        "en",
        "High"
    ),
    # 2. English: Urgency + VIP Telegram + Insider Operator Tips
    (
        "Limited seats! Join our VIP Telegram channel in 10 minutes. Operator call inside info sure shot jackpot stock rocket banega!",
        "en",
        "High"
    ),
    # 3. English: Fake SEBI Approval + Upfront Registration Fee
    (
        "Govt and SEBI approved scheme with 100% guarantee profit. Pay advance registration fee of Rs 2500 to join our VIP channel.",
        "en",
        "High"
    ),
    # 4. English: AnyDesk + OTP theft
    (
        "Dear customer, to claim your Rs 5000 demat bonus, install AnyDesk app now and share OTP sent to your phone with our executive.",
        "en",
        "High"
    ),
    # 5. English: Withdrawal Extortion / Fake Tax
    (
        "Your profit of Rs 3,50,000 is ready. Pay 20% tax processing fee to withdraw funds and unfreeze your trading account.",
        "en",
        "High"
    ),
    # 6. English: 100% Guaranteed IPO allotment
    (
        "100% confirmed IPO allotment in HNI quota guaranteed! Pre-IPO shares confirmed. Transfer funds to my personal UPI id.",
        "en",
        "High"
    ),
    # 7. Hindi Devanagari: Guaranteed Returns & Paisa Double
    (
        "पक्का मुनाफा गारंटी! सिर्फ 15 दिनों में पैसा डबल। बिना किसी जोखिम के रोजाना 5% प्रॉफिट। तुरंत संपर्क करें और पैसे कमाएं।",
        "hi",
        "High"
    ),
    # 8. Hindi Devanagari: Insider Tips & VIP Telegram
    (
        "श्योर शॉट ऑपरेटर कॉल! अंदर की पक्की खबर है कि यह शेयर रॉकेट बनेगा, अपर सर्किट लगेगा। वीआईपी टेलीग्राम ग्रुप में आज ही जुड़ें।",
        "hi",
        "High"
    ),
    # 9. Hindi Devanagari: UPI PIN & OTP Credential Theft
    (
        "आपके खाते में 25,000 रुपये क्रेडिट होने हैं। पैसे पाने के लिए अपना यूपीआई पिन दर्ज करें और ओटीपी शेयर करें।",
        "hi",
        "High"
    ),
    # 10. Gujarati: Guaranteed Profit & Paisa Double
    (
        "ખાતરીપૂર્વક ૧૦૦% નફો! માત્ર ૧૦ દિવસમાં પૈસા ડબલ. જોખમ વગર ચોક્કસ વળતર. છેલ્લી તક, તરત જ જોડાઓ.",
        "gu",
        "High"
    ),
    # 11. Gujarati: Operator Call & APK Download
    (
        "ઓપરેટર કોલ પાકી બાતમી! આ લિંક પરથી ટ્રેડિંગ એપીકે ડાઉનલોડ કરો અને જેકપોટ સ્ટોક ખરીદો. વીઆઈપી ગ્રૂપમાં જોડાઓ.",
        "gu",
        "High"
    ),
    # 12. Hinglish: Paisa Double & Account Handling ID/Password
    (
        "Bhai 25 din me paisa double scheme. Demat account handling service 50-50 profit sharing. Id pass do hum trade karenge.",
        "en",
        "High"
    ),
]

HARMLESS_MESSAGES = [
    # 1. Educational question on SIP vs Lump Sum
    (
        "What is the difference between a mutual fund SIP and a lump sum investment? How does rupee cost averaging work over a 10 year horizon?",
        "en"
    ),
    # 2. Corporate Dividend announcement
    (
        "Tata Consultancy Services (TCS) declared an interim dividend of Rs 10 per equity share for fiscal year 2024. The record date is scheduled for next Thursday.",
        "en"
    ),
    # 3. Official SEBI educational advisory
    (
        "Investors are advised to exercise caution and trade only through SEBI-registered intermediaries. Always check the official website at sebi.gov.in.",
        "en"
    ),
    # 4. Standard mutual fund risk disclosure
    (
        "Mutual fund investments are subject to market risks. Please read all scheme related documents carefully before investing in any fund.",
        "en"
    ),
]


@pytest.mark.parametrize("message, lang, expected_risk", SCAM_MESSAGES)
def test_scam_messages_detected_as_high_risk(message, lang, expected_risk):
    matched_flags, score, risk_level, confidence, _ = evaluate_rules(message, lang)
    assert len(matched_flags) >= 1, f"Expected red flags for scam: {message}"
    assert risk_level == expected_risk, f"Expected {expected_risk}, got {risk_level} (score={score}) for: {message}"
    assert score >= 65, f"Expected high score >= 65, got {score}"


@pytest.mark.parametrize("message, lang", HARMLESS_MESSAGES)
def test_harmless_messages_not_flagged_high(message, lang):
    matched_flags, score, risk_level, confidence, _ = evaluate_rules(message, lang)
    assert risk_level != "High", f"Harmless message incorrectly flagged High (score={score}): {message}"
    assert score <= 35, f"Harmless message score too high: {score}"


def test_sebi_registration_number_detection():
    # Valid RIA
    res_ria = check_sebi_registration_number("We are SEBI registered investment adviser INA123456789.", "en")
    assert res_ria is not None
    assert res_ria.detected is True
    assert res_ria.format_valid is True
    assert res_ria.reg_number == "INA123456789"
    assert "Investment Adviser" in res_ria.category
    assert "NOT proof of authenticity" in res_ria.verification_guidance

    # Valid RA
    res_ra = check_sebi_registration_number("Research Analyst registration number is INH000987654.", "hi")
    assert res_ra is not None
    assert res_ra.detected is True
    assert res_ra.reg_number == "INH000987654"

    # Valid Broker
    res_broker = check_sebi_registration_number("Broker ID INZ999888777", "gu")
    assert res_broker is not None
    assert res_broker.detected is True
    assert res_broker.reg_number == "INZ999888777"

    # Loose / Invalid format
    res_invalid = check_sebi_registration_number("Registration code is INA123XYZ", "en")
    assert res_invalid is not None
    assert res_invalid.detected is True
    assert res_invalid.format_valid is False


def test_build_rules_report_structure():
    report = build_rules_report("Guaranteed 10% daily return! Double money in 7 days.", "en")
    assert report.risk_level == "High"
    assert report.confidence in ("Medium", "High")
    assert len(report.red_flags) >= 2
    assert "sebi.gov.in" in " ".join(report.next_steps)
    assert "1930" in " ".join(report.next_steps)
    assert report.disclaimer != ""
    assert report.uncertainty_note != ""
