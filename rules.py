"""
SANGYAN Shield Core Detection Engine (rules.py)
Contains 26+ expert rules for detecting financial scams and misleading claims in
English, Hindi (Devanagari + romanized Hinglish), and Gujarati.
Stateless and privacy-preserving.
"""

import re
from typing import List, Dict, Any, Tuple, Optional
from schemas import RedFlag, ClaimEvidence, HighlightSpan, SebiCheckResult, AnalysisReport

# SEBI Registration patterns:
# RIA: Investment Adviser (INA + 9 digits)
# RA: Research Analyst (INH + 9 digits)
# Stock Broker: (INZ + 9 digits)
SEBI_REG_REGEX = re.compile(r'\b(IN[AHZ])\s*(\d{9})\b', re.IGNORECASE)
SEBI_LOOSE_REGEX = re.compile(r'\b(IN[AHZ][A-Z0-9]{6,12})\b', re.IGNORECASE)

RULES_DATABASE: List[Dict[str, Any]] = [
    {
        "id": "R_GUARANTEED_RETURNS",
        "severity": "high",
        "weight": 30,
        "category": "Returns & Guarantees",
        "patterns": [
            r"\b(guaranteed\s*(returns?|profit|income|payouts?))\b",
            r"\b(fixed\s*(daily|monthly|weekly|annual)\s*(return|profit|income))\b",
            r"\b(100%\s*(guarantee|profit|return|safe))\b",
            r"\b(zero\s*risk|risk[\s-]free|loss[\s-]free|no\s*loss\s*guarantee)\b",
            r"\b(assured\s*(return|gain|profit))\b",
            # Hindi Devanagari
            r"(पक्का\s*(मुनाफा|लाभ|रिटर्न))",
            r"(निश्चित\s*(रिटर्न|मुनाफा|आय))",
            r"(गारंटीड\s*(प्रॉफिट|रिटर्न))",
            r"(बिना\s*किसी\s*जोखिम|जीरो\s*रिस्क|नुकसान\s*की\s*कोई\s*संभावना\s*नहीं)",
            # Hinglish
            r"\b(pakka\s*(munafa|profit|return))\b",
            r"\b(nischit\s*(return|munafa))\b",
            r"\b(bina\s*risk|zero\s*risk|loss\s*free|guarantee\s*profit)\b",
            # Gujarati
            r"(ખાતરીપૂર્વક\s*(નફો|વળતર|આવક))",
            r"(ચોક્કસ\s*(વળતર|નફો))",
            r"(જોખમ\s*મુક્ત|ઝીરો\s*રિસ્ક|ખોટ\s*વગર)",
        ],
        "title": {
            "en": "Guaranteed or Risk-Free Returns Claimed",
            "hi": "गारंटीड या जोखिम-मुक्त रिटर्न का दावा",
            "gu": "ખાતરીપૂર્વક અથવા જોખમ-મુક્ત વળતરનો દાવો",
        },
        "explanation": {
            "en": "In stock markets, no one can legally or realistically guarantee returns. SEBI regulations strictly prohibit guaranteed return promises. Any guarantee is a major hallmark of fraud.",
            "hi": "शेयर बाजार में कोई भी कानूनी या वास्तविक रूप से निश्चित रिटर्न की गारंटी नहीं दे सकता। सेबी (SEBI) के नियमों में गारंटीड रिटर्न का वादा पूरी तरह गैरकानूनी है।",
            "gu": "શેરબજારમાં કોઈ પણ કાનૂની અથવા વાસ્તવિક રીતે ચોક્કસ વળતરની ખાતરી આપી શકતું નથી. સેબીના નિયમો અનુસાર ખાતરીપૂર્વક વળતરનું વચન આપવું ગેરકાયદેસર છે.",
        },
    },
    {
        "id": "R_DOUBLE_MONEY",
        "severity": "high",
        "weight": 35,
        "category": "Ponzi & Doubling Claims",
        "patterns": [
            r"\b(double\s*(your\s*)?(money|investment|capital|funds?))\b",
            r"\b(2x\s*(return|in\s*\d+|within\s*\d+))\b",
            r"\b(triple\s*your\s*money|3x\s*profit)\b",
            # Hindi Devanagari
            r"(पैसा\s*डबल|पैसे\s*दोगुने|धन\s*दोगुना)",
            r"(\d+\s*दिनों?\s*में\s*पैसा\s*(डबल|दोगुना))",
            # Hinglish
            r"\b(paise?\s*double|paisa\s*double|paisa\s*doguna)\b",
            r"\b(\d+\s*din\s*me\s*paisa\s*double)\b",
            # Gujarati
            r"(નાણાં\s*ડબલ|પૈસા\s*બમણા|મૂડી\s*બમણી)",
            r"(\d+\s*દિવસમાં\s*પૈસા\s*(ડબલ|બમણા))",
        ],
        "title": {
            "en": "'Double Your Money' Scheme",
            "hi": "'पैसा डबल' करने की लुभावनी स्कीम",
            "gu": "'પૈસા ડબલ' કરવાની લોભામણી સ્કીમ",
        },
        "explanation": {
            "en": "Promises to double or triple money in days or weeks are classic Ponzi or pyramid schemes. Legitimate wealth creation takes time and compounding, never overnight doubling.",
            "hi": "कुछ ही दिनों या हफ्तों में पैसे दोगुने करने का वादा पोंजी (Ponzi) या चिटफंड फ्रॉड का सबसे पुराना तरीका है। असली निवेश में समय लगता है, रातों-रात दोगुना नहीं होता।",
            "gu": "થોડા દિવસો કે અઠવાડિયામાં પૈસા બમણા કરવાનું વચન ક્લાસિક પોન્ઝી કૌભાંડ છે. વાસ્તવિક રોકાણમાં સમય લાગે છે, રાતોરાત ડબલ ક્યારેય થતું નથી.",
        },
    },
    {
        "id": "R_ASTRONOMICAL_PROFIT",
        "severity": "high",
        "weight": 25,
        "category": "Unrealistic Gains",
        "patterns": [
            r"\b(\d{2,3}%\s*(daily|weekly|everyday|per\s*day|hourly))\b",
            r"\b(100%\s*profit|500%\s*return|1000%\s*gain)\b",
            r"\b(multibagger\s*guarantee)\b",
            # Hindi Devanagari
            r"(प्रतिदिन\s*\d+%\s*(मुनाफा|ब्याज))",
            r"(रोजाना\s*\d+%\s*(प्रॉफिट|कमाई))",
            r"(100%\s*(लाभ|मुनाफा|फायदा))",
            # Hinglish
            r"\b(daily\s*\d+%\s*(profit|kamai))\b",
            r"\b(roj\s*\d+%\s*fayda)\b",
            # Gujarati
            r"(દરરોજ\s*\d+%\s*(નફો|કમાણી))",
            r"(૧૦૦%\s*(નફો|લાભ))",
        ],
        "title": {
            "en": "Astronomical or Daily Percentage Returns",
            "hi": "अस्वाभाविक या दैनिक प्रतिशत लाभ का दावा",
            "gu": "અવાસ્તવિક અથવા દૈનિક ટકાવારી નફાનો દાવો",
        },
        "explanation": {
            "en": "Promises of 2% daily or 50% monthly are mathematically impossible to sustain (2% daily compounded exceeds the world economy in months). Such returns do not exist in genuine markets.",
            "hi": "प्रतिदिन 2% या 5% का रिटर्न गणितीय रूप से असंभव है। यदि कोई इतना कमा सकता, तो वह दुनिया का सबसे अमीर व्यक्ति होता, किसी को मैसेज नहीं भेजता।",
            "gu": "દરરોજ ૨% કે ૫% વળતર ગણિતની દ્રષ્ટિએ અશક્ય છે. વાસ્તવિક બજારોમાં આવા કોઈ દૈનિક નફા અસ્તિત્વમાં નથી.",
        },
    },
    {
        "id": "R_URGENCY_PRESSURE",
        "severity": "medium",
        "weight": 20,
        "category": "Psychological Manipulation",
        "patterns": [
            r"\b(limited\s*(seats|spots|slots|access))\b",
            r"\b(last\s*chance|final\s*call|hurry\s*up|act\s*fast)\b",
            r"\b(join\s*(within|in)\s*\d+\s*(minutes|mins|hours))\b",
            r"\b(offer\s*valid\s*(only\s*)?today|expires\s*(soon|today))\b",
            r"\b(don'?t\s*miss\s*(this\s*)?(opportunity|chance))\b",
            # Hindi Devanagari
            r"(सीमित\s*(सीटें|स्थान|मौका))",
            r"(आखिरी\s*(मौका|अवसर)|जल्दी\s*(करें|जुड़ें))",
            r"(आज\s*ही\s*अंतिम\s*दिन|तुरंत\s*(संपर्क|जुड़ें))",
            # Hinglish
            r"\b(aakhri\s*mauka|jaldi\s*karo|offer\s*khatam)\b",
            r"\b(turant\s*join\s*kare)\b",
            # Gujarati
            r"(મર્યાદિત\s*(બેઠકો|જગ્યા|તક))",
            r"(છેલ્લી\s*તક|ઉતાવળ\s*કરો|તરત\s*જ\s*જોડાઓ)",
            r"(આજે\s*જ\s*છેલ્લો\s*દિવસ)",
        ],
        "title": {
            "en": "Artificial Urgency & Fear of Missing Out (FOMO)",
            "hi": "जल्दबाजी और छूट जाने का डर (FOMO) पैदा करना",
            "gu": "કૃત્રિમ ઉતાવળ અને તક ચૂકી જવાનો ડર (FOMO)",
        },
        "explanation": {
            "en": "Scammers induce artificial time pressure so victims transfer funds impulsively without conducting basic due diligence or consulting family.",
            "hi": "ठग जानबूझकर जल्दबाजी का माहौल बनाते हैं ताकि आप बिना सोचे-समझे या किसी समझदार व्यक्ति से पूछे बिना तुरंत पैसे भेज दें।",
            "gu": "ઠગ જાણીજોઈને સમયનું દબાણ બનાવે છે જેથી તમે વિચાર્યા વિના કે તપાસ કર્યા વિના તાત્કાલિક પૈસા ટ્રાન્સફર કરી દો.",
        },
    },
    {
        "id": "R_INSIDER_TIPS",
        "severity": "high",
        "weight": 25,
        "category": "Illegal Tip Manipulation",
        "patterns": [
            r"\b(sure\s*shot\s*(call|tip|stock|jackpot))\b",
            r"\b(operator\s*(call|buying|game|leak))\b",
            r"\b(bulk\s*deal\s*inside\s*info)\b",
            r"\b(jackpot\s*(call|stock|share))\b",
            r"\b(insider\s*(trading|info|leak|news|report))\b",
            # Hindi Devanagari
            r"(श्योर\s*शॉट\s*(कॉल|टिप|जैकपॉट))",
            r"(ऑपरेटर\s*(कॉल|गेम|खबर))",
            r"(अंदर\s*की\s*खबर|पक्की\s*खबर|जैकपॉट\s*स्टॉक)",
            # Hinglish
            r"\b(pakki\s*khabar|operator\s*call|sure\s*shot)\b",
            r"\b(andar\s*ki\s*khabar)\b",
            # Gujarati
            r"(પાકી\s*(બાતમી|માહિતી|ખબર))",
            r"(ઓપરેટર\s*(કોલ|ગેમ))",
            r"(જેકપોટ\s*(સ્ટોક|શેર))",
        ],
        "title": {
            "en": "Claims of 'Insider Info' or 'Operator Calls'",
            "hi": "'अंदर की खबर' या 'ऑपरेटर कॉल' का झांसा",
            "gu": "'અંદરની બાતમી' અથવા 'ઓપરેટર કોલ'નો દાવો",
        },
        "explanation": {
            "en": "Insider trading is illegal under SEBI laws, and real operators do not leak secrets to retail traders. These terms are used to dump illiquid penny stocks on unsuspecting retail investors.",
            "hi": "इंसाइडर ट्रेडिंग गैरकानूनी है। कोई भी असली ऑपरेटर आम जनता को कभी अंदर की खबर नहीं देता। यह घटिया पेनी स्टॉक आम निवेशकों के मत्थे मढ़ने की साजिश होती है।",
            "gu": "ઈન્સાઈડર ટ્રેડિંગ ગેરકાયદેસર છે. કોઈ પણ અસલી ઓપરેટર છૂટક રોકાણકારોને આવી માહિતી આપતા નથી. આ ખરાબ શેરો પધરાવવાની યુક્તિ છે.",
        },
    },
    {
        "id": "R_PUMP_AND_DUMP",
        "severity": "high",
        "weight": 25,
        "category": "Market Manipulation",
        "patterns": [
            r"\b(rocket\s*(banega|bnega|stock|share))\b",
            r"\b(buy\s*aggressively\s*(now|today))\b",
            r"\b(target\s*hit\s*sure|upper\s*circuit\s*(confirmed|guarantee))\b",
            r"\b(huge\s*breakout\s*(guaranteed|confirmed))\b",
            r"\b(buy\s*before\s*(it\s*is\s*)?too\s*late)\b",
            # Hindi Devanagari
            r"(रॉकेट\s*बनेगा|अपर\s*सर्किट\s*लगेगा)",
            r"(तुरंत\s*खरीदें|हाथ\s*से\s*निकल\s*जाएगा)",
            # Gujarati
            r"(રોકેટ\s*બનશે|અપર\s*સર્કિટ\s*લાગશે)",
            r"(તરત\s*જ\s*ખરીદો)",
        ],
        "title": {
            "en": "Pump-and-Dump Stock Pushing",
            "hi": "पंप-एंड-डंप और पेनी स्टॉक मैनिपुलेशन",
            "gu": "પંપ-એન્ડ-ડમ્પ અને શેર મેનીપ્યુલેશન",
        },
        "explanation": {
            "en": "Fraudsters artificially inflate ('pump') small illiquid stocks by blasting mass messages, then sell off their own shares ('dump'), causing retail buyers to suffer 90%+ losses.",
            "hi": "धोखेबाज बल्क मैसेज भेजकर छोटे शेयरों की कीमत बढ़वाते हैं और फिर अपने शेयर बेचकर भाग जाते हैं। इससे आम निवेशक की सारी जमा पूंजी डूब जाती है।",
            "gu": "ઠગો સંદેશાઓ મોકલીને નાના શેરોના ભાવ કૃત્રિમ રીતે વધારે છે અને પછી પોતાના શેર વેચીને ભાગી જાય છે, જેથી રોકાણકારોને ભારે નુકસાન થાય છે.",
        },
    },
    {
        "id": "R_TARGET_GUARANTEED",
        "severity": "medium",
        "weight": 18,
        "category": "Price Predictions",
        "patterns": [
            r"\b(target\s*(price\s*)?\d+\s*guaranteed)\b",
            r"\b(100%\s*target\s*achieved)\b",
            r"\b(guaranteed\s*target)\b",
            # Hindi Devanagari
            r"(टारगेट\s*(पक्का|गारंटीड))",
            r"(लक्ष्य\s*100%\s*हासिल)",
            # Hinglish
            r"\b(target\s*pakka|pakka\s*target)\b",
            # Gujarati
            r"(ટાર્ગેટ\s*(પાકો|ખાતરીપૂર્વક))",
        ],
        "title": {
            "en": "Guaranteed Target Price Claim",
            "hi": "निश्चित टारगेट प्राइस का दावा",
            "gu": "ચોક્કસ ટાર્ગેટ ભાવનો દાવો",
        },
        "explanation": {
            "en": "Target prices can never be guaranteed due to market volatility. Only SEBI-registered Research Analysts may provide price targets, and always accompanied by risk disclosures.",
            "hi": "बाजार के उतार-चढ़ाव में कोई भी टारगेट निश्चित नहीं हो सकता। केवल सेबी-पंजीकृत रिसर्च एनालिस्ट ही जोखिम चेतावनी के साथ विश्लेषण प्रस्तुत कर सकते हैं।",
            "gu": "બજારની અનિશ્ચિતતાને કારણે લક્ષ્ય કિંમતની ક્યારેય ખાતરી આપી શકાતી નથી. માત્ર સેબી-રજિસ્ટર્ડ વિશ્લેષક જ જોખમની ચેતવણી સાથે વિશ્લેષણ આપી શકે છે.",
        },
    },
    {
        "id": "R_VIP_TELEGRAM_WHATSAPP",
        "severity": "medium",
        "weight": 20,
        "category": "Unregulated Channels",
        "patterns": [
            r"\b(join\s*(our\s*)?(vip|premium)\s*(telegram|whatsapp|channel|group))\b",
            r"\b(telegram\s*link\s*in\s*(bio|description))\b",
            r"\b(dm\s*(me\s*)?for\s*(vip|sure\s*shot)\s*calls?)\b",
            r"\b(premium\s*channel\s*membership)\b",
            r"\b(free\s*calls?\s*in\s*telegram)\b",
            # Hindi Devanagari
            r"(वीआईपी\s*(टेलीग्राम|व्हाट्सएप)\s*ग्रुप)",
            r"(प्रीमियम\s*ग्रुप\s*में\s*जुड़ें)",
            r"(टेलीग्राम\s*पर\s*मैसेज\s*करें)",
            # Hinglish
            r"\b(vip\s*group\s*me\s*(aao|judo))\b",
            r"\b(telegram\s*pe\s*msg\s*karo)\b",
            # Gujarati
            r"(વીઆઈપી\s*(ટેલિગ્રામ|વ્હોટ્સએપ)\s*ગ્રૂપ)",
            r"(પ્રીમિયમ\s*ગ્રૂપમાં\s*જોડાઓ)",
        ],
        "title": {
            "en": "Lure to VIP Telegram / WhatsApp Groups",
            "hi": "वीआईपी टेलीग्राम या व्हाट्सएप ग्रुप में जुड़ने का आमंत्रण",
            "gu": "વીઆઈપી ટેલિગ્રામ અથવા વ્હોટ્સએપ ગ્રૂપમાં જોડાવાનું આમંત્રણ",
        },
        "explanation": {
            "en": "Unregulated messaging groups hide the organizer's identity and cannot be tracked by regulatory authorities. Fraudulent advice groups frequently re-brand once members lose money.",
            "hi": "अनधिकृत टेलीग्राम/व्हाट्सएप ग्रुप्स में एडमिन की पहचान गुप्त रहती है। पैसा डूबने पर वे आपको ब्लॉक कर देते हैं और नया ग्रुप बना लेते हैं।",
            "gu": "બિનનિયમિત જૂથોમાં સંચાલકની ઓળખ છુપાયેલી હોય છે. પૈસા ગુમાવ્યા પછી તેઓ સભ્યોને બ્લોક કરી દે છે.",
        },
    },
    {
        "id": "R_SUSPICIOUS_URLS",
        "severity": "high",
        "weight": 25,
        "category": "Suspicious Links",
        "patterns": [
            r"https?://(bit\.ly|tinyurl\.com|t\.co|cutt\.ly|is\.gd|rb\.gy)/[a-zA-Z0-9_-]+",
            r"https?://(wa\.me|chat\.whatsapp\.com|t\.me|telegram\.me)/[a-zA-Z0-9_+?-]+",
            r"https?://[a-zA-Z0-9-]+\.(xyz|top|vip|buzz|online|click|site|loan|cfd|icu|work)/",
            r"https?://(\d{1,3}\.){3}\d{1,3}(:\d+)?",
            r"(zerodha|groww|angelone|upstox|hdfc|icici)[a-zA-Z0-9-]*\.(xyz|top|site|club|app|info)",
        ],
        "title": {
            "en": "Shortened, Redirect, or Suspicious Website Link",
            "hi": "संक्षिप्त (Shortened) या संदिग्ध वेबसाइट लिंक",
            "gu": "ટૂંકી કરેલી અથવા શંકાસ્પદ વેબસાઇટ લિંક",
        },
        "explanation": {
            "en": "Shortened links (bit.ly, t.me) and strange domain extensions (.xyz, .top) are used to disguise phishing portals or clone sites designed to steal your credentials.",
            "hi": "शॉर्ट लिंक और अजीब डोमेन (.xyz, .top) असली वेबसाइटों के नकली क्लोन पेज छुपाने और आपकी बैंक/डीमैट जानकारी चुराने के लिए इस्तेमाल होते हैं।",
            "gu": "ટૂંકી લિંક્સ અને અજાણ્યા ડોમેન (.xyz, .top) નકલી ક્લોન સાઇટ્સ છુપાવવા અને બેંક વિગતો ચોરવા માટે વપરાય છે.",
        },
    },
    {
        "id": "R_SEBI_FALSE_CLAIM",
        "severity": "high",
        "weight": 35,
        "category": "Impersonation of Regulator",
        "patterns": [
            r"\b(sebi\s*(approved|guaranteed|certified|authorized\s*scheme|verified\s*returns?))\b",
            r"\b(government\s*(approved|guaranteed)\s*stock\s*scheme)\b",
            r"\b(rbi\s*approved\s*(trading|share\s*market|crypto))\b",
            # Hindi Devanagari
            r"(सेबी\s*(द्वारा\s*)?(प्रमाणित|स्वीकृत|गारंटीड|अनुमोदित))",
            r"(सरकारी\s*गारंटी\s*वाली\s*स्कीम)",
            # Hinglish
            r"\b(sebi\s*(certified|approved|guarantee))\b",
            r"\b(sarkari\s*guarantee)\b",
            # Gujarati
            r"(સેબી\s*(દ્વારા\s*)?(પ્રમાણિત|મંજૂર|ગેરંટીડ))",
            r"(સરકારી\s*ગેરંટીવાળી\s*યોજના)",
        ],
        "title": {
            "en": "False Claim of SEBI or Government Guarantee",
            "hi": "सेबी (SEBI) या सरकार द्वारा गारंटीड होने का झूठा दावा",
            "gu": "સેબી અથવા સરકાર દ્વારા ગેરંટી આપવાનો ખોટો દાવો",
        },
        "explanation": {
            "en": "CRITICAL FACT: SEBI NEVER approves, certifies, or guarantees any stock scheme, investment platform, or returns. Any message claiming 'SEBI Approved Returns' is a fraudulent fabrication.",
            "hi": "अति महत्वपूर्ण: सेबी (SEBI) कभी भी किसी स्टॉक स्कीम या रिटर्न को प्रमाणित या गारंटी नहीं देता। 'सेबी अप्रूव्ड' का दावा पूरी तरह झूठा और फर्जी है।",
            "gu": "મહત્વપૂર્ણ: સેબી ક્યારેય કોઈ સ્ટોક સ્કીમ અથવા વળતરને પ્રમાણિત કે ગેરંટી આપતું નથી. 'સેબી એપ્રૂવ્ડ'નો દાવો સંપૂર્ણપણે ખોટો છે.",
        },
    },
    {
        "id": "R_CREDENTIAL_THEFT",
        "severity": "high",
        "weight": 40,
        "category": "Credential Theft",
        "patterns": [
            r"\b(share|send|enter|give)\s*(your\s*)?(otp|one\s*time\s*password|upi\s*pin|trading\s*password)\b",
            r"\b(enter\s*upi\s*pin\s*to\s*(receive|claim|credit|get)\s*money)\b",
            r"\b(login\s*credentials|mpin|card\s*cvv)\b",
            # Hindi Devanagari
            r"(ओटीपी\s*(शेयर|भेजें|बताएं|दर्ज\s*करें))",
            r"(पैसे\s*पाने\s*के\s*लिए\s*यूपीआई\s*पिन\s*(दर्ज|डालें))",
            r"(पासवर्ड\s*(मांगना|देना))",
            # Hinglish
            r"\b(otp\s*(bhejo|share\s*karo|batao|send\s*karo))\b",
            r"\b(upi\s*pin\s*(dalo|enter\s*karo))\b",
            # Gujarati
            r"(ઓટીપી\s*(આપો|મોકલો|શેર\s*કરો))",
            r"(પૈસા\s*મેળવવા\s*માટે\s*યુપીઆઈ\s*પિન\s*નાખો)",
            r"(પાસવર્ડ\s*આપો)",
        ],
        "title": {
            "en": "Demand for OTP, UPI PIN, or Password",
            "hi": "ओटीपी (OTP), यूपीआई पिन या पासवर्ड की मांग",
            "gu": "ઓટીપી, યુપીઆઈ પિન અથવા પાસવર્ડની માંગણી",
        },
        "explanation": {
            "en": "CRITICAL DANGER: UPI PIN is ONLY needed to SEND money, never to receive money. Never share your OTP, PIN, or password with anyone under any circumstances.",
            "hi": "सावधान: यूपीआई पिन केवल पैसे भेजने के लिए होता है, पैसे प्राप्त करने के लिए पिन की आवश्यकता कभी नहीं होती! अपना ओटीपी या पिन कभी किसी को न बताएं।",
            "gu": "ચેતવણી: યુપીઆઈ પિન ફક્ત પૈસા ચૂકવવા માટે જ હોય છે, પૈસા મેળવવા માટે ક્યારેય પિન નાખવાનો હોતો નથી. ક્યારેય કોઈને ઓટીપી કે પિન આપશો નહીં.",
        },
    },
    {
        "id": "R_REMOTE_ACCESS",
        "severity": "high",
        "weight": 40,
        "category": "Device Compromise",
        "patterns": [
            r"\b(install|download)\s*(anydesk|teamviewer|quicksupport|rustdesk|screenshare|ultraviewer|zoho\s*assist)\b",
            r"\b(share\s*(your\s*)?screen\s*(for\s*verification|to\s*trade))\b",
            # Hindi Devanagari
            r"(एनीडेस्क|टीमव्यूअर|क्विकसपोर्ट)\s*(इंस्टॉल|डाउनलोड)",
            r"(स्क्रीन\s*शेयर\s*करें)",
            # Hinglish
            r"\b(anydesk\s*download\s*karo|teamviewer\s*install)\b",
            # Gujarati
            r"(એનીડેસ્ક|ટીમવ્યૂઅર)\s*(ઇન્સ્ટોલ|ડાઉનલોડ)",
            r"(સ્ક્રીન\s*શેર\s*કરો)",
        ],
        "title": {
            "en": "Request to Install Remote-Access Software",
            "hi": "रिमोट एक्सेस ऐप (AnyDesk / TeamViewer) इंस्टॉल करने का दबाव",
            "gu": "રિમોટ એક્સેસ એપ્લિકેશન (AnyDesk/TeamViewer) ઇન્સ્ટોલ કરવાની માંગ",
        },
        "explanation": {
            "en": "Scammers ask victims to install screen-sharing software (AnyDesk, TeamViewer) to view banking passwords, capture SMS OTPs, and drain accounts remotely.",
            "hi": "ठग फोन की स्क्रीन देखने वाले ऐप (जैसे AnyDesk, TeamViewer) डाउनलोड करवाकर आपके फोन का पूरा कंट्रोल ले लेते हैं और बैंक खाता खाली कर देते हैं।",
            "gu": "ઠગ સ્ક્રીન-શેરિંગ એપ ડાઉનલોડ કરાવીને તમારા ફોનનો પૂરો અંકુશ મેળવી લે છે અને બેંક ખાતું ખાલી કરી શકે છે.",
        },
    },
    {
        "id": "R_UPFRONT_FEES",
        "severity": "medium",
        "weight": 20,
        "category": "Advance Fee Fraud",
        "patterns": [
            r"\b(pay\s*(registration|joining|membership|advance|entry)\s*(fee|charges?|amount))\b",
            r"\b(pay\s*₹?\d+\s*to\s*start\s*(trading|earning))\b",
            # Hindi Devanagari
            r"(शुरुआती\s*(फीस|चार्ज|पंजीकरण\s*शुल्क))",
            r"(रजिस्ट्रेशन\s*फीस\s*(जमा|पे)\s*करें)",
            # Hinglish
            r"\b(fees\s*pehle\s*do|registration\s*charge\s*bhejo)\b",
            # Gujarati
            r"(નોંધણી\s*ફી|જોડાણ\s*શુલ્ક|અગાઉથી\s*ફી)",
        ],
        "title": {
            "en": "Upfront Registration or Joining Fee Demanded",
            "hi": "अग्रिम रजिस्ट्रेशन या जॉइनिंग फीस की मांग",
            "gu": "અગાઉથી નોંધણી અથવા જોડાણ ફીની માંગણી",
        },
        "explanation": {
            "en": "Legitimate SEBI intermediaries charge transparent fees deducted through legal banking channels, never via advance UPI transfers for informal group access.",
            "hi": "सेबी पंजीकृत संस्थान किसी अनौपचारिक ग्रुप में शामिल होने के लिए अग्रिम यूपीआई फीस नहीं मांगते। यह फीस फ्रॉड का हिस्सा हो सकती है।",
            "gu": "સેબી માન્ય મધ્યસ્થીઓ કોઈપણ અનૌપચારિક જૂથમાં જોડાવા માટે અગાઉથી યુપીઆઈ દ્વારા ફી માંગતા નથી.",
        },
    },
    {
        "id": "R_WITHDRAWAL_UNLOCK_FEE",
        "severity": "high",
        "weight": 35,
        "category": "Exit Extortion Scam",
        "patterns": [
            r"\b(pay\s+[^.\n]{0,35}?(tax|processing\s*fee|commission|fee|charge)\s+to\s+(withdraw|release|unlock)\s*(funds?|profit|money|account)?)\b",
            r"\b(unfreeze\s*(your\s*)?(trading\s*)?account)\b",
            r"\b(account\s*frozen\s*[^.\n]{0,30}?(pay|fee|amount|unfreeze))\b",
            r"\b(withdrawal\s*fee\s*(required|mandatory|needed))\b",
            # Hindi Devanagari
            r"(पैसे\s*निकालने\s*के\s*लिए\s*[^।\n]{0,25}?(टैक्स|चार्ज|फीस)\s*दें)",
            r"(खाता\s*फ्रीज\s*हो\s*गया\s*है|अनफ्रीज\s*के\s*लिए\s*पैसे)",
            # Hinglish
            r"\b(paisa\s*nikalne\s*ke\s*liye\s*[^.\n]{0,20}?(tax|fee|charge))\b",
            r"\b(account\s*unfreeze\s*(charges?|fee)?)\b",
            # Gujarati
            r"(પૈસા\s*ઉપાડવા\s*માટે\s*[^।\n]{0,25}?(ટેક્સ|ફી)\s*ભરો)",
            r"(ખાતું\s*અનફ્રીઝ\s*કરવા\s*માટે\s*ચાર્જ)",
        ],
        "title": {
            "en": "Fee Demanded to 'Unlock' or Withdraw Profits",
            "hi": "मुनाफा निकालने या खाता अनलॉक करने के लिए अतिरिक्त पैसे मांगना",
            "gu": "નફો ઉપાડવા અથવા ખાતું અનલોક કરવા માટે ફીની માંગણી",
        },
        "explanation": {
            "en": "This is the hallmark of a pig-butchering trap. Fictitious profits are shown on a fake dashboard, and when you try to withdraw, they demand additional 'taxes' or 'fees' and never return a rupee.",
            "hi": "यह सबसे खतरनाक फ्रॉड है। नकली ऐप पर भारी मुनाफा दिखाकर उसे निकालने के नाम पर टैक्स या अनफ्रीज चार्ज मांगा जाता है, और पैसे कभी वापस नहीं मिलते।",
            "gu": "આ સૌથી સામાન્ય છેતરપિંડી છે. નકલી સ્ક્રીન પર મોટો નફો બતાવી તેને ઉપાડવાના નામે વધુ પૈસા પડાવી લેવામાં આવે છે.",
        },
    },
    {
        "id": "R_CELEBRITY_DEEPFAKE",
        "severity": "high",
        "weight": 30,
        "category": "Celebrity & Finfluencer Impersonation",
        "patterns": [
            r"\b(mukesh\s*ambani|anant\s*ambani|narayana\s*murthy|nandan\s*nilekani|ratan\s*tata)\s*(project|fund|trading|platform|app|crypto|scheme)\b",
            r"\b(pm\s*modi|narendra\s*modi)\s*(scheme|investment|crypto|app)\b",
            r"\b(deepfake|ai\s*video\s*of\s*(ambani|tata|murthy))\b",
            # Hindi Devanagari
            r"(मुकेश\s*अंबानी|रतन\s*टाटा|नारायण\s*मूर्ति)\s*(का\s*नया\s*प्रोजेक्ट|की\s*योजना|का\s*प्लेटफॉर्म)",
            # Gujarati
            r"(મુકેશ\s*અંબાણી|રતન\s*ટાટા)\s*(નો\s*પ્રોજેક્ટ|ની\s*યોજના)",
        ],
        "title": {
            "en": "Celebrity / Industrialist Impersonation (AI Deepfake)",
            "hi": "उद्योगपति या प्रसिद्ध हस्ती के नाम पर फर्जीवाड़ा (Deepfake)",
            "gu": "જાણીતી હસ્તીના નામે છેતરપિંડી (ડીપફેક)",
        },
        "explanation": {
            "en": "Cybercriminals use AI-generated deepfake videos of prominent figures (Mukesh Ambani, Ratan Tata, Narayana Murthy) falsely promoting secret automated trading portals.",
            "hi": "साइबर अपराधी मुकेश अंबानी, रतन टाटा जैसी हस्तियों के एआई (Deepfake) वीडियो बनाकर दावा करते हैं कि वे किसी सीक्रेट ट्रेडिंग ऐप से पैसे कमा रहे हैं।",
            "gu": "સાયબર ગુનેગારો જાણીતી હસ્તીઓના બનાવટી (ડીપફેક) વિડીયો બનાવીને નકલી ટ્રેડિંગ યોજનાઓનો પ્રચાર કરે છે.",
        },
    },
    {
        "id": "R_AI_BOT_MAGIC",
        "severity": "medium",
        "weight": 22,
        "category": "Unrealistic Automation Claims",
        "patterns": [
            r"\b(100%\s*automated\s*(ai\s*)?(trading\s*)?bot)\b",
            r"\b(ai\s*(algorithm|robot|software)\s*(guaranteed|auto\s*profit))\b",
            r"\b(sleep\s*and\s*earn|hands[\s-]free\s*passive\s*income\s*bot)\b",
            # Hindi Devanagari
            r"(एआई\s*(ट्रेडिंग\s*)?बॉट|ऑटोमेटेड\s*कमाई)",
            r"(सोते\s*हुए\s*पैसे\s*कमाएं)",
            # Hinglish
            r"\b(ai\s*bot\s*se\s*kamaye|automated\s*trading\s*bot)\b",
            # Gujarati
            r"(એઆઈ\s*બોટ|ઓટોમેટેડ\s*ટ્રેડિંગ\s*સોફ્ટવેર)",
        ],
        "title": {
            "en": "'Magic' AI Trading Bot or Passive Income Guarantee",
            "hi": "'जादुई' एआई ट्रेडिंग बॉट से ऑटोमैटिक कमाई का दावा",
            "gu": "'જાદુઈ' AI ટ્રેડિંગ બોટથી આપોઆપ કમાણીનો દાવો",
        },
        "explanation": {
            "en": "No AI trading bot has solved financial markets to provide guaranteed automated profits without catastrophic downside risk. Selling automated trading software to retail users with guaranteed returns is illegal.",
            "hi": "कोई भी एआई बॉट बिना जोखिम के रोजाना पैसे नहीं बना सकता। ऐसे बॉट अक्सर आपका पूरा पैसा डुबो देते हैं।",
            "gu": "કોઈપણ AI બોટ જોખમ વિના સતત નફો આપી શકતું નથી. આવા સોફ્ટવેર રોકાણકારોને છેતરવા માટે વપરાય છે.",
        },
    },
    {
        "id": "R_FREE_DEMAT_BONUS",
        "severity": "low",
        "weight": 10,
        "category": "Misleading Inducements",
        "patterns": [
            r"\b(open\s*(free\s*)?demat\s*(and\s*)?get\s*₹?\d+\s*(cash|bonus|free\s*money))\b",
            r"\b(free\s*₹?\d+\s*credited\s*to\s*your\s*trading\s*account)\b",
            r"\b(signup\s*bonus\s*₹?\d+)\b",
            # Hindi Devanagari
            r"(डीमैट\s*खाता\s*खोलें\s*और\s*पाएं\s*₹?\d+\s*कैश\s*बोनस)",
            # Gujarati
            r"(ડીમેટ\s*ખાતું\s*ખોલો\s*અને\s*મેળવો\s*રોકડ\s*બોનસ)",
        ],
        "title": {
            "en": "Cash Bonus or Free Money for Account Opening",
            "hi": "डीमैट खाता खोलने पर मुफ्त नकद या बोनस का लालच",
            "gu": "ડીમેટ ખાતું ખોલવા પર મફત રોકડ બોનસની લાલચ",
        },
        "explanation": {
            "en": "SEBI regulations prohibit brokers and intermediaries from offering cash incentives, bonuses, or lottery gifts to induce clients to open demat accounts or trade.",
            "hi": "सेबी के नियमों के अनुसार किसी को ट्रेडिंग खाता खोलने के लिए नकद बोनस या इनाम का लालच देना प्रतिबंधित है।",
            "gu": "સેબીના નિયમો અનુસાર ટ્રેડિંગ એકાઉન્ટ ખોલવા માટે રોકડ બોનસ અથવા ભેટની લાલચ આપવી પ્રતિબંધિત છે.",
        },
    },
    {
        "id": "R_GUARANTEED_IPO",
        "severity": "high",
        "weight": 35,
        "category": "Pre-IPO / Fake Allotment",
        "patterns": [
            r"\b(100%\s*(confirmed|guaranteed)\s*ipo\s*allotment)\b",
            r"\b(pre[\s-]ipo\s*(quota|shares?)\s*(confirmed|guaranteed))\b",
            r"\b(hni\s*(quota|allotment)\s*guarantee)\b",
            r"\b(exclusive\s*institutional\s*ipo\s*allotment)\b",
            # Hindi Devanagari
            r"(आईपीओ\s*100%\s*(पक्का|अलॉटमेंट\s*गारंटी))",
            r"(प्री[\s-]आईपीओ\s*शेयर\s*गारंटी)",
            # Hinglish
            r"\b(ipo\s*(pakka\s*milega|allotment\s*guarantee))\b",
            # Gujarati
            r"(આઈપીઓ\s*૧૦૦%\s*(ખાતરીપૂર્વક\s*મળશે|ફાળવણી))",
        ],
        "title": {
            "en": "Guaranteed 100% IPO Allotment Claim",
            "hi": "आईपीओ (IPO) में 100% अलॉटमेंट की पक्की गारंटी",
            "gu": "IPO માં ૧૦૦% ફાળવણીની ખાતરીનો દાવો",
        },
        "explanation": {
            "en": "IPO allotment in India is strictly governed by computerised lottery draws overseen by stock exchanges. No private individual, broker, or syndicate can promise or guarantee IPO allotment.",
            "hi": "भारत में आईपीओ का आवंटन पूरी तरह कम्प्यूटराइज्ड लॉटरी द्वारा होता है। कोई भी व्यक्ति या संस्था आईपीओ अलॉटमेंट की गारंटी नहीं दे सकती। यह फ्रॉड है।",
            "gu": "ભારતમાં IPO ની ફાળવણી સ્ટોક એક્સચેન્જ દ્વારા કોમ્પ્યુટરાઈઝ્ડ ડ્રો દ્વારા થાય છે. કોઈ પણ વ્યક્તિ IPO ફાળવણીની ખાતરી આપી શકતું નથી.",
        },
    },
    {
        "id": "R_CRYPTO_FOREX_ARBITRAGE",
        "severity": "high",
        "weight": 30,
        "category": "Illegal Forex / Crypto Promises",
        "patterns": [
            r"\b(forex\s*trading\s*(high\s*return|guaranteed|daily\s*income))\b",
            r"\b(usdt\s*(arbitrage|staking)\s*(guaranteed|\d+%))\b",
            r"\b(binance\s*(doubling|arbitrage|bot))\b",
            r"\b(crypto\s*(mining\s*pool|investment\s*scheme)\s*returns?)\b",
            # Hindi Devanagari
            r"(फॉरेक्स\s*ट्रेडिंग\s*(मुनाफा|रिटर्न))",
            r"(क्रिप्टो\s*डबलिंग\s*स्कीम)",
            # Gujarati
            r"(ફોરેક્સ\s*ટ્રેડિંગ\s*નફો)",
            r"(ક્રિપ્ટો\s*ડબલ\s*કરવાની\s*સ્કીમ)",
        ],
        "title": {
            "en": "Unregulated Forex or Crypto Arbitrage Promises",
            "hi": "अनधिकृत फॉरेक्स या क्रिप्टो आर्बिट्रेज स्कीम",
            "gu": "બિનસત્તાવાર ફોરેક્સ અથવા ક્રિપ્ટો સ્કીમ",
        },
        "explanation": {
            "en": "Trading foreign currencies on unauthorized electronic portals violates the Foreign Exchange Management Act (FEMA). RBI maintains an 'Alert List' of unauthorized forex trading platforms.",
            "hi": "अनधिकृत पोर्टल पर विदेशी मुद्रा (Forex) ट्रेडिंग फेमा (FEMA) कानून का उल्लंघन है। आरबीआई (RBI) ने ऐसी अवैध वेबसाइटों की अलर्ट लिस्ट जारी कर रखी है।",
            "gu": "બિનસત્તાવાર પ્લેટફોર્મ પર ફોરેક્સ ટ્રેડિંગ ફેમા કાયદાનું ઉલ્લંઘન છે. આવા સાયબર રોકાણોથી બચવું જોઈએ.",
        },
    },
    {
        "id": "R_PERSONAL_UPI_PAYMENT",
        "severity": "high",
        "weight": 35,
        "category": "Illegitimate Payment Routing",
        "patterns": [
            r"\b(pay\s*to\s*(my\s*)?(personal\s*)?upi\s*id)\b",
            r"\b(gpay|phonepe|paytm)\s*(pe\s*bhejo|to\s*number|\s*:\s*\d{10})\b",
            r"\b([a-zA-Z0-9._-]+@(okhdfcbank|okaxis|oksbi|okicici|paytm|ybl|ibl|apl|axl))\b",
            # Hindi Devanagari
            r"(पर्सनल\s*खाते\s*में\s*पैसे\s*भेजें)",
            r"(इस\s*नंबर\s*पर\s*(फोनपे|गूगलपे)\s*करें)",
            # Hinglish
            r"\b(personal\s*account\s*me\s*bhejo|phonepe\s*karo\s*is\s*no\s*pe)\b",
            # Gujarati
            r"(અંગત\s*ખાતામાં\s*પૈસા\s*ટ્રાન્સફર\s*કરો)",
            r"(આ\s*નંબર\s*પર\s*ગૂગલપે\s*કરો)",
        ],
        "title": {
            "en": "Payment to Individual / Personal UPI Account",
            "hi": "व्यक्तिगत यूपीआई या निजी बैंक खाते में भुगतान की मांग",
            "gu": "વ્યક્તિગત યુપીઆઈ અથવા ખાનગી બેંક ખાતામાં ચુકવણીની માંગણી",
        },
        "explanation": {
            "en": "Registered stock brokers and advisors never collect client funds in individual savings accounts or personal UPI handles. Monies must only go to verified corporate clearing accounts.",
            "hi": "सेबी पंजीकृत ब्रोकर या सलाहकार कभी भी अपने व्यक्तिगत यूपीआई या निजी बचत खाते में पैसे नहीं लेते। यह सीधा फ्रॉड का संकेत है।",
            "gu": "સેબી રજિસ્ટર્ડ બ્રોકર્સ ક્યારેય અંગત યુપીઆઈ કે બચત ખાતામાં ગ્રાહકોના પૈસા લેતા નથી.",
        },
    },
    {
        "id": "R_MLM_REFERRAL_PYRAMID",
        "severity": "medium",
        "weight": 20,
        "category": "Pyramid & MLM Structure",
        "patterns": [
            r"\b(refer\s*\d+\s*(friends|members)\s*(and\s*earn|to\s*unlock))\b",
            r"\b(multi[\s-]level\s*marketing|mlm\s*investment)\b",
            r"\b(team\s*commission|level\s*income|binary\s*income)\b",
            r"\b(downline\s*(members|earnings))\b",
            # Hindi Devanagari
            r"(\d+\s*लोगों\s*को\s*जोड़ें|रेफरल\s*कमीशन)",
            r"(टीम\s*बनाएं\s*और\s*रोजाना\s*कमाएं)",
            # Hinglish
            r"\b(members\s*jodo|referral\s*bonus\s*milega)\b",
            # Gujarati
            r"(\d+\s*સભ્યોને\s*જોડો|રેફરલ\s*કમિશન)",
            r"(ટીમ\s*બનાવીને\s*કમાણી)",
        ],
        "title": {
            "en": "Multi-Level Marketing / Referral Pyramid Scheme",
            "hi": "एमएलएम (MLM) या लोगों को जोड़ने वाली पिरामिड स्कीम",
            "gu": "નેટવર્ક માર્કેટિંગ અથવા પિરામિડ સ્કીમ",
        },
        "explanation": {
            "en": "If earning requires recruiting new participants rather than underlying investment value, it is an illegal pyramid or money circulation scheme prohibited by the Prize Chits and Money Circulation Banning Act.",
            "hi": "यदि कमाई का मुख्य जरिया अन्य लोगों को जोड़ना है, तो यह गैरकानूनी पिरामिड स्कीम है। इसमें अंततः 99% लोगों के पैसे डूब जाते हैं।",
            "gu": "જો કમાણી અન્ય લોકોને જોડવા પર આધારિત હોય, તો તે ગેરકાયદેસર સ્કીમ છે જેમાં રોકાણકારોના નાણાં ડૂબી જાય છે.",
        },
    },
    {
        "id": "R_APK_DOWNLOAD",
        "severity": "high",
        "weight": 35,
        "category": "Malicious Software / APK",
        "patterns": [
            r"\b(download\s*(this\s*)?(apk|app\s*from\s*(link|drive|telegram)))\b",
            r"\b(install\s*our\s*(custom\s*)?trading\s*app\s*apk)\b",
            r"\b([a-zA-Z0-9_-]+\.apk)\b",
            # Hindi Devanagari
            r"(एपीके\s*(डाउनलोड|इंस्टॉल)\s*करें)",
            r"(लिंक\s*से\s*ऐप\s*डाउनलोड\s*करें)",
            # Hinglish
            r"\b(apk\s*download\s*karo|link\s*se\s*app\s*dalo)\b",
            # Gujarati
            r"(એપીકે\s*(ડાઉનલોડ|ઇન્સ્ટોલ)\s*કરો)",
            r"(લિંક\s*પરથી\s*એપ\s*ડાઉનલોડ\s*કરો)",
        ],
        "title": {
            "en": "Direct Android APK Installation Request",
            "hi": "असुरक्षित एपीके (APK) फाइल डाउनलोड करने का निर्देश",
            "gu": "અસુરક્ષિત APK ફાઇલ ડાઉનલોડ કરવાનો નિર્દેશ",
        },
        "explanation": {
            "en": "Never install APK files sent via WhatsApp or Telegram. These rogue applications contain spyware that intercepts SMS OTPs, keystrokes, and drains your bank accounts.",
            "hi": "व्हाट्सएप या टेलीग्राम से मिली APK फाइल कभी इंस्टॉल न करें! यह मैलवेयर होता है जो आपके फोन के सभी पासवर्ड और बैंक ओटीपी चुरा लेता है।",
            "gu": "વ્હોટ્સએપ કે ટેલિગ્રામ પરથી મળેલી APK ફાઇલ ક્યારેય ઇન્સ્ટોલ કરશો નહીં. તે તમારા બેંક ઓટીપી અને પાસવર્ડ ચોરી શકે છે.",
        },
    },
    {
        "id": "R_RECOVERY_SCAM",
        "severity": "high",
        "weight": 30,
        "category": "Secondary Scam (Recovery)",
        "patterns": [
            r"\b(recover\s*(your\s*)?(lost|scammed)\s*(money|crypto|funds?))\b",
            r"\b(fund\s*recovery\s*(expert|agent|specialist))\b",
            r"\b(100%\s*refund\s*of\s*lost\s*trading\s*capital)\b",
            # Hindi Devanagari
            r"(डूबा\s*हुआ\s*पैसा\s*(वापस|रिकवर)\s*करवाएं)",
            r"(स्कैम\s*का\s*पैसा\s*100%\s*वापस)",
            # Hinglish
            r"\b(duba\s*hua\s*paisa\s*wapas|recovery\s*expert)\b",
            # Gujarati
            r"(ડૂબેલા\s*નાણાં\s*પાછા\s*મેળવો)",
            r"(ગુમાવેલા\s*પૈસા\s*રીકવર\s*કરો)",
        ],
        "title": {
            "en": "Fake 'Fund Recovery' Scam",
            "hi": "डूबा हुआ पैसा वापस दिलाने का झूठा दावा (Recovery Scam)",
            "gu": "ગુમાવેલા નાણાં પરત અપાવવાનો ખોટો દાવો",
        },
        "explanation": {
            "en": "Victims who have previously lost money are re-targeted by scammers pretending to be 'recovery agents' who demand advance fees and disappear.",
            "hi": "जो लोग पहले ठगी का शिकार हो चुके हैं, उन्हें दोबारा निशाना बनाकर 'पैसा वापस दिलाने' के नाम पर फिर से एडवांस फीस ठगी जाती है।",
            "gu": "જે લોકો અગાઉ છેતરાયા છે, તેમને ફરીથી નિશાન બનાવી નાણાં પાછા અપાવવાના બહાને વધુ ફી પડાવી લેવામાં આવે છે.",
        },
    },
    {
        "id": "R_UNSOLICITED_CONTACT",
        "severity": "low",
        "weight": 10,
        "category": "Unsolicited Cold Outreach",
        "patterns": [
            r"\b(hi\s*dear|hello\s*sir|excuse\s*me)\b.*\b(part[\s-]time\s*job|trading\s*opportunity|extra\s*income)\b",
            r"\b(found\s*your\s*number\s*(in|on)\s*(an?\s*)?(investment|whatsapp)\s*group)\b",
            r"\b(work\s*from\s*home\s*(stock|crypto|crypto\s*task))\b",
            # Hindi Devanagari
            r"(पार्ट\s*टाइम\s*जॉब|घर\s*बैठे\s*कमाई|रोज\s*\d+\s*हजार\s*कमाएं)",
            # Hinglish
            r"\b(ghar\s*baithe\s*(kamaye|trading\s*job))\b",
            # Gujarati
            r"(પાર્ટ\s*ટાઇમ\s*જોબ|ઘેરબેઠા\s*કમાણી)",
        ],
        "title": {
            "en": "Unsolicited Cold Outreach / Fake Part-Time Job",
            "hi": "अपरिचित नंबर से पार्ट-टाइम ट्रेडिंग जॉब का संदेश",
            "gu": "અજાણ્યા નંબર પરથી પાર્ટ-ટાઇમ જોબનો સંદેશ",
        },
        "explanation": {
            "en": "Cold messages on WhatsApp from unknown foreign or virtual numbers offering 'part time trading' are entry points for investment task frauds.",
            "hi": "अपरिचित नंबरों से व्हाट्सएप पर पार्ट-टाइम कमाई का ऑफर अक्सर बड़े इनवेस्टमेंट फ्रॉड की पहली सीढ़ी होता है।",
            "gu": "અજાણ્યા નંબરો પરથી મળતા પાર્ટ-ટાઇમ કમાણીના સંદેશાઓ ઘણીવાર મોટા નાણાકીય કૌભાંડની શરૂઆત હોય છે.",
        },
    },
    {
        "id": "R_ACCOUNT_HANDLING",
        "severity": "high",
        "weight": 35,
        "category": "Unauthorized Trading Handover",
        "patterns": [
            r"\b(give\s*(me\s*)?(your\s*)?(id\s*and\s*password|login\s*details)\s*(i\s*will\s*trade))\b",
            r"\b(account\s*handling\s*service)\b",
            r"\b(50[\s-]50\s*profit\s*sharing\s*(on\s*your\s*account)?)\b",
            r"\b(portfolio\s*handling\s*guaranteed)\b",
            # Hindi Devanagari
            r"(अकाउंट\s*हैंडलिंग\s*सर्विस|आईडी\s*पासवर्ड\s*दें\s*हम\s*ट्रेड\s*करेंगे)",
            r"(50-50\s*प्रॉफिट\s*शेयरिंग)",
            # Hinglish
            r"\b(id\s*pass\s*do\s*hum\s*trade\s*karenge|account\s*handle)\b",
            # Gujarati
            r"(એકાઉન્ટ\s*હેન્ડલિંગ\s*સેવા|આઈડી\s*પાસવર્ડ\s*આપો)",
            r"(૫૦-૫૦\s*નફાની\s*ભાગીદારી)",
        ],
        "title": {
            "en": "Unauthorized 'Account Handling' / ID-Password Handover",
            "hi": "डीमैट खाता हैंडल करने या आईडी-पासवर्ड मांगने की पेशकश",
            "gu": "ડીમેટ એકાઉન્ટ હેન્ડલિંગ અથવા આઈડી-પાસવર્ડ માંગણી",
        },
        "explanation": {
            "en": "Sharing your trading ID and password with anyone is illegal under stock exchange regulations. Scammers execute circular trades to drain your funds or transfer your stocks to their accounts.",
            "hi": "किसी भी व्यक्ति को अपना ट्रेडिंग आईडी-पासवर्ड देना गैरकानूनी और अत्यंत जोखिम भरा है। वे आपके खाते से गलत सौदे करके पैसे उड़ा सकते हैं।",
            "gu": "કોઈપણ વ્યક્તિને તમારો ટ્રેડિંગ આઈડી-પાસવર્ડ આપવો જોખમી અને ગેરકાયદેસર છે. તેનાથી તમારી સંપૂર્ણ મૂડી ગુમાવવાનું જોખમ રહેલું છે.",
        },
    },
]


def check_sebi_registration_number(text: str, lang: str = "en") -> Optional[SebiCheckResult]:
    """
    Scans for SEBI registration number formats:
    - INA: Investment Adviser (9 digits)
    - INH: Research Analyst (9 digits)
    - INZ: Stock Broker (9 digits)
    Strictly emphasizes that having a valid format does NOT mean it is genuine.
    """
    match = SEBI_REG_REGEX.search(text)
    if not match:
        loose_match = SEBI_LOOSE_REGEX.search(text)
        if loose_match:
            candidate = loose_match.group(1).upper()
            guidance = {
                "en": f"Found a SEBI-like string '{candidate}', but the format does not match official 3-letter + 9-digit standards. Anyone can invent registration numbers. ALWAYS check officially on sebi.gov.in.",
                "hi": f"सेबी जैसा दिखने वाला नंबर '{candidate}' मिला, लेकिन यह आधिकारिक 3 अक्षर + 9 अंकों के प्रारूप से मेल नहीं खाता। कोई भी फर्जी नंबर लिख सकता है। हमेशा sebi.gov.in पर आधिकारिक जांच करें।",
                "gu": f"સેબી જેવો નંબર '{candidate}' મળ્યો, પરંતુ તે સત્તાવાર ફોર્મેટ સાથે મેળ ખાતો નથી. હંમેશા sebi.gov.in પર સત્તાવાર રીતે ચકાસો.",
            }
            return SebiCheckResult(
                detected=True,
                reg_number=candidate,
                category="Unknown",
                format_valid=False,
                verification_guidance=guidance.get(lang, guidance["en"])
            )
        return None

    prefix = match.group(1).upper()
    digits = match.group(2)
    reg_number = f"{prefix}{digits}"
    
    category_map = {
        "INA": "Investment Adviser (RIA)",
        "INH": "Research Analyst (RA)",
        "INZ": "Stock Broker",
    }
    category = category_map.get(prefix, "SEBI Intermediary")

    guidance = {
        "en": f"Format appears structurally valid for {category} ({reg_number}). WARNING: Anyone can copy a genuine intermediary's number onto a fake message! A valid format is NOT proof of authenticity. Verify the person's phone/email matches SEBI records on sebi.gov.in.",
        "hi": f"प्रारूप संरचनात्मक रूप से {category} ({reg_number}) के अनुरूप दिखता है। चेतावनी: कोई भी धोखेबाज किसी असली सलाहकार का नंबर कॉपी करके मैसेज में लिख सकता है! सही प्रारूप प्रामाणिकता का प्रमाण नहीं है। हमेशा sebi.gov.in पर जाकर फोन नंबर और ईमेल का मिलान करें।",
        "gu": f"ફોર્મેટ {category} ({reg_number}) માટે માન્ય દેખાય છે. ચેતવણી: કોઈપણ ઠગ કોઈ સાચા સલાહકારનો નંબર કોપી કરી શકે છે! ફોર્મેટ સાચું હોવું એ સત્યતાનું પ્રમાણ નથી. હંમેશા sebi.gov.in પર જઈને સંપર્ક વિગતો ચકાસો.",
    }

    return SebiCheckResult(
        detected=True,
        reg_number=reg_number,
        category=category,
        format_valid=True,
        verification_guidance=guidance.get(lang, guidance["en"])
    )


def evaluate_rules(text: str, lang: str = "en") -> Tuple[List[RedFlag], int, str, str, List[Tuple[int, int, str, str]]]:
    """
    Evaluates input text against all 26+ rules.
    Returns:
    - matched RedFlag objects
    - total risk score (0-100)
    - risk_level ('Low', 'Medium', 'High')
    - confidence ('Low', 'Medium', 'High')
    - list of raw match spans (start, end, rule_id, severity) for highlighting
    """
    matched_flags: List[RedFlag] = []
    match_spans: List[Tuple[int, int, str, str]] = []
    total_weight = 0
    categories_hit = set()
    has_high = False

    clean_lang = lang if lang in ("en", "hi", "gu") else "en"

    for rule in RULES_DATABASE:
        found_in_rule = False
        for pattern_str in rule["patterns"]:
            try:
                for match in re.finditer(pattern_str, text, re.IGNORECASE):
                    start, end = match.span()
                    evidence_snippet = match.group(0).strip()
                    if not evidence_snippet:
                        continue
                    
                    match_spans.append((start, end, rule["id"], rule["severity"]))

                    if not found_in_rule:
                        found_in_rule = True
                        total_weight += rule["weight"]
                        categories_hit.add(rule["category"])
                        if rule["severity"] == "high":
                            has_high = True

                        title = rule["title"].get(clean_lang, rule["title"]["en"])
                        explanation = rule["explanation"].get(clean_lang, rule["explanation"]["en"])

                        matched_flags.append(
                            RedFlag(
                                rule_id=rule["id"],
                                title=title,
                                why_it_matters=explanation,
                                evidence_quote=evidence_snippet,
                                severity=rule["severity"],
                            )
                        )
            except Exception:
                continue

    # Score calculation (normalized 0 to 100)
    # 0 rules: 0-10
    # Low severity only: 15-35
    # Medium severity: 35-65
    # High severity: 70-100
    if not matched_flags:
        score = 8
        risk_level = "Low"
    elif has_high:
        score = min(100, 65 + len(matched_flags) * 7)
        risk_level = "High"
    elif total_weight >= 30 or len(matched_flags) >= 2:
        score = min(75, 40 + len(matched_flags) * 10)
        risk_level = "Medium"
    else:
        score = min(40, 20 + len(matched_flags) * 8)
        risk_level = "Low"

    # Confidence calculation:
    # Based on number of distinct categories matched and message length
    char_len = len(text.strip())
    if char_len < 30 and len(matched_flags) <= 1:
        confidence = "Low"
    elif len(categories_hit) >= 2 or len(matched_flags) >= 3 or (has_high and len(matched_flags) >= 2):
        confidence = "High"
    else:
        confidence = "Medium"

    return matched_flags, score, risk_level, confidence, match_spans


def generate_highlighted_spans(text: str, match_spans: List[Tuple[int, int, str, str]]) -> List[HighlightSpan]:
    """
    Builds clean non-overlapping character spans of text indicating flagged sections.
    """
    if not text:
        return []
    if not match_spans:
        return [HighlightSpan(text=text, is_flagged=False)]

    # Sort spans by start position, then by length descending
    sorted_spans = sorted(match_spans, key=lambda s: (s[0], -(s[1] - s[0])))
    
    # Merge overlapping/adjacent intervals
    merged: List[Tuple[int, int, str, str]] = []
    for cur_start, cur_end, cur_id, cur_sev in sorted_spans:
        if not merged:
            merged.append((cur_start, cur_end, cur_id, cur_sev))
        else:
            prev_start, prev_end, prev_id, prev_sev = merged[-1]
            if cur_start < prev_end:
                # Overlap: keep maximum end
                new_end = max(prev_end, cur_end)
                # Keep high severity if either was high
                new_sev = "high" if "high" in (prev_sev, cur_sev) else prev_sev
                merged[-1] = (prev_start, new_end, prev_id, new_sev)
            else:
                merged.append((cur_start, cur_end, cur_id, cur_sev))

    result: List[HighlightSpan] = []
    idx = 0
    total_len = len(text)

    for start, end, rule_id, severity in merged:
        start = max(0, min(start, total_len))
        end = max(0, min(end, total_len))

        if start > idx:
            result.append(HighlightSpan(text=text[idx:start], is_flagged=False))
        if end > start:
            result.append(
                HighlightSpan(
                    text=text[start:end],
                    is_flagged=True,
                    rule_id=rule_id,
                    severity=severity
                )
            )
        idx = max(idx, end)

    if idx < total_len:
        result.append(HighlightSpan(text=text[idx:total_len], is_flagged=False))

    return result


def build_rules_report(text: str, lang: str = "en") -> AnalysisReport:
    """
    Builds a complete, deterministic AnalysisReport directly from the rule engine.
    Used as standalone detector or as reliable fallback when LLM is unavailable.
    """
    clean_lang = lang if lang in ("en", "hi", "gu") else "en"
    matched_flags, score, risk_level, confidence, raw_spans = evaluate_rules(text, clean_lang)
    highlighted_spans = generate_highlighted_spans(text, raw_spans)
    sebi_check = check_sebi_registration_number(text, clean_lang)

    # Localized summary and notes
    summaries = {
        "High": {
            "en": "CRITICAL RISK: Multiple severe red flags detected. This message exhibits classic predatory tactics including impossible guarantees or personal payment requests. Do not send money or credentials.",
            "hi": "गंभीर जोखिम: इस संदेश में धोखाधड़ी के कई खतरनाक लक्षण मिले हैं (जैसे पक्के रिटर्न का दावा या निजी खाते में पैसे मांगना)। कोई भी रकम न भेजें और न ही अपनी जानकारी साझा करें।",
            "gu": "ગંભીર જોખમ: આ સંદેશમાં છેતરપિંડીના અનેક ગંભીર લક્ષણો જોવા મળ્યા છે (જેમ કે ખોટી ખાતરી અથવા અંગત ખાતામાં પૈસા માંગવા). કોઈ નાણાં મોકલશો નહીં કે માહિતી આપશો નહીં.",
        },
        "Medium": {
            "en": "MODERATE RISK: Caution advised. Unregulated advisory cues, pressure tactics, or unverified claims found. Verify official credentials on sebi.gov.in before taking any action.",
            "hi": "मध्यम जोखिम: सावधानी आवश्यक है। इसमें जल्दबाजी पैदा करने या अनधिकृत सलाह के संकेत मिले हैं। कोई भी कदम उठाने से पहले sebi.gov.in पर जांच करें।",
            "gu": "મધ્યમ જોખમ: સાવધાની રાખવાની જરૂર છે. ઉતાવળ કરાવવા અથવા બિનસત્તાવાર સલાહના સંકેતો મળ્યા છે. કોઈ પગલું ભરતા પહેલા sebi.gov.in પર ચકાસણી કરો.",
        },
        "Low": {
            "en": "LOW RISK INDICATOR: No prominent predatory scam patterns detected. However, all financial investments carry inherent market risks. Never trade without independent research.",
            "hi": "कम जोखिम: इस संदेश में कोई स्पष्ट धोखाधड़ी के संकेत नहीं मिले हैं। फिर भी, शेयर बाजार में निवेश हमेशा जोखिम के अधीन होता है। स्वयं जांच किए बिना निर्णय न लें।",
            "gu": "ઓછું જોખમ: આ સંદેશમાં છેતરપિંડીના કોઈ સ્પષ્ટ સંકેતો નથી મળ્યા. છતાં, શેરબજારમાં રોકાણ હંમેશા જોખમને આધીન છે. સંપૂર્ણ માહિતી મેળવ્યા વિના રોકાણ કરશો નહીં.",
        },
    }

    uncertainty_notes = {
        "en": "This automated analysis is a risk indicator based on linguistic and regulatory fraud markers, not legal proof. Scammers constantly evolve their wording. Always conduct independent verification.",
        "hi": "यह विश्लेषण धोखाधड़ी के भाषा पैटर्न और नियामक नियमों पर आधारित एक जोखिम संकेतक है, कोई कानूनी प्रमाण नहीं। साइबर ठग लगातार अपने तरीके बदलते हैं। स्वयं सत्यापन अवश्य करें।",
        "gu": "આ વિશ્લેષણ ભાષાકીય સંકેતો અને નિયમો પર આધારિત એક જોખમ સૂચક છે, કાનૂની પુરાવો નથી. સાયબર ઠગો પોતાની ભાષા બદલતા રહે છે. હંમેશા સ્વતંત્ર ચકાસણી કરો.",
    }

    # Promotion vs education
    if risk_level == "High":
        promo = "promotion"
    elif risk_level == "Medium":
        promo = "mixed"
    else:
        promo = "education"

    # Things that look ok (if low/medium)
    things_ok: List[str] = []
    if risk_level == "Low":
        if clean_lang == "hi":
            things_ok = [
                "कोई अवास्तविक निश्चित रिटर्न का दावा नहीं मिला।",
                "ओटीपी, पासवर्ड या रिमोट ऐप का कोई अनुरोध नहीं है।",
                "कोई आपातकालीन दबाव या 'पैसा डबल' करने की योजना नहीं दिखी।"
            ]
        elif clean_lang == "gu":
            things_ok = [
                "ચોક્કસ કે અવાસ્તવિક નફાનો કોઈ દાવો મળ્યો નથી.",
                "ઓટીપી, પાસવર્ડ કે રિમોટ એપ માંગવામાં આવી નથી.",
                "ઉતાવળ કરવાનું કોઈ દબાણ કે પૈસા ડબલ કરવાની સ્કીમ નથી."
            ]
        else:
            things_ok = [
                "No claims of guaranteed or risk-free returns detected.",
                "No requests for passwords, OTPs, or remote screen sharing apps.",
                "Absence of high-pressure 'double money' or Ponzi patterns."
            ]
    elif risk_level == "Medium":
        if clean_lang == "hi":
            things_ok = [
                "ओटीपी या बैंक पिन की सीधी मांग नहीं मिली।"
            ]
        elif clean_lang == "gu":
            things_ok = [
                "ઓટીપી અથવા બેંક પિનની સીધી માંગણી નથી મળી."
            ]
        else:
            things_ok = [
                "No direct demand for banking OTP or UPI PIN detected."
            ]

    # Claim evidence
    claims: List[ClaimEvidence] = []
    if matched_flags:
        for f in matched_flags[:3]:
            claims.append(
                ClaimEvidence(
                    claim=f"Claim: '{f.evidence_quote}'",
                    evidence_status="unverifiable" if f.severity != "high" else "contradicted",
                    note=f.why_it_matters
                )
            )
    else:
        claims.append(
            ClaimEvidence(
                claim="General informational or neutral statement",
                evidence_status="verifiable",
                note="Does not trigger predefined predatory fraud rules." if clean_lang == "en" else "કોઈ શંકાસ્પદ દાવા નથી." if clean_lang == "gu" else "कोई संदिग्ध दावा नहीं मिला।"
            )
        )

    # Next steps (localized, strictly root domains only)
    if clean_lang == "hi":
        next_steps = [
            "किसी भी मध्यस्थ की आधिकारिक वैधता जांचने के लिए केवल आधिकारिक पोर्टल sebi.gov.in पर जाएं।",
            "यदि वित्तीय धोखाधड़ी हुई है, तो तुरंत 1930 पर कॉल करें या cybercrime.gov.in पर शिकायत दर्ज करें।",
            "पूंजी बाजार संबंधी शिकायतों के लिए सेबी के आधिकारिक निवारण पोर्टल scores.sebi.gov.in का उपयोग करें।",
            "अगर आपने गलती से पैसे भेज दिए हैं, तो तुरंत अपने बैंक की हेल्पलाइन पर संपर्क करके खाता ब्लॉक करवाएं।",
            "याद रखें: अपना ओटीपी, यूपीआई पिन कभी किसी के साथ साझा न करें।"
        ]
    elif clean_lang == "gu":
        next_steps = [
            "કોઈપણ સલાહકારની સત્તાવાર માન્યતા ચકાસવા માટે ફક્ત સત્તાવાર પોર્ટલ sebi.gov.in ની મુલાકાત લો.",
            "જો નાણાકીય છેતરપિંડી થઈ હોય, તો તરત જ ૧૯૩૦ પર કૉલ કરો અથવા cybercrime.gov.in પર ફરિયાદ નોંધાવો.",
            "શેરબજાર સંબંધિત ફરિયાદો માટે સેબીના પોર્ટલ scores.sebi.gov.in નો ઉપયોગ કરો.",
            "જો ભૂલથી પૈસા ટ્રાન્સફર થઈ ગયા હોય, તો તાત્કાલિક તમારી બેંકનો સંપર્ક કરો.",
            "યાદ રાખો: ક્યારેય તમારો ઓટીપી કે યુપીઆઈ પિન કોઈને આપશો નહીં."
        ]
    else:
        next_steps = [
            "Verify any intermediary's official registration status directly on sebi.gov.in.",
            "If defrauded or pressured, immediately report to the National Cyber Crime Helpline at 1930 or file a report at cybercrime.gov.in.",
            "Lodge formal grievances regarding securities intermediaries on SEBI's complaint portal at scores.sebi.gov.in.",
            "If payment was transferred, alert your bank's fraud control department immediately to freeze transactions.",
            "Never disclose your OTP, UPI PIN, or passwords, and never install remote-access apps."
        ]

    summary_text = summaries[risk_level].get(clean_lang, summaries[risk_level]["en"])
    uncertainty_text = uncertainty_notes.get(clean_lang, uncertainty_notes["en"])

    return AnalysisReport(
        risk_level=risk_level,
        confidence=confidence,
        score=score,
        summary=summary_text,
        red_flags=matched_flags,
        things_that_look_ok=things_ok,
        uncertainty_note=uncertainty_text,
        promotion_vs_education=promo,
        claim_evidence=claims,
        next_steps=next_steps,
        highlighted_spans=highlighted_spans,
        sebi_registration_check=sebi_check,
        ai_enhanced=False,
        ai_note=None,
    )
