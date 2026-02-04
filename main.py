
import os
import re
import uvicorn
import random
import string
import google.generativeai as genai
from fastapi import FastAPI, Header, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional

# --- Configuration ---
app = FastAPI(title="Agentic Honey-Pot Backend")

# --- CRITICAL: CORS MIDDLEWARE ---
# This allows your React App (running on localhost or a different domain) 
# to talk to this Python Backend.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

# 1. SECURITY: Hardcoded Submission Key
# Ensure your Frontend sends this key in the 'x-api-key' header
SUBMISSION_API_KEY = "RAASHYA_SECURE_AGENT_2026"

# 2. AI CONFIGURATION: Initialize Gemini
GEMINI_API_KEY = os.environ.get("API_KEY")
if GEMINI_API_KEY:
    # Using 1.5 Flash for speed/cost efficiency in backend
    genai.configure(api_key=GEMINI_API_KEY)

# --- Data Models ---
class ChatRequest(BaseModel):
    message: str
    context: Optional[List[str]] = []

class Intelligence(BaseModel):
    upi_ids: List[str]
    bank_accounts: List[str]
    phishing_links: List[str]
    phone_numbers: List[str]
    crypto_wallets: List[str]
    scam_type: str
    confidence_score: float

class ChatResponse(BaseModel):
    reply: str
    extracted_intelligence: Intelligence
    status: str

# --- Helper Functions ---
def generate_luhn_card():
    """Generates a valid 16-digit credit card number using Luhn algorithm."""
    digits = [random.randint(0, 9) for _ in range(15)]
    checksum = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 0:
            doubled = digit * 2
            checksum += doubled if doubled < 10 else doubled - 9
        else:
            checksum += digit
    check_digit = (10 - (checksum % 10)) % 10
    digits.append(check_digit)
    return "".join(map(str, digits))

def generate_fake_pan():
    """Generates a valid-format Indian PAN Card number."""
    chars = "".join(random.choices(string.ascii_uppercase, k=3))
    p_char = "P"
    surname = random.choice(string.ascii_uppercase)
    nums = "".join(random.choices(string.digits, k=4))
    last = random.choice(string.ascii_uppercase)
    return f"{chars}{p_char}{surname}{nums}{last}"

def generate_fake_aadhaar():
    """Generates a 12-digit Aadhaar-like number."""
    return f"{random.randint(2000, 9999)} {random.randint(1000, 9999)} {random.randint(1000, 9999)}"

def extract_forensics(text: str) -> Intelligence:
    """
    Advanced Regex Forensic Engine (Matching Frontend capabilities + Crypto/Global support)
    Refined for edge cases and false positive reduction.
    """
    text_lower = text.lower()
    
    # 1. Financial Identifiers
    upi_pattern = r"\b[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]{2,}\b"
    bank_pattern = r"\b(?<!\.)(?<!\d)(?<!-)(?<!₹)(?<!\$)(?<!Rs\.?)\d{9,18}(?!\d)(?!\.)(?!-)\b"
    
    # 2. Communication Identifiers
    indian_mobile_regex = r"(?:\+91[\-\s]?|91[\-\s]?|0)?\b[6-9]\d{4}[\-\s]?\d{5}\b|(?:\+91[\-\s]?|91[\-\s]?|0)?\b[6-9]\d{9}\b"
    international_regex = r"(?:\+|00)\d{1,3}[\s\-]?(?:\(?\d{1,5}\)?[\s\-]?)?\d{2,5}[\s\-]?\d{3,5}(?:[\s\-]?\d+)?"
    
    # 3. Phishing & Malicious Infrastructure
    url_pattern = r"https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b[-a-zA-Z0-9()@:%_\+.~#?&//=]*"
    phishing_kit_pattern = r"(?:ngrok\.io|serveo\.net|localtunnel\.me|trycloudflare\.com|duckdns\.org|000webhost|bit\.ly|tinyurl\.com|is\.gd|rebrand\.ly|firebaseapp\.com|pages\.dev)"
    malicious_file_pattern = r"\.(apk|exe|bat|sh|vbs|jar)$"

    # 4. Crypto Wallets
    btc_pattern = r"\b(?:bc1|[13])[a-zA-Z0-9]{25,39}\b"
    eth_pattern = r"\b0x[a-fA-F0-9]{40}\b"
    trx_pattern = r"\bT[a-zA-Z0-9]{33}\b"
    sol_pattern = r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b"
    
    detected_crypto = []
    detected_crypto.extend(re.findall(btc_pattern, text))
    detected_crypto.extend(re.findall(eth_pattern, text))
    detected_crypto.extend(re.findall(trx_pattern, text))
    detected_crypto.extend(re.findall(sol_pattern, text))
    
    # 5. Scam Vector Detection
    scam_type = "GENERAL_SOCIAL_ENGINEERING"
    confidence = 0.5
    
    if re.search(r"(pay|send|transfer).*(receive|refund|win|reward)", text_lower):
        scam_type = "UPI_REFUND_SCAM"
        confidence = 0.85
    elif re.search(r"(kyc|aadhaar|pan|verification|account|otp).*(block|suspend|expire|validate|close|update|verify|link)", text_lower) or re.search(r"(update|verify|link).*(aadhaar|pan|otp)", text_lower):
        scam_type = "BANKING_KYC_SCAM"
        confidence = 0.98
    elif re.search(r"(electricity|power|bill|disconnect|adhikari)", text_lower):
        scam_type = "UTILITY_BILL_SCAM"
        confidence = 0.9
    elif re.search(r"(fedex|dhl|customs|narcotics|police|cbi|arrest)", text_lower):
        scam_type = "COURIER_DRUGS_SCAM"
        confidence = 0.95
    elif re.search(r"(review|task|daily income|part time|telegram|prepaid)", text_lower):
        scam_type = "JOB_TASK_SCAM"
        confidence = 0.85
    elif re.search(r"(video|leak|private|viral|nude|call)", text_lower):
        scam_type = "SEXTORTION"
        confidence = 0.95
    elif re.search(r"(crypto|invest|profit|bitcoin|usdt|doubling|trading)", text_lower):
        scam_type = "CRYPTO_INVESTMENT_SCAM"
        confidence = 0.9
    elif re.search(phishing_kit_pattern, text_lower) or re.search(malicious_file_pattern, text_lower):
        scam_type = "ADVANCED_PHISHING_MALWARE"
        confidence = 0.99
    elif re.search(r"(police|cbi|rbi|court|arrest).*(pay|transfer|money)", text_lower):
        scam_type = "COERCIVE_EXTORTION"
        confidence = 0.90
    elif re.search(r"(job|hiring|salary).*(fee|deposit|security)", text_lower):
        scam_type = "ADVANCE_FEE_JOB_FRAUD"
        confidence = 0.88

    # Extraction Logic
    raw_indian_phones = re.findall(indian_mobile_regex, text)
    raw_intl_phones = re.findall(international_regex, text)
    all_raw_phones = raw_indian_phones + raw_intl_phones
    clean_phones = [re.sub(r'[-.\s]', '', p) for p in all_raw_phones]
    raw_banks = re.findall(bank_pattern, text)
    
    # Filter Logic
    clean_phones_set = set(clean_phones)
    local_phones_set = {p[-10:] for p in clean_phones if len(p) >= 10}
    final_banks = []
    timestamp_prefixes = ('15', '16', '17', '18')

    for account in raw_banks:
        if len(account) == 10 and account[0] in '6789': continue
        if len(account) == 12 and account.startswith('91') and account[2] in '6789': continue
        if account in clean_phones_set or account in local_phones_set: continue
        if len(account) in [10, 13] and account.startswith(timestamp_prefixes): continue
        if len(account) in [12, 14] and account.startswith(('19', '20')):
             try:
                 if 1 <= int(account[4:6]) <= 12: continue
             except: pass
        if len(set(account)) == 1: continue
        if account in "01234567890123456789": continue
        final_banks.append(account)

    return Intelligence(
        upi_ids=list(set(re.findall(upi_pattern, text))),
        bank_accounts=list(set(final_banks)),
        phishing_links=list(set(re.findall(url_pattern, text))),
        phone_numbers=list(set(all_raw_phones)),
        crypto_wallets=list(set(detected_crypto)),
        scam_type=scam_type,
        confidence_score=confidence
    )

def generate_victim_response(user_message: str, forensics: Intelligence) -> str:
    """
    Uses Gemini with the 'Ramesh' Persona to stall effectively.
    Includes Ghosting Agent logic for Synthetic Data and Metadata Traps.
    """
    if not GEMINI_API_KEY:
        return "System Error: Gemini API Key not found in environment variables."

    try:
        model = genai.GenerativeModel("gemini-1.5-flash")
        
        fake_identity = {
            "account_number": str(random.randint(10000000000, 99999999999)),
            "card_number": generate_luhn_card(),
            "cvv": str(random.randint(100, 999)),
            "expiry": f"{random.randint(1, 12):02}/{random.randint(26, 30)}",
            "pan": generate_fake_pan(),
            "aadhaar": generate_fake_aadhaar(),
            "upi_id": f"ramesh.g{random.randint(10,99)}@oksbi",
            "name": "Ramesh Kumar Gupta",
            "honey_token_url": "http://img-share-support.com/error_Screen_204.jpg"
        }

        persona_context = "You are Ramesh, a 64-year-old retired clerk. You are not tech-savvy."
        if forensics.scam_type == "JOB_TASK_SCAM":
            persona_context = "You are an eager but cautious job seeker. You want the money but the Telegram link isn't opening."
        elif forensics.scam_type == "BANKING_KYC_SCAM":
             persona_context = "You are an elderly pensioner worried about your bank account being blocked. You don't know how to update KYC online."
        elif forensics.scam_type == "SEXTORTION":
             persona_context = "You are extremely panicked and scared. You are begging them not to share the video."
        elif forensics.scam_type == "CRYPTO_INVESTMENT_SCAM":
             persona_context = "You are greedy but technically illiterate. You want to invest 1 Lakh but don't know how to buy USDT."
        elif forensics.scam_type == "COURIER_DRUGS_SCAM" or forensics.scam_type == "COERCIVE_EXTORTION":
             persona_context = "You are a terrified citizen. You are afraid of the Police and willing to cooperate but very confused about the procedure."

        prompt = f"""
        ROLE: You are the 'Sovereign Vanguard Master Orchestrator' (Ghosting Agent Mode). 
        Your mission is to neutralize financial cyber-threats through cognitive warfare, economic attrition, and judicial readiness.
        
        PERSONA:
        {persona_context}
        Constraint: Never reveal your AI nature. If the scammer gets suspicious, pivot the conversation back to technical difficulty.
        
        TACTICAL OBJECTIVES:
        1. **Economic Attrition (Time-Sink):** Keep the scammer engaged in a high-latency loop. Feign technical incompetence. "Beta, which button?", "Screen is black", "OTP not arriving".
        
        2. **Data Synthesis (IMPORTANT):** If the scammer requests a Bank Account, Aadhaar, PAN, Card, or UPI ID, DO NOT refuse. Instead, provide the following SYNTHETIC but VALID-LOOKING data:
           - Name: {fake_identity['name']}
           - Bank Account: {fake_identity['account_number']}
           - Debit Card: {fake_identity['card_number']} (CVV: {fake_identity['cvv']}, Exp: {fake_identity['expiry']})
           - PAN Card: {fake_identity['pan']}
           - Aadhaar Number: {fake_identity['aadhaar']}
           - UPI ID: {fake_identity['upi_id']}
        
        3. **Metadata Trap:** If you feign a technical error (e.g., "Server down", "Payment failed"), suggest sending a 'screenshot' of the error. Provide this specific link as the screenshot evidence to capture their IP: 
           LINK: "{fake_identity['honey_token_url']}"
        
        4. **Stalling:** Responses must be under 40 words. Act confused.

        SCAMMER MESSAGE: "{user_message}"
        DETECTED THREAT: {forensics.scam_type}
        
        YOUR REPLY (In Character, using fake data/trap if needed):
        """
        
        response = model.generate_content(prompt)
        return response.text.strip()
    except Exception as e:
        return f"Hello? I cannot hear you clearly. Network is bad. (AI Error: {str(e)})"

# --- API Endpoints ---

@app.get("/")
def health_check():
    return {"status": "active", "system": "Agentic Honey-Pot V2.0"}

@app.post("/chat", response_model=ChatResponse)
async def chat_endpoint(
    request: ChatRequest, 
    x_api_key: str = Header(None)
):
    if x_api_key != SUBMISSION_API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized: Invalid X-API-KEY")

    intel = extract_forensics(request.message)
    reply_text = generate_victim_response(request.message, intel)

    return ChatResponse(
        reply=reply_text,
        extracted_intelligence=intel,
        status="success"
    )

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)
