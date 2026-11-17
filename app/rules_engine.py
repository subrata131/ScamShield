import re
from app.ml_model import predict_text

SCAM_RULES = [
    {
        "code": "OTP_REQUEST",
        "pattern": r"\b(share|send|reveal|provide|tell us)\s+(your\s+)?(otp|pin|password|cvv)\b",
        "reason": "Asks you to share a one-time password, PIN, password or CVV.",
        "weight": 35,
        "tactic": "Credential Harvesting",
    },
    {
        "code": "KYC_EXPIRED",
        "pattern": r"\b(kyc\s+(has\s+)?expired|update\s+your\s+kyc|pan\s+(card\s+)?(blocked|inactive|suspended)|update\s+(your\s+)?pan)\b",
        "reason": "Claims your KYC or PAN has expired, is inactive, or must be updated.",
        "weight": 25,
        "tactic": "Credential Harvesting",
    },
    {
        "code": "ACCOUNT_THREAT",
        "pattern": r"\b(account|bank account|sim card|debit card)\s+(will be|has been)\s+(blocked|suspended|deactivated|frozen)\b",
        "reason": "Threatens to block, freeze, or suspend an account or service.",
        "weight": 25,
        "tactic": "Urgency Pressure",
    },
    {
        "code": "URGENT_PRESSURE",
        "pattern": r"\b(urgent|immediately|act now|within 24 hours|last warning|tonight by|immediately contact)\b",
        "reason": "Uses urgent language to pressure you into acting quickly without thinking.",
        "weight": 15,
        "tactic": "Urgency Pressure",
    },
    {
        "code": "PRIZE_BAIT",
        "pattern": r"\b(you have won|claim your prize|won a lottery|free prize|lucky draw|kbc lottery|cashback reward)\b",
        "reason": "Promises an unearned prize, lottery reward, or fake cashback.",
        "weight": 25,
        "tactic": "Financial Greed Bait",
    },
    {
        "code": "ADVANCE_FEE",
        "pattern": r"\b(pay (a |the )?(processing fee|advance fee)|send money to claim|deposit registration fee)\b",
        "reason": "Requests an advance payment to release a prize, job, loan, or service.",
        "weight": 30,
        "tactic": "Financial Coercion",
    },
    {
        "code": "ELECTRICITY_DISCONNECT",
        "pattern": r"\b(electricity|power|bijli)\s+(will be|is to be)?\s*(disconnected|cut|suspended)\b|\belectricity\s+officer\b|\bcall\s+electricity\s+helpline\b",
        "reason": "Impersonates utility or electricity board threatening imminent power disconnection.",
        "weight": 35,
        "tactic": "Utility Disconnection Threat",
    },
    {
        "code": "TASK_TELEGRAM_SCAM",
        "pattern": r"\b(like youtube videos|earn \d+ daily|telegram hr|part[- ]time job|daily payment of rs|work from home earn)\b",
        "reason": "Promotes high-yield part-time task scams or suspicious Telegram recruitment.",
        "weight": 30,
        "tactic": "Task Scam / Work Bait",
    },
    {
        "code": "MALICIOUS_APK_SIDELOAD",
        "pattern": r"\b(download|install)\s+([a-zA-Z0-9_\-\.]+\.apk|support app|quicksupport)\b|\b(sbi|yono|bank|rewards?|update)\.apk\b",
        "reason": "Directs you to download an untrusted APK package or remote control software.",
        "weight": 40,
        "tactic": "Malicious Sideloading",
    },
    {
        "code": "DIGITAL_ARREST_MSG",
        "pattern": r"\b(digital arrest|narcotics bureau|crime branch|cbi officer|customs seizure|illegal parcel seized)\b",
        "reason": "Fabricates legal or law enforcement threats like digital arrest or seized contraband.",
        "weight": 45,
        "tactic": "Authority Impersonation",
    },
    {
        "code": "HINGLISH_THREAT",
        "pattern": r"\b(account band ho|bijli kat|turant sampark kare|turant update kare|lottery lag gaya|aaj raat 9:30)\b",
        "reason": "Uses Hindi/Hinglish coercive phrasing threatening immediate service termination.",
        "weight": 30,
        "tactic": "Fear & Urgency Coercion",
    },
    {
        "code": "UPI_PIN_RECEIVE_FRAUD",
        "pattern": r"\b(enter (your )?upi pin to (receive|claim|get)|accept money enter pin|enter 6 digit pin to receive)\b",
        "reason": "Misleadingly asks for UPI PIN to receive funds. Entering a PIN always sends money, never receives.",
        "weight": 45,
        "tactic": "Credential Harvesting",
    },
]

AUDIO_SCAM_RULES = [
    {
        "code": "AUDIO_AUTHORITY_IMPERSONATION",
        "pattern": r"\b(police|cbi|customs|narcotics|crime branch|arrest warrant|digital arrest|supreme court|high court|income tax department|tax officer|cyber crime branch|ed officer|nia officer)\b",
        "reason": "Caller claims to be from police, customs, tax, CBI, or law enforcement threatening legal action.",
        "weight": 45,
        "tactic": "Authority Impersonation",
    },
    {
        "code": "AUDIO_COERCION_ISOLATION",
        "pattern": r"\b(do not (disconnect|hang up|cut the call)|stay on the (call|line)|keep (the )?call connected|do not tell anyone|confidential investigation|digital custody|room lock)\b",
        "reason": "Uses coercive pressure demanding you stay on the call or isolate yourself from family and legal counsel.",
        "weight": 35,
        "tactic": "Isolation / Digital Custody",
    },
    {
        "code": "AUDIO_REMOTE_ACCESS",
        "pattern": r"\b(download|install)\s+(anydesk|teamviewer|rustdesk|quicksupport|screen share|screen mirroring)\b",
        "reason": "Instructs you to install screen-sharing or remote-access applications to take over your device.",
        "weight": 40,
        "tactic": "Remote Device Takeover",
    },
    {
        "code": "AUDIO_SAFE_TRANSFER",
        "pattern": r"\b(transfer (money|funds)|send money)\s+(to\s+)?(a\s+)?(safe|secure|rbi|verification|government|secret)\s+account\b",
        "reason": "Instructs you to transfer money to a supposed 'safe' or 'RBI verification' bank account.",
        "weight": 45,
        "tactic": "Financial Coercion",
    },
    {
        "code": "AUDIO_PARCEL_DRUGS",
        "pattern": r"\b(parcel|courier|consignment|fedex|dhl)\s+(contains?|having)\s+(drugs|illegal|narcotics|contraband|passport|mdma|weed)\b",
        "reason": "Alleges an illegal parcel or contraband was seized under your identity or Aadhaar card.",
        "weight": 40,
        "tactic": "False Contraband Allegation",
    },
]


def normalize_leetspeak(text: str) -> str:
    """Decodes common leetspeak substitutions and removes obfuscating intra-word separators."""
    normalized = re.sub(r"(?<=\b[a-zA-Z0-9])[\.\-_/\s](?=[a-zA-Z0-9]\b)", "", text)
    substitutions = {
        "@": "a",
        "0": "o",
        "$": "s",
        "3": "e",
        "5": "s",
        "7": "t",
        "!": "i",
        "|": "i",
    }
    for char, replacement in substitutions.items():
        normalized = normalized.replace(char, replacement)
    return normalized


def analyze_message(message: str) -> dict:
    clean_message = message.strip()
    reasons = []
    matched_rules = []
    tactics = []
    rule_score = 0

    normalized_text = normalize_leetspeak(clean_message)

    for rule in SCAM_RULES:
        match = re.search(rule["pattern"], clean_message, re.IGNORECASE) or re.search(
            rule["pattern"], normalized_text, re.IGNORECASE
        )
        if match:
            rule_score += rule["weight"]
            matched_rules.append(rule["code"])
            reasons.append(rule["reason"])
            tactic = rule.get("tactic")
            if tactic and tactic not in tactics:
                tactics.append(tactic)

    # Machine Learning NLP Evaluation
    ml_pred = predict_text(clean_message)
    scam_prob = ml_pred.get("scam_probability", 0.0)

    # Hybrid Ensemble Scoring
    if rule_score > 0:
        score = min(rule_score, 100)
    elif scam_prob >= 0.70:
        score = int(scam_prob * 100)
        reasons.append(f"Machine learning NLP model detected high-risk scam probability ({int(scam_prob * 100)}%).")
        if ml_pred.get("influential_keywords"):
            reasons.append(f"Suspicious intent terms identified by ML: {', '.join(ml_pred['influential_keywords'])}.")
        if "Subtle Social Engineering Intent" not in tactics:
            tactics.append("Subtle Social Engineering Intent")
    elif scam_prob >= 0.55:
        score = 30
        reasons.append(f"Machine learning model flagged subtle suspicious phrasing ({int(scam_prob * 100)}% scam likelihood).")
    else:
        score = 0

    score = min(score, 100)
    if score >= 60:
        verdict = "scam"
        advice = (
            "High risk scam detected: Do not click any links, do not share OTPs, PINs, or banking details. "
            "Never transfer funds to 'safe accounts'. Report cyber fraud immediately on 1930 or cybercrime.gov.in."
        )
    elif score >= 25:
        verdict = "suspicious"
        advice = (
            "Caution: Suspicious indicators found. Pause and verify the request directly using the organisation's "
            "verified telephone number or official mobile app before taking any action."
        )
    else:
        verdict = "safe"
        advice = "No known warning patterns were detected. This does not guarantee the message is genuine."

    return {
        "message": clean_message,
        "verdict": verdict,
        "risk_score": score,
        "reasons": reasons,
        "matched_rules": matched_rules,
        "tactics": tactics,
        "ml_analysis": {
            "model_used": ml_pred.get("model"),
            "scam_probability": scam_prob,
            "confidence": ml_pred.get("confidence"),
            "influential_keywords": ml_pred.get("influential_keywords", [])
        },
        "method": "hybrid_ml_and_heuristics",
        "advice": advice,
        "disclaimer": "Automated ScamShield assessment combining machine learning NLP and threat heuristics. A low score does not prove that a message is genuine.",
    }


def analyze_audio(transcript: str, duration_seconds: float | None = None) -> dict:
    clean_transcript = transcript.strip()
    if not clean_transcript:
        return {
            "transcript": "",
            "verdict": "invalid",
            "risk_level": "unknown",
            "risk_score": 0,
            "reasons": ["No speech or audio transcript provided to analyze."],
            "advice": "Speak into your microphone, upload an audio recording, or select a sample call.",
            "duration_seconds": duration_seconds,
            "tactics": [],
            "method": "audio_heuristics",
            "disclaimer": "Audio prototype analysis. A low score does not guarantee legitimacy.",
        }

    reasons = []
    matched_rules = []
    tactics = []
    rule_score = 0

    combined_rules = AUDIO_SCAM_RULES + SCAM_RULES

    for rule in combined_rules:
        if re.search(rule["pattern"], clean_transcript, re.IGNORECASE):
            if rule["code"] not in matched_rules:
                rule_score += rule["weight"]
                matched_rules.append(rule["code"])
                reasons.append(rule["reason"])
                tactic = rule.get("tactic")
                if tactic and tactic not in tactics:
                    tactics.append(tactic)

    # ML Analysis on Call Transcript
    ml_pred = predict_text(clean_transcript)
    scam_prob = ml_pred.get("scam_probability", 0.0)

    if rule_score > 0:
        score = min(rule_score, 100)
    elif scam_prob >= 0.70:
        score = int(scam_prob * 100)
        reasons.append(f"Machine learning NLP model detected high call scam likelihood ({int(scam_prob * 100)}%).")
    else:
        score = 0

    score = min(score, 100)
    if score >= 55:
        verdict = "scam"
        risk_level = "high"
        advice = (
            "High risk call: Hang up immediately. Government authorities, police, customs, and banks "
            "never issue digital arrests, demand OTPs, or order urgent money transfers over the phone. "
            "Call 1930 to report cyber fraud if threatened."
        )
    elif score >= 25:
        verdict = "suspicious"
        risk_level = "medium"
        advice = (
            "Caution: This call exhibits suspicious pressure or verification tactics. "
            "Do not share OTPs, passwords, or install remote-control applications. "
            "Disconnect and call the institution back on their official verified number."
        )
    else:
        verdict = "safe"
        risk_level = "low"
        advice = (
            "No common scam call coercion or deception patterns were detected. "
            "Always remain vigilant and never disclose banking credentials or OTPs on unexpected calls."
        )

    return {
        "transcript": clean_transcript,
        "verdict": verdict,
        "risk_level": risk_level,
        "risk_score": score,
        "reasons": reasons,
        "matched_rules": matched_rules,
        "tactics": tactics,
        "ml_analysis": {
            "model_used": ml_pred.get("model"),
            "scam_probability": scam_prob,
            "confidence": ml_pred.get("confidence")
        },
        "duration_seconds": duration_seconds,
        "method": "hybrid_audio_ml_heuristics",
        "advice": advice,
        "disclaimer": (
            "ScamShield audio analysis evaluates spoken call patterns, ML classification, and transcripts. "
            "It does not replace human caution or official authority verification."
        ),
    }
