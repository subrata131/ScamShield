import re

SCAM_RULES = [
    {
        "code": "OTP_REQUEST",
        "pattern": r"\b(share|send|reveal|provide|tell us)\s+(your\s+)?(otp|pin|password|cvv)\b",
        "reason": "Asks you to share a one-time password, PIN, password or CVV.",
        "weight": 35,
    },
    {
        "code": "KYC_EXPIRED",
        "pattern": r"\b(kyc\s+(has\s+)?expired|update\s+your\s+kyc)\b",
        "reason": "Claims your KYC has expired or must be updated.",
        "weight": 25,
    },
    {
        "code": "ACCOUNT_THREAT",
        "pattern": r"\b(account|bank account)\s+(will be|has been)\s+(blocked|suspended)\b",
        "reason": "Threatens to block or suspend an account.",
        "weight": 25,
    },
    {
        "code": "URGENT_PRESSURE",
        "pattern": r"\b(urgent|immediately|act now|within 24 hours|last warning)\b",
        "reason": "Uses urgent language to pressure you into acting quickly.",
        "weight": 15,
    },
    {
        "code": "PRIZE_BAIT",
        "pattern": r"\b(you have won|claim your prize|won a lottery|free prize)\b",
        "reason": "Promises a prize or lottery reward.",
        "weight": 25,
    },
    {
        "code": "ADVANCE_FEE",
        "pattern": r"\b(pay (a |the )?(processing fee|advance fee)|send money to claim)\b",
        "reason": "Requests an advance payment to release a reward or service.",
        "weight": 30,
    },
]

AUDIO_SCAM_RULES = [
    {
        "code": "AUDIO_AUTHORITY_IMPERSONATION",
        "pattern": r"\b(police|cbi|customs|narcotics|crime branch|arrest warrant|digital arrest|supreme court|high court|income tax department|tax officer|cyber crime branch)\b",
        "reason": "Caller claims to be from police, customs, tax, or law enforcement threatening legal action.",
        "weight": 45,
    },
    {
        "code": "AUDIO_COERCION_ISOLATION",
        "pattern": r"\b(do not (disconnect|hang up|cut the call)|stay on the (call|line)|keep (the )?call connected|do not tell anyone|confidential investigation|digital custody)\b",
        "reason": "Uses coercive pressure demanding you stay on the call or isolate yourself.",
        "weight": 35,
    },
    {
        "code": "AUDIO_REMOTE_ACCESS",
        "pattern": r"\b(download|install)\s+(anydesk|teamviewer|rustdesk|quicksupport|screen share)\b",
        "reason": "Instructs you to install screen-sharing or remote-access applications.",
        "weight": 40,
    },
    {
        "code": "AUDIO_SAFE_TRANSFER",
        "pattern": r"\b(transfer (money|funds)|send money)\s+(to\s+)?(a\s+)?(safe|secure|rbi|verification|government)\s+account\b",
        "reason": "Instructs you to transfer money to a supposed safe or verification bank account.",
        "weight": 45,
    },
    {
        "code": "AUDIO_PARCEL_DRUGS",
        "pattern": r"\b(parcel|courier|consignment)\s+(contains?|having)\s+(drugs|illegal|narcotics|contraband|passport)\b",
        "reason": "Alleges an illegal parcel or contraband was seized under your identity.",
        "weight": 40,
    },
]


def analyze_message(message: str) -> dict:
    clean_message = message.strip()
    reasons = []
    matched_rules = []
    score = 0

    for rule in SCAM_RULES:
        if re.search(rule["pattern"], clean_message, re.IGNORECASE):
            score += rule["weight"]
            matched_rules.append(rule["code"])
            reasons.append(rule["reason"])

    score = min(score, 100)
    if score >= 60:
        verdict = "scam"
        advice = "Do not click links or share money, OTPs or banking details. Verify through the organisation's official app or phone number."
    elif score >= 25:
        verdict = "suspicious"
        advice = "Pause and verify the request using an official channel before taking action."
    else:
        verdict = "safe"
        advice = "No known warning patterns were detected. This does not guarantee the message is genuine."

    return {
        "message": clean_message,
        "verdict": verdict,
        "risk_score": score,
        "reasons": reasons,
        "matched_rules": matched_rules,
        "method": "rule_based",
        "advice": advice,
        "disclaimer": "Prototype assessment only. A low score does not prove that a message is safe.",
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
            "method": "audio_heuristics",
            "disclaimer": "Audio prototype analysis. A low score does not guarantee legitimacy.",
        }

    reasons = []
    matched_rules = []
    score = 0

    combined_rules = AUDIO_SCAM_RULES + SCAM_RULES

    for rule in combined_rules:
        if re.search(rule["pattern"], clean_transcript, re.IGNORECASE):
            if rule["code"] not in matched_rules:
                score += rule["weight"]
                matched_rules.append(rule["code"])
                reasons.append(rule["reason"])

    score = min(score, 100)
    if score >= 55:
        verdict = "scam"
        risk_level = "high"
        advice = (
            "High risk call: Hang up immediately. Government authorities, police, and banks "
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
        "duration_seconds": duration_seconds,
        "method": "audio_heuristics",
        "advice": advice,
        "disclaimer": (
            "ScamShield audio analysis evaluates spoken call patterns and transcripts. "
            "It does not replace human caution or official authority verification."
        ),
    }
