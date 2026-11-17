import os
from pathlib import Path
import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

MODEL_DIR = Path(__file__).resolve().parent / "models"
MODEL_PATH = MODEL_DIR / "scam_classifier.joblib"

# Comprehensive curated training corpus of real-world scam and legitimate messages
TRAINING_DATA = [
    # --- SCAM SAMPLES (Class 1) ---
    ("URGENT: Your bank KYC has expired. Update immediately or your bank account will be suspended within 24 hours.", 1),
    ("Dear SBI user, your netbanking has been blocked due to missing PAN. Click here to verify your details.", 1),
    ("Your bank OTP is 948210. Share this OTP with our verification executive to unblock your account.", 1),
    ("Congratulations! You have won a cash prize of 25,00,000 in KBC lottery. Call 9876543210 to claim.", 1),
    ("Dear customer, your electricity power will be disconnected tonight at 9:30 PM due to unpaid bill. Contact officer immediately.", 1),
    ("Earn 3000 to 5000 daily working from home by liking YouTube videos. Contact HR on Telegram @WorkHomeHR.", 1),
    ("This is Mumbai Police Narcotics Branch. An illegal courier containing drugs was seized under your Aadhaar. Stay on the call.", 1),
    ("Digital arrest warrant issued against you by CBI. Do not disconnect the video call or police will arrive at your home.", 1),
    ("Your SIM card will be deactivated in 2 hours due to unverified KYC. Call customer care 9988776655.", 1),
    ("Income tax department has approved your refund of Rs. 15,450. Click link and enter debit card details to receive refund.", 1),
    ("You have won a free iPhone 15 Pro! Pay only Rs. 499 courier fee to deliver to your doorstep.", 1),
    ("Dear customer, download SBI_Rewards.apk to redeem your 9850 reward points worth Rs 4925 immediately.", 1),
    ("Enter your 6-digit UPI PIN to receive cashback reward of Rs 2,000 directly into your bank account.", 1),
    ("Aapka electricity connection aaj raat 9:30 baje cut kar diya jayega. Turant sampark kare.", 1),
    ("Account band ho jayega. Turant apna KYC update kare is link par.", 1),
    ("Work from home part-time job: Guaranteed daily payouts of Rs 4000. Send Rs 500 registration deposit to activate account.", 1),
    ("URG3NT: Sh@re your 0TP immediately with support or your card will be bl0cked.", 1),
    ("Install AnyDesk or QuickSupport on your mobile phone to complete KYC verification with our bank manager.", 1),
    ("Courier seized at airport customs. Foreign currency and narcotics found. Transfer verification penalty to safe government account.", 1),
    ("Dear user, your Netflix subscription expired. Verify your credit card details immediately to avoid account termination.", 1),
    ("Amazon Security: Suspicious login from IP 192.168.1.1. Login to verify your identity: http://amaz0n-security.top/login.", 1),
    ("Your loan of Rs 5,00,000 has been pre-approved without documents. Pay Rs 1500 processing charge to disburse amount.", 1),
    ("Transfer your savings to RBI secure verification account during this confidential money laundering investigation.", 1),
    ("We have detected unauthorized transactions on your debit card. Reveal your CVV and card expiry to block charges.", 1),
    ("Dear user, submit your Aadhaar card and PAN card details on this link to claim PM Kisan subsidy bonus.", 1),
    ("Job Offer: Google hiring remote data entry specialists. Daily earnings Rs 6000. Contact Telegram agent now.", 1),
    ("Immediate action required: Your WhatsApp account will be deleted in 12 hours. Verify your phone number here.", 1),
    ("You have received an unexpected payment of Rs 10,000. Open UPI link and approve the collect request to receive.", 1),
    ("Dear customer, your credit card points are expiring tonight. Redeem for cash reward by clicking link.", 1),
    ("Supreme Court digital custody warrant. You are under surveillance. Do not tell anyone or leave your room.", 1),

    # --- LEGITIMATE / HAM SAMPLES (Class 0) ---
    ("Your bank OTP for transaction of Rs. 450.00 at Swiggy is 482910. Do not share this OTP with anyone.", 0),
    ("Rs. 1,200.00 debited from A/C XX4921 on 15-Nov-2024 at Reliance Fresh. Balance: Rs. 24,530.00.", 0),
    ("Hi, the lecture has been rescheduled to tomorrow at 10 AM in Room 302. See you there.", 0),
    ("Your order #98214 from Amazon has been shipped and will be delivered by tomorrow evening.", 0),
    ("Hello, this is Dr. Sen's clinic reminding you of your dental appointment tomorrow at 11 AM.", 0),
    ("Your electricity bill of Rs. 840 for October has been generated. Due date is 25-Nov. View bill on official portal.", 0),
    ("Flight 6E-204 from Delhi to Mumbai is on time. Web check-in is now open.", 0),
    ("Happy birthday! Wishing you a fantastic day filled with joy, laughter, and success.", 0),
    ("Hey, are we still meeting for lunch at 1 PM today? Let me know.", 0),
    ("Your monthly WiFi broadband plan will renew on 1st of next month. Thank you for using Airtel.", 0),
    ("Please find attached the project meeting minutes and next steps discussed during today's call.", 0),
    ("Your Uber driver Ramesh is arriving in a White Swift Dzire (DL 1Z 4920).", 0),
    ("Your verification code for Discord login is 918234. If you did not request this, please secure your account.", 0),
    ("Dear student, library books are due for return by Friday. You may renew online via the student portal.", 0),
    ("Hi Mom, I reached the hostel safely. Will call you after dinner.", 0),
    ("Your package from Flipkart has been delivered to your front door. Thank you for shopping with us.", 0),
    ("Reminder: Team weekly standup starts in 15 minutes on Google Meet.", 0),
    ("We have received your payment of Rs. 499 for your mobile postpaid bill. Reference ID: TXN998822.", 0),
    ("Can you please review the pull request on GitHub when you have a moment? Thanks!", 0),
    ("Your gym membership is active until 31st December. Stay healthy and fit!", 0),
    ("The weather forecast predicts light rain in Mumbai tomorrow afternoon. Carry an umbrella.", 0),
    ("Hey, I pushed the latest commit to the main branch. Let's run the tests tomorrow morning.", 0),
    ("Your train ticket for 12301 Rajdhani Express is confirmed: Coach B4, Berth 23.", 0),
    ("Hi team, lunch has arrived in the cafeteria on the 3rd floor. Please help yourselves.", 0),
    ("Your password for college portal was successfully changed on 14-Nov. Contact IT admin if you did not do this.", 0),
    ("Good morning! Just checking in on how the hackathon preparation is coming along.", 0),
    ("Thank you for visiting City Hospital. Please rate your consultation experience with Dr. Sharma.", 0),
    ("Your Google Cloud subscription receipt for the month of October is ready for download.", 0),
    ("Hey buddy, do you have the notes from yesterday's computer networks class?", 0),
    ("Your movie tickets for Inception at PVR Cinema are confirmed. Show starts at 7:30 PM.", 0),
]


def train_and_save_model() -> Pipeline:
    """Trains the TF-IDF + Logistic Regression NLP classification pipeline."""
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    
    texts = [item[0] for item in TRAINING_DATA]
    labels = [item[1] for item in TRAINING_DATA]

    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(
            ngram_range=(1, 2),
            sublinear_tf=True,
            max_features=5000,
            lowercase=True
        )),
        ("clf", LogisticRegression(
            C=2.0,
            class_weight="balanced",
            max_iter=1000,
            random_state=42
        ))
    ])

    pipeline.fit(texts, labels)
    joblib.dump(pipeline, MODEL_PATH)
    return pipeline


_MODEL: Pipeline | None = None


def get_model() -> Pipeline:
    """Loads the persisted ML model or trains it on first invocation."""
    global _MODEL
    if _MODEL is not None:
        return _MODEL

    if MODEL_PATH.exists():
        try:
            _MODEL = joblib.load(MODEL_PATH)
            return _MODEL
        except Exception:
            pass

    _MODEL = train_and_save_model()
    return _MODEL


def predict_text(text: str) -> dict:
    """
    Evaluates text with the trained ML classifier.
    Returns probability, confidence level, and feature contribution.
    """
    clean_text = text.strip()
    if not clean_text:
        return {
            "model_loaded": True,
            "scam_probability": 0.0,
            "is_scam": False,
            "confidence": "none",
            "model": "TF-IDF + Logistic Regression",
        }

    model = get_model()
    # Predict probabilities [P(ham), P(scam)]
    probs = model.predict_proba([clean_text])[0]
    scam_prob = float(probs[1])

    # Extract top contributing features (explainable AI)
    vectorizer: TfidfVectorizer = model.named_steps["tfidf"]
    clf: LogisticRegression = model.named_steps["clf"]
    
    feature_names = np.array(vectorizer.get_feature_names_out())
    transformed = vectorizer.transform([clean_text]).toarray()[0]
    coefficients = clf.coef_[0]

    # Feature contribution = tf-idf value * logistic regression weight
    contributions = transformed * coefficients
    top_indices = np.argsort(contributions)[::-1]
    
    influential_keywords = []
    for idx in top_indices:
        if contributions[idx] > 0.05 and len(influential_keywords) < 5:
            influential_keywords.append(feature_names[idx])

    if scam_prob >= 0.70:
        confidence = "high"
    elif scam_prob >= 0.40:
        confidence = "medium"
    else:
        confidence = "low"

    return {
        "model_loaded": True,
        "scam_probability": round(scam_prob, 3),
        "is_scam": scam_prob >= 0.50,
        "confidence": confidence,
        "influential_keywords": influential_keywords,
        "model": "TF-IDF + Logistic Regression (v1.0)",
    }
