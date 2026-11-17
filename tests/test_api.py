from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["features"]["audio_check"] is True
    assert data["features"]["url_parameter_check"] is True

def test_scam_message():
    response = client.post("/api/analyze", json={"message": "URGENT! Your KYC has expired. Share your OTP immediately or your bank account will be blocked."})
    assert response.status_code == 200
    assert response.json()["verdict"] == "scam"
    assert response.json()["risk_score"] == 100

def test_normal_message():
    response = client.post("/api/analyze", json={"message": "Hello, I will meet you at college tomorrow."})
    assert response.status_code == 200
    assert response.json()["verdict"] == "safe"

def test_bank_otp_sample_is_safe():
    response = client.post(
        "/api/analyze",
        json={"message": "Your bank OTP for the transaction is 123456. Do not share this OTP with anyone."},
    )
    assert response.status_code == 200
    assert response.json()["verdict"] == "safe"

def test_normal_message_sample_is_safe():
    response = client.post(
        "/api/analyze",
        json={"message": "Hi, the class has been moved to 10 AM tomorrow. See you there."},
    )
    assert response.status_code == 200
    assert response.json()["verdict"] == "safe"

def test_empty_message_rejected():
    response = client.post("/api/analyze", json={"message": ""})
    assert response.status_code == 422

def test_url_endpoint_json_body():
    response = client.post("/api/analyze/url", json={"url": "http://verify.account.example.com/login"})
    assert response.status_code == 200
    assert response.json()["verdict"] == "suspicious"

def test_url_checking_parameter_get():
    response = client.get("/api/analyze/url?url=https://example.com")
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "safe"
    assert "url_parameters" in data

def test_url_checking_parameter_post_query():
    response = client.post("/api/analyze/url?url=https://example.com")
    assert response.status_code == 200
    assert response.json()["verdict"] == "safe"

def test_url_endpoint_open_redirect_parameter():
    response = client.post("/api/analyze/url", json={"url": "https://example.com/auth?redirect=http://amaz0n-fake.com"})
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "suspicious"
    assert "redirect" in data["url_parameters"]["flagged"]

def test_audio_endpoint_scam():
    response = client.post(
        "/api/analyze/audio",
        json={
            "transcript": "This is crime branch police narcotics department. Arrest warrant issued. Do not disconnect the call.",
            "duration_seconds": 15.5
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "scam"
    assert data["risk_score"] >= 55
    assert any("police" in r.lower() or "authority" in r.lower() for r in data["reasons"])

def test_audio_endpoint_safe():
    response = client.post(
        "/api/analyze/audio",
        json={
            "transcript": "Hello, this is a reminder from the dental clinic about your appointment tomorrow at 10 AM.",
            "duration_seconds": 8.0
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "safe"
    assert data["risk_score"] < 25

def test_audio_empty_rejected():
    response = client.post("/api/analyze/audio", json={"transcript": ""})
    assert response.status_code == 422


def test_community_reports_api():
    # Test submission
    post_res = client.post(
        "/api/reports",
        json={
            "category": "message",
            "content": "Electricity bill not paid. Power will be cut tonight.",
            "verdict": "scam",
            "risk_score": 85,
            "tactics": ["Utility Threat", "Urgency Pressure"],
            "notes": "Test report from hackathon suite",
            "reporter_contact": "user@test.org"
        }
    )
    assert post_res.status_code == 200
    res_data = post_res.json()
    assert res_data["status"] == "success"
    assert "report" in res_data
    assert res_data["report"]["category"] == "message"

    # Test feed
    feed_res = client.get("/api/reports/feed?limit=5")
    assert feed_res.status_code == 200
    feed_data = feed_res.json()
    assert feed_data["status"] == "success"
    assert feed_data["count"] > 0
    assert len(feed_data["reports"]) <= 5

    # Test stats
    stats_res = client.get("/api/reports/stats")
    assert stats_res.status_code == 200
    stats_data = stats_res.json()
    assert stats_data["total_reports"] >= 1
    assert "categories" in stats_data

    # Clean up test row so tests never pollute live community feed
    import sqlite3
    from app.database import DB_PATH
    with sqlite3.connect(str(DB_PATH)) as conn:
        conn.execute("DELETE FROM scam_reports WHERE notes = 'Test report from hackathon suite'")
        conn.commit()


def test_leetspeak_and_evasion_detection():
    # Message using @, 0, and dots to evade simple regex
    evasive_msg = "URG3NT! Your k.y.c has expired. Sh@re your 0TP immediately or account will be bl0cked."
    response = client.post("/api/analyze", json={"message": evasive_msg})
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "scam"
    assert data["risk_score"] >= 60
    assert "tactics" in data
    assert "Credential Harvesting" in data["tactics"] or "Urgency Pressure" in data["tactics"]


def test_hinglish_disconnection_scam():
    hinglish_msg = "Aapka bijli connection aaj raat 9:30 baje cut kar diya jayega. Turant sampark kare 9876543210."
    response = client.post("/api/analyze", json={"message": hinglish_msg})
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] in ["scam", "suspicious"]
    assert any("electricity" in r.lower() or "hinglish" in r.lower() or "disconnection" in r.lower() for r in data["reasons"])


def test_homoglyph_url_detection():
    # Lookalike using Cyrillic 'a' (\u0430)
    fake_paypal = "https://p\u0430ypal.com/verify"
    response = client.post("/api/analyze/url", json={"url": fake_paypal})
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "suspicious"
    assert data["risk_score"] >= 40
    assert any("homoglyph" in r.lower() for r in data["reasons"])


def test_upi_intent_detection():
    upi_link = "upi://pay?pa=scammer@okaxis&pn=BonusPrize&am=5000&tn=Claim_Lottery_Refund"
    response = client.post("/api/analyze/url", json={"url": upi_link})
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "suspicious"
    assert any("upi" in r.lower() for r in data["reasons"])
    assert any("refund" in r.lower() or "pin" in r.lower() for r in data["reasons"])


def test_audio_file_upload_endpoint():
    dummy_wav_content = b"RIFF\x24\x00\x00\x00WAVEfmt \x10\x00\x00\x00\x01\x00\x01\x00\x44\xac\x00\x00\x88\x58\x01\x00\x02\x00\x10\x00data\x00\x00\x00\x00"
    files = {"file": ("call_sample.wav", dummy_wav_content, "audio/wav")}
    response = client.post("/api/analyze/audio/upload", files=files)
    assert response.status_code == 200
    data = response.json()
    assert "filename" in data or "file_info" in data
    assert data["verdict"] in ["scam", "suspicious"]


def test_ml_model_integration():
    # 1. Health check verifies model is loaded
    health_res = client.get("/api/health")
    assert health_res.status_code == 200
    health_data = health_res.json()
    assert health_data["model_loaded"] is True
    assert "ml_model" in health_data
    assert health_data["ml_model"]["status"] == "active"

    # 2. Message analysis includes ML analysis block
    scam_res = client.post(
        "/api/analyze",
        json={"message": "Dear customer, your bank account access will be terminated tonight. Please verify your identity quickly."}
    )
    assert scam_res.status_code == 200
    scam_data = scam_res.json()
    assert "ml_analysis" in scam_data
    assert scam_data["ml_analysis"]["scam_probability"] >= 0.50
    assert len(scam_data["ml_analysis"]["influential_keywords"]) > 0

    # 3. Legitimate message has low ML probability
    safe_res = client.post(
        "/api/analyze",
        json={"message": "Hey team, the project meeting is confirmed for 2 PM in room 4."}
    )
    assert safe_res.status_code == 200
    safe_data = safe_res.json()
    assert safe_data["ml_analysis"]["scam_probability"] < 0.50
    assert safe_data["verdict"] == "safe"
