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
