from app.url_checker import analyze_url

def test_empty_url():
    assert analyze_url("")["verdict"] == "invalid"

def test_http_warning():
    result = analyze_url("http://example.com")
    assert result["risk_score"] == 20

def test_suspicious_url():
    result = analyze_url("http://verify.account.example.com/login")
    assert result["verdict"] == "suspicious"

def test_regular_https_url():
    result = analyze_url("https://example.com")
    assert result["verdict"] == "safe"
    assert result["risk_score"] == 0
