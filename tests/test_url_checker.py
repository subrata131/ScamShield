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


def test_official_bank_domains_are_safe():
    # Legitimate official bank domains must NOT be flagged as brand impersonation
    assert analyze_url("https://www.hdfcbank.com")["verdict"] == "safe"
    assert analyze_url("https://www.icicibank.com")["verdict"] == "safe"
    assert analyze_url("https://www.onlinesbi.sbi")["verdict"] == "safe"
    assert analyze_url("https://paytm.com")["verdict"] == "safe"

    # But phishing lookalikes MUST still be flagged
    assert analyze_url("https://hdfc-verify-login.com")["verdict"] == "suspicious"
    assert analyze_url("https://sbi-rewards.top/login")["verdict"] == "suspicious"
