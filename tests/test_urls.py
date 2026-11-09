from app.url_checker import analyze_url

def test_url_open_redirect_parameter():
    url = "https://example.com/login?redirect=https://amaz0n-fake.com/auth"
    result = analyze_url(url)
    assert result["verdict"] == "suspicious"
    assert "redirect" in result["url_parameters"]["flagged"]
    assert any("open-redirect parameter" in r for r in result["reasons"])

def test_url_credential_parameter():
    url = "https://example.com/verify?token=secret123&otp=998877"
    result = analyze_url(url)
    assert result["verdict"] == "suspicious"
    assert "token" in result["url_parameters"]["flagged"] or "otp" in result["url_parameters"]["flagged"]
    assert any("sensitive credentials" in r for r in result["reasons"])

def test_url_executable_parameter():
    url = "https://example.com/download?file=patch.exe"
    result = analyze_url(url)
    assert result["verdict"] == "suspicious"
    assert "file" in result["url_parameters"]["flagged"]

def test_url_safe_parameters():
    url = "https://example.com/search?q=weather&page=2"
    result = analyze_url(url)
    assert result["verdict"] == "safe"
    assert len(result["url_parameters"]["flagged"]) == 0
