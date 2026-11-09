from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_frontend_serves_html():
    response = client.get("/")
    assert response.status_code == 200
    html = response.text
    # Verify dark mode toggle is present
    assert 'id="theme-toggle"' in html
    assert 'data-theme' in html or 'theme-toggle' in html
    # Verify audio pane controls are present
    assert 'id="audio-pane"' in html
    assert 'id="record-btn"' in html
    assert 'id="audio-file-input"' in html
    assert 'data-audio-sample="digital_arrest"' in html
    # Verify URL checking parameter samples and inputs are present
    assert 'id="url-input"' in html
    assert 'data-url=' in html
    assert 'redirect' in html

def test_frontend_serves_css():
    response = client.get("/static/style.css")
    assert response.status_code == 200
    css = response.text
    # Verify dark theme variables and styling exist
    assert '[data-theme="dark"]' in css
    assert '.theme-toggle' in css
    # Verify audio styles exist
    assert '.record-btn' in css
    assert '.audio-upload-label' in css
    # Verify parameter pill styles exist
    assert '.param-badge' in css
    assert '.param-pill' in css

def test_frontend_serves_js():
    response = client.get("/static/app.js")
    assert response.status_code == 200
    js = response.text
    # Verify dark mode logic exists
    assert 'initTheme' in js
    assert 'scamshield_theme' in js
    # Verify audio options exist
    assert 'audioSamples' in js
    assert 'startRecording' in js
    # Verify url parameter handling exists
    assert 'handleUrlParametersOnLoad' in js
    assert 'URLSearchParams' in js

