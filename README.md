# ScamShield

A beginner-friendly full-stack prototype for explainable scam-message, suspicious-URL, and audio call checks.

## Features in this build

- **Dark Mode**: Fully accessible light/dark theme toggle with automatic system theme preference detection (`prefers-color-scheme`) and persistence across sessions via `localStorage`.
- **Audio Check Option**:
  - Live microphone voice recording and real-time speech-to-text dictation (Web Speech API + MediaRecorder).
  - Audio file upload support (`.mp3`, `.wav`, `.m4a`, `.ogg`, `.webm`) with in-browser audio preview.
  - Simulated high-risk call scenarios (Digital arrest / police extortion, Bank KYC expiry OTP threats, Lottery fee fraud, Legitimate appointments).
  - Text-to-speech audition ("Listen Call") to hear scenarios spoken aloud.
  - Dedicated `/api/analyze/audio` endpoint with phone-call intimidation and scam heuristics.
- **URL Parameter Checking**:
  - Deep query parameter inspection detecting open redirects (`?redirect=`, `?url=`), plaintext credential leaks (`?token=`, `?password=`, `?otp=`), dangerous executable downloads (`.exe`, `.apk`), and embedded script payloads.
  - URL parameter API support: `GET /api/analyze/url?url=...` and `POST /api/analyze/url` with query parameter or JSON body.
  - Browser query parameter deep linking: Open `/?url=https://...` or `/?message=...` or `/?audio=...` to prefill and analyze automatically.
  - "Copy check link" button to share parameterized check results.
- **FastAPI backend** with `/api/health`, `/api/analyze`, `/api/analyze/url`, and `/api/analyze/audio`.
- **Rule-based message analysis** with plain-language explanations.
- **URL heuristics** that inspect the address and query parameters as text only; the server never visits user-supplied URLs.
- **Responsive frontend** with Message / Link / Audio tabs, sample chips, verdict-first results, risk meter, reasons, next-step advice, report modal, feedback controls, and safety tips.
- **Automated pytest test suite** covering API endpoints, URL parameter heuristics, audio analysis, and frontend assets.

## Setup on Windows PowerShell

Open a terminal in the project folder:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pytest -v
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000` for the frontend and `http://127.0.0.1:8000/docs` for API documentation.

Deep linking with URL parameters:
- `http://127.0.0.1:8000/?url=https://example.com/login?redirect=http://amaz0n-fake.com`
- `http://127.0.0.1:8000/?tab=audio`

## Project layout

```text
ScamShield/
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── rules_engine.py
│   └── url_checker.py
├── frontend/
│   ├── index.html
│   ├── style.css
│   └── app.js
├── tests/
│   ├── test_api.py
│   ├── test_frontend_assets.py
│   ├── test_url_checker.py
│   └── test_urls.py
├── requirements.txt
├── .gitignore
└── README.md
```
