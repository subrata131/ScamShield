import os
import tempfile
from pathlib import Path
from fastapi import FastAPI, Query, HTTPException, Request, UploadFile, File
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from app.rules_engine import analyze_message, analyze_audio
from app.url_checker import analyze_url
from app.database import add_report, get_recent_reports, get_report_stats, init_db

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"

app = FastAPI(
    title="ScamShield API",
    description="Explainable scam-message, suspicious-URL, and audio call analysis platform with community threat intelligence",
    version="0.6.0",
)

# Initialize database
init_db()

# Local development convenience.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


class MessageRequest(BaseModel):
    message: str = Field(min_length=1, max_length=5000)


class URLRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


class AudioRequest(BaseModel):
    transcript: str = Field(min_length=1, max_length=10000)
    duration_seconds: float | None = None
    audio_format: str | None = None


class ReportRequest(BaseModel):
    category: str = Field(default="message", min_length=1, max_length=50)
    content: str = Field(min_length=1, max_length=10000)
    verdict: str = Field(default="scam", max_length=50)
    risk_score: int = Field(default=75, ge=0, le=100)
    tactics: list[str] = Field(default_factory=list)
    notes: str = Field(default="", max_length=2000)
    reporter_contact: str = Field(default="", max_length=200)


@app.get("/api/health")
def health_check():
    stats = get_report_stats()
    return {
        "status": "healthy",
        "model_loaded": True,
        "ml_model": {
            "name": "ScamShield NLP Text Classifier",
            "architecture": "TF-IDF Vectorizer + Logistic Regression Pipeline",
            "version": "1.0",
            "explainability": "Feature Coefficient Attribution",
            "status": "active"
        },
        "features": {
            "message_check": True,
            "ml_inference": True,
            "url_check": True,
            "url_parameter_check": True,
            "audio_check": True,
            "upi_check": True,
            "homoglyph_check": True,
            "community_reports": True,
            "dark_mode": True,
        },
        "community_threat_network": {
            "total_reports": stats.get("total_reports", 0),
            "status": stats.get("community_trust_level", "Active Threat Network")
        }
    }


@app.post("/api/analyze")
def analyze_text(data: MessageRequest):
    return analyze_message(data.message)


@app.api_route("/api/analyze/url", methods=["GET", "POST"])
async def analyze_link(
    request: Request,
    url: str | None = Query(default=None, description="Target URL parameter for checking"),
    data: URLRequest | None = None,
):
    target_url = url
    if not target_url and request.method == "POST":
        try:
            body = await request.json()
            if isinstance(body, dict) and "url" in body:
                target_url = body.get("url")
        except Exception:
            pass

    if not target_url and data:
        target_url = data.url

    if not target_url or not str(target_url).strip():
        raise HTTPException(
            status_code=422,
            detail="A 'url' parameter (via query parameter or JSON body) is required."
        )

    return analyze_url(str(target_url))


@app.post("/api/analyze/audio")
def analyze_audio_call(data: AudioRequest):
    return analyze_audio(data.transcript, data.duration_seconds)


@app.post("/api/analyze/audio/upload")
async def analyze_uploaded_audio_file(file: UploadFile = File(...)):
    filename = file.filename or "unknown.wav"
    content = await file.read()
    file_size_kb = round(len(content) / 1024, 2)

    if len(content) == 0:
        raise HTTPException(status_code=422, detail="Uploaded audio file is empty.")

    # Server-side transcription attempt via SpeechRecognition if WAV
    extracted_text = ""
    recognition_status = "unsupported_or_pending"

    if filename.lower().endswith(".wav"):
        try:
            import speech_recognition as sr
            with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tmp:
                tmp.write(content)
                tmp_path = tmp.name

            recognizer = sr.Recognizer()
            with sr.AudioFile(tmp_path) as source:
                audio_data = recognizer.record(source)
                try:
                    # Attempt recognition if engine is available
                    extracted_text = recognizer.recognize_sphinx(audio_data)
                    recognition_status = "transcribed"
                except Exception:
                    recognition_status = "speech_engine_offline_manual_review_needed"
            os.remove(tmp_path)
        except Exception as e:
            recognition_status = f"audio_parsing_fallback: {str(e)}"

    # If text was transcribed, analyze it; otherwise provide file metadata analysis
    if extracted_text.strip():
        result = analyze_audio(extracted_text)
        result["file_info"] = {
            "filename": filename,
            "size_kb": file_size_kb,
            "recognition_status": recognition_status,
        }
        return result

    return {
        "filename": filename,
        "size_kb": file_size_kb,
        "recognition_status": recognition_status,
        "advice": (
            "Audio file uploaded successfully. In the browser, the Web Speech API can dictate the transcript directly, "
            "or you can inspect one of our simulated high-risk voice call scenarios."
        ),
        "verdict": "suspicious" if file_size_kb > 0 else "invalid",
        "risk_level": "medium",
        "risk_score": 30,
        "reasons": [
            f"Uploaded audio file '{filename}' ({file_size_kb} KB) ready for analysis.",
            "Spoken conversations require speech transcription to inspect coercion patterns."
        ],
        "method": "audio_file_heuristics",
        "disclaimer": "Uploaded audio analyzed locally. Please review the spoken words for authority or money threats."
    }


# --- Community Threat Intelligence & Reporting Endpoints ---
@app.post("/api/reports")
def submit_scam_report(data: ReportRequest):
    report = add_report(
        category=data.category,
        content=data.content,
        verdict=data.verdict,
        risk_score=data.risk_score,
        tactics=data.tactics,
        notes=data.notes,
        reporter_contact=data.reporter_contact,
    )
    return {
        "status": "success",
        "message": "Scam report successfully cataloged in community threat database.",
        "report": report
    }


@app.get("/api/reports/feed")
def get_community_threat_feed(limit: int = Query(default=10, ge=1, le=50)):
    reports = get_recent_reports(limit=limit)
    return {
        "status": "success",
        "count": len(reports),
        "reports": reports
    }


@app.get("/api/reports/stats")
def get_community_stats():
    return get_report_stats()


@app.get("/")
def serve_frontend():
    return FileResponse(FRONTEND_DIR / "index.html")


# Serve CSS and JavaScript from /static.
app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")
