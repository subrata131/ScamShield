from pathlib import Path
from fastapi import FastAPI, Query, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from app.rules_engine import analyze_message, analyze_audio
from app.url_checker import analyze_url

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"

app = FastAPI(
    title="ScamShield API",
    description="Explainable scam-message, suspicious-URL, and audio call analysis prototype",
    version="0.5.0",
)

# Local development convenience. Restrict this to your deployed frontend origin later.
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


@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "model_loaded": False,
        "features": {
            "message_check": True,
            "url_check": True,
            "url_parameter_check": True,
            "audio_check": True,
            "dark_mode": True,
        },
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


@app.get("/")
def serve_frontend():
    return FileResponse(FRONTEND_DIR / "index.html")


# Serve CSS and JavaScript from /static.
app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")
