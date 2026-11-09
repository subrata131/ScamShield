const $ = (id) => document.getElementById(id);

let activeTab = "message";
let lastResult = null;
let lastInput = "";
let lastCheckedType = "message";

// Audio state variables
let mediaRecorder = null;
let audioChunks = [];
let recordTimerInterval = null;
let recordStartTime = 0;
let recordedAudioUrl = null;
let speechRecognizer = null;
let isRecording = false;

// Sample message texts
const messageSamples = {
  scam: "URGENT! Your KYC has expired. Share your OTP immediately or your bank account will be blocked.",
  otp: "Your bank OTP for the transaction is 123456. Do not share this OTP with anyone.",
  prize: "Congratulations! You have won a lottery. Pay a processing fee to claim your prize.",
  normal: "Hi, the class has been moved to 10 AM tomorrow. See you there."
};

// Sample audio call scripts
const audioSamples = {
  digital_arrest: "This is officer Vikram from the Crime Branch Narcotics Bureau. A suspicious package with illegal narcotics has been seized under your Aadhaar number. A digital arrest warrant has been issued. Do not disconnect the call or you will be arrested immediately.",
  kyc_threat: "Hello, this is officer Sharma calling from your bank security division. Your account KYC has expired. Please tell us your six digit OTP immediately or your bank account and debit card will be blocked within two hours.",
  lottery_call: "Congratulations! You have won a cash lottery of twenty-five lakh rupees in our annual lucky draw. To claim your prize, please send an advance processing fee of 2500 rupees right now to our clearance agent.",
  normal_call: "Hello, this is City Medical Clinic reminding you of your doctor appointment tomorrow at 10 AM with Dr. Sen. Please arrive 10 minutes early. Thank you."
};

// --- Theme Management (Dark Mode) ---
function initTheme() {
  const savedTheme = localStorage.getItem("scamshield_theme");
  const systemPrefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
  const initialTheme = savedTheme || (systemPrefersDark ? "dark" : "light");
  applyTheme(initialTheme);

  if (window.matchMedia) {
    window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", (e) => {
      if (!localStorage.getItem("scamshield_theme")) {
        applyTheme(e.matches ? "dark" : "light");
      }
    });
  }
}

function applyTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  const themeToggle = $("theme-toggle");
  const themeText = $("theme-text");
  if (themeToggle && themeText) {
    if (theme === "dark") {
      themeText.textContent = "Light";
      themeToggle.setAttribute("aria-label", "Switch to light mode");
      themeToggle.setAttribute("title", "Switch to light mode");
    } else {
      themeText.textContent = "Dark";
      themeToggle.setAttribute("aria-label", "Switch to dark mode");
      themeToggle.setAttribute("title", "Switch to dark mode");
    }
  }
}

function toggleTheme() {
  const currentTheme = document.documentElement.getAttribute("data-theme") || "light";
  const newTheme = currentTheme === "dark" ? "light" : "dark";
  applyTheme(newTheme);
  localStorage.setItem("scamshield_theme", newTheme);
  toast(`${newTheme === "dark" ? "Dark" : "Light"} mode enabled`);
}

$("theme-toggle")?.addEventListener("click", toggleTheme);

// --- Toast Notification ---
function toast(message) {
  const el = $("toast");
  if (!el) return;
  el.textContent = message;
  el.classList.add("show");
  window.setTimeout(() => el.classList.remove("show"), 2600);
}

// --- Tab Switching ---
function switchTab(tab) {
  activeTab = tab;
  document.querySelectorAll(".tab").forEach(btn => {
    const selected = btn.dataset.tab === tab;
    btn.classList.toggle("active", selected);
    btn.setAttribute("aria-selected", String(selected));
  });

  ["message", "link", "audio"].forEach(name => {
    $(`${name}-pane`)?.classList.toggle("hidden", name !== tab);
  });

  const analyzeBtn = $("analyze-button");
  if (analyzeBtn) {
    analyzeBtn.classList.remove("hidden");
    if (tab === "audio") {
      analyzeBtn.innerHTML = 'Analyze call recording <span>→</span>';
    } else if (tab === "link") {
      analyzeBtn.innerHTML = 'Analyze link <span>→</span>';
    } else {
      analyzeBtn.innerHTML = 'Analyze now <span>→</span>';
    }
  }

  $("error-box")?.classList.add("hidden");
}

document.querySelectorAll(".tab").forEach(btn => {
  btn.addEventListener("click", () => switchTab(btn.dataset.tab));
});

// --- Message Input Listeners ---
$("message-input")?.addEventListener("input", e => {
  $("char-count").textContent = `${e.target.value.length} / 5000`;
  if (/^(https?:\/\/)?[\w.-]+\.[a-z]{2,}(\/\S*)?$/i.test(e.target.value.trim())) {
    $("error-box").textContent = "This looks like a URL. You can switch to the Link tab to check it with parameter analysis.";
    $("error-box").classList.remove("hidden");
  } else {
    $("error-box").classList.add("hidden");
  }
});

document.querySelectorAll("[data-sample]").forEach(btn => {
  btn.addEventListener("click", () => {
    const val = messageSamples[btn.dataset.sample] || "";
    $("message-input").value = val;
    $("char-count").textContent = `${val.length} / 5000`;
  });
});

// --- Link & URL Checking Parameter Listeners ---
$("url-input")?.addEventListener("input", e => {
  checkUrlParamsIndicator(e.target.value);
});

function checkUrlParamsIndicator(urlText) {
  const indicator = $("url-param-indicator");
  if (!indicator) return;
  const trimmed = urlText.trim();
  if (trimmed.includes("?") && trimmed.split("?")[1]) {
    indicator.classList.remove("hidden");
    try {
      const full = trimmed.startsWith("http://") || trimmed.startsWith("https://") ? trimmed : `https://${trimmed}`;
      const parsed = new URL(full);
      const paramCount = Array.from(parsed.searchParams.keys()).length;
      indicator.textContent = `${paramCount} query parameter${paramCount !== 1 ? "s" : ""} detected`;
    } catch {
      indicator.textContent = "Query parameters detected";
    }
  } else {
    indicator.classList.add("hidden");
  }
}

document.querySelectorAll("[data-url]").forEach(btn => {
  btn.addEventListener("click", () => {
    const url = btn.dataset.url;
    $("url-input").value = url;
    checkUrlParamsIndicator(url);
  });
});

// --- Audio Feature Listeners & Speech Recognition ---
$("audio-transcript-input")?.addEventListener("input", e => {
  $("audio-char-count").textContent = `${e.target.value.length} / 10000`;
});

document.querySelectorAll("[data-audio-sample]").forEach(btn => {
  btn.addEventListener("click", () => {
    const sampleKey = btn.dataset.audioSample;
    const sampleText = audioSamples[sampleKey] || "";
    $("audio-transcript-input").value = sampleText;
    $("audio-char-count").textContent = `${sampleText.length} / 10000`;
    toast("Loaded sample call conversation");
  });
});

// Speech Synthesis ("Listen Call")
const playSampleBtn = $("play-sample-audio-btn");
playSampleBtn?.addEventListener("click", () => {
  if (!("speechSynthesis" in window)) {
    toast("Speech synthesis is not supported in this browser.");
    return;
  }

  if (window.speechSynthesis.speaking) {
    window.speechSynthesis.cancel();
    playSampleBtn.textContent = "🔊 Listen Call";
    playSampleBtn.classList.remove("playing");
    return;
  }

  const textToSpeak = $("audio-transcript-input")?.value.trim();
  if (!textToSpeak) {
    toast("Type or select a call scenario above to listen.");
    return;
  }

  const utterance = new SpeechSynthesisUtterance(textToSpeak);
  utterance.rate = 0.95;
  utterance.onstart = () => {
    playSampleBtn.textContent = "⏹ Stop Listening";
    playSampleBtn.classList.add("playing");
  };
  utterance.onend = utterance.onerror = () => {
    playSampleBtn.textContent = "🔊 Listen Call";
    playSampleBtn.classList.remove("playing");
  };
  window.speechSynthesis.speak(utterance);
});

// Microphone Voice Recording & Live Speech Recognition
const recordBtn = $("record-btn");
const recordBtnText = $("record-btn-text");
const recordTimer = $("record-timer");
const recordStatus = $("record-status");
const audioPreview = $("audio-preview");

recordBtn?.addEventListener("click", async () => {
  if (isRecording) {
    stopRecording();
  } else {
    await startRecording();
  }
});

async function startRecording() {
  audioChunks = [];
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    mediaRecorder = new MediaRecorder(stream);

    mediaRecorder.ondataavailable = e => {
      if (e.data.size > 0) audioChunks.push(e.data);
    };

    mediaRecorder.onstop = () => {
      const audioBlob = new Blob(audioChunks, { type: "audio/webm" });
      if (recordedAudioUrl) URL.revokeObjectURL(recordedAudioUrl);
      recordedAudioUrl = URL.createObjectURL(audioBlob);
      if (audioPreview) {
        audioPreview.src = recordedAudioUrl;
        audioPreview.classList.remove("hidden");
      }
      stream.getTracks().forEach(track => track.stop());
    };

    mediaRecorder.start();
    isRecording = true;
    recordBtn.classList.add("recording");
    recordBtnText.textContent = "Stop Recording";
    recordStatus.textContent = "Listening... Speak clearly into your mic";
    recordTimer.classList.remove("hidden");

    recordStartTime = Date.now();
    updateRecordTimer();
    recordTimerInterval = setInterval(updateRecordTimer, 1000);

    // Initialize Web Speech API if supported for live transcription
    const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
    if (SpeechRecognition) {
      try {
        speechRecognizer = new SpeechRecognition();
        speechRecognizer.continuous = true;
        speechRecognizer.interimResults = true;
        speechRecognizer.lang = "en-US";

        speechRecognizer.onresult = event => {
          let liveTranscript = "";
          for (let i = 0; i < event.results.length; ++i) {
            liveTranscript += event.results[i][0].transcript + " ";
          }
          if (liveTranscript.trim()) {
            $("audio-transcript-input").value = liveTranscript.trim();
            $("audio-char-count").textContent = `${liveTranscript.trim().length} / 10000`;
          }
        };

        speechRecognizer.onerror = () => {
          // Silent fallback to standard recording
        };

        speechRecognizer.start();
      } catch {
        // Recognition not initialized
      }
    }
  } catch (err) {
    toast(`Microphone error: ${err.message || "Permission denied"}`);
    recordStatus.textContent = "Mic access blocked. You can upload an audio file or select a sample call.";
  }
}

function stopRecording() {
  if (mediaRecorder && mediaRecorder.state !== "inactive") {
    mediaRecorder.stop();
  }
  if (speechRecognizer) {
    try { speechRecognizer.stop(); } catch {}
  }
  isRecording = false;
  clearInterval(recordTimerInterval);
  recordBtn.classList.remove("recording");
  recordBtnText.textContent = "Record Voice / Call";
  recordStatus.textContent = "Recording finished. Click 'Analyze call recording' to inspect.";
}

function updateRecordTimer() {
  const elapsedSec = Math.floor((Date.now() - recordStartTime) / 1000);
  const mins = String(Math.floor(elapsedSec / 60)).padStart(2, "0");
  const secs = String(elapsedSec % 60).padStart(2, "0");
  recordTimer.textContent = `${mins}:${secs}`;
}

// Audio File Upload
const audioFileInput = $("audio-file-input");
audioFileInput?.addEventListener("change", e => {
  const file = e.target.files && e.target.files[0];
  if (!file) return;

  $("audio-file-name").textContent = file.name;
  if (recordedAudioUrl) URL.revokeObjectURL(recordedAudioUrl);
  recordedAudioUrl = URL.createObjectURL(file);
  if (audioPreview) {
    audioPreview.src = recordedAudioUrl;
    audioPreview.classList.remove("hidden");
  }

  // If transcript is empty, invite user to transcribe or use a sample
  const currentTranscript = $("audio-transcript-input").value.trim();
  if (!currentTranscript) {
    toast(`Uploaded: ${file.name}. Review or type call transcript.`);
  }
});

// --- Core Unified Analysis Function ---
async function analyze() {
  let endpoint = "/api/analyze";
  let payload = {};
  let input = "";

  if (activeTab === "link") {
    endpoint = "/api/analyze/url";
    input = $("url-input")?.value.trim() || "";
    if (!input) {
      showError("Paste a link first, or choose a sample.");
      return;
    }
    payload = { url: input };
  } else if (activeTab === "audio") {
    endpoint = "/api/analyze/audio";
    input = $("audio-transcript-input")?.value.trim() || "";
    if (!input) {
      showError("Record a call conversation, upload an audio file, or choose a sample call scenario first.");
      return;
    }
    payload = { transcript: input };
  } else {
    endpoint = "/api/analyze";
    input = $("message-input")?.value.trim() || "";
    if (!input) {
      showError("Paste a message first, or choose a sample.");
      return;
    }
    payload = { message: input };
  }

  const button = $("analyze-button");
  button.disabled = true;
  button.textContent = "Analyzing…";
  button.setAttribute("aria-label", "Analyzing");
  $("error-box").classList.add("hidden");
  $("result-section").classList.add("hidden");

  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.detail || "The request could not be completed.");
    }
    lastResult = data;
    lastInput = input;
    lastCheckedType = activeTab;
    renderResult(data, input, activeTab);
  } catch (err) {
    showError(`Could not analyze this ${activeTab}. ${err.message} Ensure the ScamShield backend is running.`);
  } finally {
    button.disabled = false;
    if (activeTab === "audio") {
      button.innerHTML = 'Analyze call recording <span>→</span>';
    } else if (activeTab === "link") {
      button.innerHTML = 'Analyze link <span>→</span>';
    } else {
      button.innerHTML = 'Analyze now <span>→</span>';
    }
    button.removeAttribute("aria-label");
  }
}

function showError(message) {
  const el = $("error-box");
  if (!el) return;
  el.textContent = message;
  el.classList.remove("hidden");
}

// --- Render Result Card ---
function renderResult(data, input, type) {
  const verdict = data.verdict;
  const isScam = verdict === "scam";
  const isSuspicious = verdict === "suspicious";
  const isSafe = verdict === "safe";
  const isInvalid = verdict === "invalid";

  const card = $("result-card");
  card.classList.remove("verdict-scam", "verdict-suspicious", "verdict-safe");
  const resultTone = isScam ? "verdict-scam" : isSuspicious || isInvalid ? "verdict-suspicious" : "verdict-safe";
  card.classList.add(resultTone);

  $("verdict-symbol").textContent = isScam ? "!" : isSuspicious || isInvalid ? "!" : "✓";
  $("verdict-eyebrow").textContent = isScam ? "HIGH RISK" : isSuspicious || isInvalid ? "CAUTION" : "LOW RISK";

  if (type === "audio") {
    $("verdict-title").textContent = isScam ? "Scam Call Patterns Detected" : isSuspicious ? "Suspicious Call" : "Safe Call Tone";
    $("verdict-subtitle").textContent = isScam ? "Hang up immediately. Do not share OTPs, transfer funds, or stay on the line." : isSuspicious ? "Be careful. Verify caller identity independently." : "No known scam call scripts or coercion detected.";
  } else if (type === "link") {
    $("verdict-title").textContent = isScam ? "High-Risk Link" : isSuspicious ? "Suspicious Address / Parameters" : isInvalid ? "Invalid Link Address" : "No Known Warning Signals";
    $("verdict-subtitle").textContent = isScam ? "Do not open this URL or share login details." : isSuspicious ? "Be careful. Verify destination domain and redirect parameters." : isInvalid ? "We could not inspect this address format." : "No configured warning patterns or deceptive parameters were detected.";
  } else {
    $("verdict-title").textContent = isScam ? "Scam Signals Found" : isSuspicious ? "Suspicious Message" : "No Known Warning Signals";
    $("verdict-subtitle").textContent = isScam ? "Do not click, pay, or share sensitive details." : isSuspicious ? "Be careful. Verify independently before acting." : "No configured warning patterns were detected.";
  }

  const riskScore = Number.isFinite(data.risk_score) ? Math.min(100, Math.max(0, data.risk_score)) : 0;
  $("score-number").textContent = riskScore;
  $("risk-level").textContent = isScam ? "HIGH RISK" : isSuspicious || isInvalid ? "CAUTION" : "LOW RISK";
  $("risk-meter").style.width = `${riskScore}%`;
  $("emergency-help")?.classList.toggle("hidden", !isScam);

  // Render URL Query Parameters breakdown if present
  const paramTagsContainer = $("parameter-tags");
  if (paramTagsContainer) {
    paramTagsContainer.replaceChildren();
    if (type === "link" && data.url_parameters) {
      const { keys = [], flagged = [], count = 0 } = data.url_parameters;
      if (count > 0) {
        paramTagsContainer.classList.remove("hidden");
        const titleSpan = document.createElement("strong");
        titleSpan.textContent = flagged.length > 0 ? "Flagged URL Parameters:" : "URL Parameters Inspected:";
        paramTagsContainer.appendChild(titleSpan);

        keys.forEach(k => {
          const pill = document.createElement("span");
          pill.className = `param-pill ${flagged.includes(k) ? "param-flagged" : ""}`;
          pill.textContent = flagged.includes(k) ? `⚠️ ${k} (flagged)` : `✓ ${k}`;
          paramTagsContainer.appendChild(pill);
        });
      } else {
        paramTagsContainer.classList.add("hidden");
      }
    } else {
      paramTagsContainer.classList.add("hidden");
    }
  }

  // Render Reason List
  const list = $("reason-list");
  list.replaceChildren();
  const reasons = data.reasons || [];
  if (!reasons.length) {
    const li = document.createElement("li");
    li.textContent = "No configured warning patterns were detected.";
    list.appendChild(li);
  } else {
    reasons.forEach(reason => {
      const li = document.createElement("li");
      li.textContent = reason;
      list.appendChild(li);
    });
  }

  $("advice-text").textContent = data.advice || "Verify independently before taking action.";
  $("disclaimer-text").textContent = data.disclaimer || "Automated prototype assessment. A low score does not prove that content is safe.";

  const checked = $("checked-content");
  const prefix = type === "link" ? "Checked link: " : type === "audio" ? "Checked audio recording transcript: " : "Checked message: ";
  checked.textContent = `${prefix}${input}`;
  checked.classList.remove("hidden");

  $("result-section").classList.remove("hidden");
  $("result-section").scrollIntoView({
    behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth",
    block: "start"
  });
}

// --- URL Parameter Browser Integration (Deep Linking) ---
function handleUrlParametersOnLoad() {
  const urlParams = new URLSearchParams(window.location.search);

  // 1. URL checking parameter: ?url=... or ?link=...
  if (urlParams.has("url") || urlParams.has("link")) {
    const targetUrl = urlParams.get("url") || urlParams.get("link");
    switchTab("link");
    if ($("url-input")) {
      $("url-input").value = targetUrl;
      checkUrlParamsIndicator(targetUrl);
    }
    // Auto analyze when parameter is provided in address bar
    analyze();
    return;
  }

  // 2. Message checking parameter: ?message=... or ?msg=... or ?text=...
  if (urlParams.has("message") || urlParams.has("msg") || urlParams.has("text")) {
    const targetMsg = urlParams.get("message") || urlParams.get("msg") || urlParams.get("text");
    switchTab("message");
    if ($("message-input")) {
      $("message-input").value = targetMsg;
      $("char-count").textContent = `${targetMsg.length} / 5000`;
    }
    analyze();
    return;
  }

  // 3. Audio parameter: ?audio=... or ?transcript=...
  if (urlParams.has("audio") || urlParams.has("transcript")) {
    const targetAudio = urlParams.get("audio") || urlParams.get("transcript");
    switchTab("audio");
    if ($("audio-transcript-input")) {
      $("audio-transcript-input").value = targetAudio;
      $("audio-char-count").textContent = `${targetAudio.length} / 10000`;
    }
    analyze();
    return;
  }

  // 4. Tab selection parameter: ?tab=audio or ?tab=link
  if (urlParams.has("tab")) {
    const tabName = urlParams.get("tab");
    if (["message", "link", "audio"].includes(tabName)) {
      switchTab(tabName);
    }
  }
}

// Copy check link with URL parameter
$("share-link-button")?.addEventListener("click", () => {
  if (!lastInput) {
    toast("Run a check first to share the link.");
    return;
  }
  const baseUrl = window.location.origin + window.location.pathname;
  let paramKey = "url";
  if (lastCheckedType === "message") paramKey = "message";
  if (lastCheckedType === "audio") paramKey = "audio";

  const shareableUrl = `${baseUrl}?${paramKey}=${encodeURIComponent(lastInput)}`;
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(shareableUrl).then(() => {
      toast("Copied shareable check link with parameter!");
    }).catch(() => {
      prompt("Copy check link:", shareableUrl);
    });
  } else {
    prompt("Copy check link:", shareableUrl);
  }
});

// Event Bindings
$("analyze-button")?.addEventListener("click", analyze);
$("reset-button")?.addEventListener("click", () => {
  $("result-section")?.classList.add("hidden");
  if (activeTab === "link") $("url-input")?.focus();
  else if (activeTab === "audio") $("audio-transcript-input")?.focus();
  else $("message-input")?.focus();
});

document.querySelectorAll("[data-feedback]").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll("[data-feedback]").forEach(item => item.classList.remove("selected"));
    btn.classList.add("selected");
    toast(btn.dataset.feedback === "correct" ? "Thanks for confirming this result." : "Thanks. This feedback is only shown in the demo and is not stored.");
  });
});

$("report-button")?.addEventListener("click", () => {
  $("report-modal")?.classList.remove("hidden");
  $("report-confirmation")?.classList.add("hidden");
  const reportType = $("report-type");
  if (reportType) {
    if (activeTab === "audio") reportType.value = "Call Audio / Recording";
    else if (activeTab === "link") reportType.value = "Link";
    else reportType.value = "Message";
  }
});
$("close-modal")?.addEventListener("click", () => $("report-modal")?.classList.add("hidden"));
$("report-modal")?.addEventListener("click", e => {
  if (e.target === $("report-modal")) $("report-modal")?.classList.add("hidden");
});
$("save-report")?.addEventListener("click", () => {
  $("report-confirmation").textContent = "Report details reviewed locally. Server-side community reporting will be added in a future phase.";
  $("report-confirmation")?.classList.remove("hidden");
});
document.addEventListener("keydown", e => {
  if (e.key === "Escape") $("report-modal")?.classList.add("hidden");
});

// Initialization on DOMContentLoaded
document.addEventListener("DOMContentLoaded", () => {
  initTheme();
  handleUrlParametersOnLoad();
});

// In case script runs after DOM is ready
if (document.readyState === "interactive" || document.readyState === "complete") {
  initTheme();
  handleUrlParametersOnLoad();
}
