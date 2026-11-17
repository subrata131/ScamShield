import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "scams.db"

DIVERSE_SEED_DATA = [
    (
        "audio",
        "Caller claiming to be from Mumbai Crime Branch stating a courier with narcotics was seized under Aadhaar. Demanded immediate digital arrest custody.",
        "scam",
        90,
        json.dumps(["Authority Impersonation", "Digital Custody / Isolation", "Fear Coercion"]),
        "Reported by user in Delhi. Scammer wore fake police uniform on Skype video call.",
        datetime.now(timezone.utc).isoformat(),
        "verified"
    ),
    (
        "message",
        "Dear consumer, your electricity power will be disconnected tonight at 9:30 PM due to unpaid bill. Call our electricity officer immediately on 9876543210 to avoid disconnection.",
        "scam",
        85,
        json.dumps(["Utility Threat", "Urgency Pressure", "Fake Helpline"]),
        "Widespread electricity board SMS scam targeting metro & rural consumers.",
        datetime.now(timezone.utc).isoformat(),
        "verified"
    ),
    (
        "link",
        "http://sbi-rewards-redeem.top/login?redirect=http://update-apk.icu/sbi.apk",
        "scam",
        95,
        json.dumps(["Brand Impersonation", "Abuse-Prone TLD", "Malicious APK Sideloading"]),
        "Phishing domain distributing remote-access banking trojan APK.",
        datetime.now(timezone.utc).isoformat(),
        "verified"
    ),
    (
        "message",
        "Earn Rs. 3000 to Rs. 5000 daily by simply liking YouTube videos. Work from home 1 hour daily. Contact our HR manager on Telegram @EarnDaily_HR.",
        "scam",
        75,
        json.dumps(["Task Scam", "Unrealistic Financial Return", "Telegram Recruitment"]),
        "Prepaid task scam requesting initial deposit after 3 free small payouts.",
        datetime.now(timezone.utc).isoformat(),
        "verified"
    ),
    (
        "link",
        "upi://pay?pa=cashback-clearance@okaxis&pn=RewardClaim&am=4999&tn=Enter_PIN_to_Claim_Refund",
        "scam",
        90,
        json.dumps(["UPI Collect Fraud", "Fake Refund Bait", "PIN Deception"]),
        "Fraudulent collect request claiming you need to enter UPI PIN to receive refund.",
        datetime.now(timezone.utc).isoformat(),
        "verified"
    ),
    (
        "message",
        "Your bank KYC has expired. Your account and debit card will be blocked within 24 hours. Update immediately: http://bit.ly/bank-kyc-verify",
        "scam",
        90,
        json.dumps(["Credential Harvesting", "Urgency Pressure", "URL Shortener Concealment"]),
        "Classic fake KYC SMS asking for debit card number and netbanking password.",
        datetime.now(timezone.utc).isoformat(),
        "verified"
    ),
    (
        "message",
        "Income Tax Dept: Approved tax refund of Rs. 18,750 for PAN ending in 8912. Confirm your bank account & CVV to receive credit: https://incometax-refunds.xyz",
        "scam",
        85,
        json.dumps(["Tax Refund Lure", "Credential Harvesting", "Abuse-Prone TLD"]),
        "Phishing landing page stealing debit card CVVs under the guise of tax refund.",
        datetime.now(timezone.utc).isoformat(),
        "verified"
    ),
    (
        "audio",
        "Automated DHL Customs Alert: Illegal parcel with passports and contraband held at Delhi IGI Airport. Press 1 to speak with Narcotics Control Bureau officer.",
        "scam",
        90,
        json.dumps(["Authority Impersonation", "Customs Intimidation", "IVR Call Spoofing"]),
        "Automated robocall transferring to fake customs officer for extortion.",
        datetime.now(timezone.utc).isoformat(),
        "verified"
    ),
]


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), timeout=15.0)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(force_reseed_if_repetitive: bool = True) -> None:
    with get_db_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scam_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                category TEXT NOT NULL,
                content TEXT NOT NULL,
                verdict TEXT NOT NULL,
                risk_score INTEGER NOT NULL DEFAULT 0,
                tactics TEXT DEFAULT '[]',
                notes TEXT DEFAULT '',
                reporter_contact TEXT DEFAULT '',
                created_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'verified'
            )
        """)

        cursor = conn.execute("SELECT COUNT(DISTINCT content) AS distinct_count, COUNT(*) as total FROM scam_reports")
        row = cursor.fetchone()
        distinct_count = row["distinct_count"] if row else 0

        # Reseed if empty or if polluted with identical repetitive reports
        if distinct_count < 4 and force_reseed_if_repetitive:
            conn.execute("DELETE FROM scam_reports WHERE status = 'verified'")
            conn.executemany("""
                INSERT INTO scam_reports (category, content, verdict, risk_score, tactics, notes, created_at, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, DIVERSE_SEED_DATA)
            conn.commit()


def add_report(
    category: str,
    content: str,
    verdict: str = "scam",
    risk_score: int = 70,
    tactics: list[str] | None = None,
    notes: str = "",
    reporter_contact: str = "",
    status: str = "verified",
) -> dict:
    init_db(force_reseed_if_repetitive=False)
    tactics_json = json.dumps(tactics or [])
    created_at = datetime.now(timezone.utc).isoformat()
    clean_cat = category.lower().strip() or "message"

    with get_db_connection() as conn:
        cursor = conn.execute("""
            INSERT INTO scam_reports (category, content, verdict, risk_score, tactics, notes, reporter_contact, created_at, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (clean_cat, content.strip(), verdict, risk_score, tactics_json, notes.strip(), reporter_contact.strip(), created_at, status))
        conn.commit()
        report_id = cursor.lastrowid

    return {
        "id": report_id,
        "category": clean_cat,
        "content": content.strip(),
        "verdict": verdict,
        "risk_score": risk_score,
        "tactics": tactics or [],
        "notes": notes.strip(),
        "created_at": created_at,
        "status": status
    }


def get_recent_reports(limit: int = 10) -> list[dict]:
    """
    Returns unique recent scam threats deduplicated by content.
    If multiple users reported the same scam, it returns report_count so
    the feed displays distinct diverse threats rather than identical duplicates.
    """
    init_db(force_reseed_if_repetitive=False)
    with get_db_connection() as conn:
        cursor = conn.execute("""
            SELECT 
                MAX(id) AS id,
                category,
                content,
                verdict,
                MAX(risk_score) AS risk_score,
                tactics,
                notes,
                MAX(created_at) AS created_at,
                COUNT(*) AS report_count,
                status
            FROM scam_reports
            WHERE status = 'verified'
            GROUP BY content
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()

    reports = []
    for r in rows:
        try:
            parsed_tactics = json.loads(r["tactics"])
        except Exception:
            parsed_tactics = []

        reports.append({
            "id": r["id"],
            "category": r["category"],
            "content": r["content"],
            "verdict": r["verdict"],
            "risk_score": r["risk_score"],
            "tactics": parsed_tactics,
            "notes": r["notes"],
            "created_at": r["created_at"],
            "report_count": r["report_count"],
            "status": r["status"]
        })
    return reports


def get_report_stats() -> dict:
    init_db(force_reseed_if_repetitive=False)
    with get_db_connection() as conn:
        total = conn.execute("SELECT COUNT(*) AS total FROM scam_reports").fetchone()["total"]
        scam_count = conn.execute("SELECT COUNT(*) AS count FROM scam_reports WHERE verdict = 'scam'").fetchone()["count"]
        categories_cursor = conn.execute("""
            SELECT category, COUNT(*) as count FROM scam_reports GROUP BY category
        """).fetchall()

    category_counts = {row["category"]: row["count"] for row in categories_cursor}

    return {
        "total_reports": total,
        "scam_reports": scam_count,
        "categories": category_counts,
        "community_trust_level": "Active Threat Network",
    }
