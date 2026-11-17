import ipaddress
import re
import unicodedata
from difflib import SequenceMatcher
from urllib.parse import parse_qsl, unquote, urlsplit

try:
    import tldextract
    _EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())
    def extract_domain_parts(host: str) -> dict:
        extracted = _EXTRACTOR(host)
        registered_domain = (
            f"{extracted.domain}.{extracted.suffix}"
            if extracted.domain and extracted.suffix
            else host
        )
        return {
            "registered_domain": registered_domain,
            "domain_label": extracted.domain or host,
            "subdomain": extracted.subdomain or ""
        }
except ImportError:
    # Reliable offline fallback extractor for environments without tldextract
    COMMON_MULTI_SUFFIXES = {
        "co.uk", "org.uk", "gov.uk", "ac.uk", "co.in", "net.in", "org.in", "gov.in",
        "com.au", "net.au", "org.au", "co.nz", "com.br", "co.jp"
    }
    def extract_domain_parts(host: str) -> dict:
        parts = host.lower().split(".")
        if len(parts) >= 3 and f"{parts[-2]}.{parts[-1]}" in COMMON_MULTI_SUFFIXES:
            suffix = f"{parts[-2]}.{parts[-1]}"
            domain = parts[-3]
            subdomain = ".".join(parts[:-3])
        elif len(parts) >= 2:
            suffix = parts[-1]
            domain = parts[-2]
            subdomain = ".".join(parts[:-2])
        else:
            suffix = ""
            domain = host
            subdomain = ""
        registered_domain = f"{domain}.{suffix}" if domain and suffix else host
        return {
            "registered_domain": registered_domain,
            "domain_label": domain or host,
            "subdomain": subdomain
        }


SUSPICIOUS_WORDS = {
    "verify", "account", "login", "update",
    "secure", "claim", "free", "prize",
    "billing", "payment", "wallet", "password",
    "confirm", "support", "refund", "urgent"
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd",
    "cutt.ly", "rb.gy", "shorturl.at",
    "ow.ly", "buff.ly", "rebrand.ly"
}

BRANDS = {
    "amazon", "google", "microsoft", "apple",
    "paypal", "facebook", "instagram", "netflix",
    "whatsapp", "flipkart", "ebay", "sbi",
    "icici", "hdfc", "youtube", "telegram",
    "paytm", "phonepe", "gpay", "axis", "pnb"
}

# Common digit substitutions used in lookalike domains.
LOOKALIKE_MAP = str.maketrans({
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t"
})

# Suspicious TLDs heavily observed in transient phishing and malware campaigns
ABUSE_TLDS = {
    "top", "xyz", "icu", "buzz", "sbs", "cfd", "rest", "tk", "ml", "ga", "cf", "gq", "zip", "mov"
}

# Common Cyrillic and Greek homoglyphs used to spoof Latin letters
HOMOGLYPH_MAP = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0443": "y", "\u0445": "x", "\u0456": "i", "\u03bf": "o", "\u03c1": "p",
    "\u0410": "A", "\u0412": "B", "\u0415": "E", "\u041e": "O", "\u0420": "P",
    "\u0421": "C", "\u0422": "T", "\u0425": "X"
}


def normalize_name(name: str) -> str:
    """Normalize a domain label for brand comparison."""
    name = name.lower().translate(LOOKALIKE_MAP)
    return re.sub(r"[^a-z]", "", name)


def detect_homoglyphs(raw_host: str) -> bool:
    """Check if raw host uses mixed non-Latin confusables masquerading as Latin characters."""
    has_homoglyph = any(char in HOMOGLYPH_MAP for char in raw_host)
    if has_homoglyph:
        return True
    # Check if string mixes latin and cyrillic/greek scripts
    scripts = set()
    for char in raw_host:
        if char.isalnum():
            try:
                script = unicodedata.name(char).split()[0]
                scripts.add(script)
            except Exception:
                pass
    if "CYRILLIC" in scripts and "LATIN" in scripts:
        return True
    return False


def get_domain_parts(host: str) -> dict:
    return extract_domain_parts(host)


def detect_brand_impersonation(host: str, domain_parts: dict):
    registered_label = domain_parts["domain_label"]
    subdomain_labels = domain_parts["subdomain"].split(".") if domain_parts["subdomain"] else []

    normalized_registered = normalize_name(registered_label)

    for brand in BRANDS:
        normalized_brand = normalize_name(brand)

        # Exact brand domain label: amazon.com
        if normalized_registered == normalized_brand:
            if any(
                normalize_name(label) == normalized_brand
                for label in subdomain_labels
            ):
                return brand, "brand_in_subdomain"
            continue

        # Brand name embedded in the registered domain label:
        # amaz0n-billing.com -> amazonbilling
        if normalized_brand in normalized_registered:
            return brand, "brand_in_domain"

        # Detect common one-character spelling variations.
        similarity = SequenceMatcher(
            None, normalized_registered, normalized_brand
        ).ratio()

        if (
            len(normalized_registered) >= 4
            and similarity >= 0.82
        ):
            return brand, "lookalike_spelling"

        # Brand appearing in a misleading subdomain:
        if any(
            normalize_name(label) == normalized_brand
            for label in subdomain_labels
        ):
            return brand, "brand_in_subdomain"

    return None, None


def analyze_url(url: str) -> dict:
    original = url.strip()

    if not original or any(ch.isspace() for ch in original):
        return {
            "url": original,
            "verdict": "invalid",
            "risk_level": "unknown",
            "risk_score": 0,
            "reasons": ["Enter one valid URL without spaces."],
            "advice": "Check the address and try again."
        }

    # Handle UPI Payment Intent Deep Links
    if original.startswith("upi://") or "://upi" in original:
        return analyze_upi_link(original)

    candidate = (
        original if "://" in original
        else "https://" + original
    )

    try:
        parsed = urlsplit(candidate)
        hostname = parsed.hostname

        # Validate malformed ports.
        _ = parsed.port

        if parsed.scheme not in {"http", "https"} or not hostname:
            raise ValueError("Unsupported URL")

        raw_hostname = hostname
        # Convert internationalized hostnames to ASCII.
        host = hostname.encode("idna").decode("ascii").lower().rstrip(".")

        if not host or ".." in host:
            raise ValueError("Invalid hostname")

    except (ValueError, UnicodeError):
        return {
            "url": original,
            "verdict": "invalid",
            "risk_level": "unknown",
            "risk_score": 0,
            "reasons": ["The URL format is invalid or unsupported."],
            "advice": "Enter a complete HTTP or HTTPS web address."
        }

    reasons = []
    score = 0

    def add_finding(message: str, points: int):
        nonlocal score
        reasons.append(message)
        score += points

    # 1. HTTP check
    if parsed.scheme == "http":
        add_finding(
            "This link uses HTTP instead of encrypted HTTPS.",
            20
        )

    # 2. @ symbol / deceptive user information
    if "@" in parsed.netloc:
        add_finding(
            "The address contains an @ symbol that can disguise its destination.",
            25
        )

    # 3. Homoglyph / Mixed-script spoofing check
    if detect_homoglyphs(raw_hostname):
        add_finding(
            "The domain uses visual lookalike non-Latin characters (homoglyph attack) to impersonate a legitimate name.",
            40
        )

    # 4. Punycode / encoded internationalized domain
    if any(label.startswith("xn--") for label in host.split(".")):
        add_finding(
            "The domain contains an encoded internationalized hostname.",
            20
        )

    # 5. URL shortener
    if host in SHORTENERS or any(
        host.endswith("." + shortener) for shortener in SHORTENERS
    ):
        add_finding(
            "This is a URL-shortening service. Its final destination is hidden.",
            25
        )

    # 6. IP address instead of a domain
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False

    if is_ip:
        add_finding(
            "The link uses a raw IP address instead of a domain name.",
            30
        )

    # 7. Domain and subdomain analysis
    domain_parts = get_domain_parts(host)

    subdomain_labels = (
        domain_parts["subdomain"].split(".")
        if domain_parts["subdomain"]
        else []
    )

    if len(subdomain_labels) >= 3:
        add_finding(
            "The hostname contains an unusually large number of subdomains.",
            15
        )

    # 8. Suspicious keywords in the hostname
    matched_words = sorted(
        word for word in SUSPICIOUS_WORDS if word in host
    )

    if matched_words:
        add_finding(
            "The hostname contains potentially deceptive words: "
            + ", ".join(matched_words) + ".",
            15
        )

    # 9. Abuse-prone TLD check when paired with words or brands
    tld = host.split(".")[-1] if "." in host else ""
    if tld in ABUSE_TLDS and (matched_words or any(b in host for b in BRANDS)):
        add_finding(
            f"The domain uses the '.{tld}' top-level domain frequently exploited for high-turnover phishing campaigns.",
            25
        )

    # 10. Brand impersonation and typosquatting
    brand, brand_type = detect_brand_impersonation(host, domain_parts)

    if brand:
        if brand_type == "brand_in_subdomain":
            message = (
                f"The hostname places {brand.title()} in a subdomain, "
                "but the registered domain belongs to another domain."
            )
        elif brand_type == "lookalike_spelling":
            message = (
                f"The registered domain has a spelling similar to "
                f"{brand.title()}."
            )
        else:
            message = (
                f"The registered domain contains the name "
                f"{brand.title()} with additional text or characters."
            )

        add_finding(message, 55)

    # 11. URL Query Parameter Checking
    query_params = parse_qsl(parsed.query, keep_blank_values=True)
    param_keys = [k for k, _ in query_params]
    flagged_params = []

    REDIRECT_PARAMS = {
        "redirect", "redirect_to", "redirect_url", "redirect_uri",
        "url", "dest", "destination", "target", "return", "return_to",
        "next", "forward", "link", "r", "u", "goto", "out"
    }

    CREDENTIAL_PARAMS = {
        "password", "pass", "pwd", "token", "secret", "otp",
        "pin", "cvv", "auth_key", "session_id", "access_token"
    }

    SUSPICIOUS_EXTENSIONS = (
        ".exe", ".scr", ".bat", ".apk", ".vbs", ".msi", ".cmd", ".iso"
    )

    for key, val in query_params:
        key_lower = key.lower()
        val_unquoted = unquote(val).strip()

        # Check for open redirect parameters
        if key_lower in REDIRECT_PARAMS and val_unquoted:
            if "://" in val_unquoted or val_unquoted.startswith("//"):
                try:
                    redir_target = val_unquoted if "://" in val_unquoted else "https:" + val_unquoted
                    redir_parts = urlsplit(redir_target)
                    redir_host = redir_parts.hostname
                    if redir_host and redir_host != host:
                        flagged_params.append(key)
                        add_finding(
                            f"The URL contains an open-redirect parameter ('{key}') pointing to an external destination ('{redir_host}').",
                            35
                        )
                except Exception:
                    pass

        # Check for sensitive credentials in plaintext query parameters
        if key_lower in CREDENTIAL_PARAMS and val:
            if key not in flagged_params:
                flagged_params.append(key)
                add_finding(
                    f"The URL exposes sensitive credentials or authentication tokens ('{key}') in plaintext query parameters.",
                    25
                )

        # Check for suspicious executable/download extensions in parameters
        if any(val_unquoted.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS):
            if key not in flagged_params:
                flagged_params.append(key)
                add_finding(
                    f"The URL parameter '{key}' references a potentially dangerous executable or installer package.",
                    30
                )

        # Check for embedded script payloads or encoded URLs in values
        val_lower = val_unquoted.lower()
        if any(sig in val_lower for sig in ["javascript:", "data:text/html", "%3a%2f%2f"]):
            if key not in flagged_params:
                flagged_params.append(key)
                add_finding(
                    f"The URL parameter '{key}' contains an obfuscated or script payload.",
                    25
                )

    # 12. Final risk calculation
    score = min(score, 100)

    if score >= 65:
        verdict = "suspicious"
        risk_level = "high"
        advice = (
            "High risk: Do not open this link or enter personal, "
            "banking, or login information. Visit the official website "
            "by typing its address yourself."
        )
    elif score >= 25:
        verdict = "suspicious"
        risk_level = "medium"
        advice = (
            "This link has suspicious characteristics. Avoid opening it "
            "until you independently verify the destination."
        )
    else:
        verdict = "safe"
        risk_level = "low"
        advice = (
            "No configured warning patterns were detected. "
            "This does not prove that the website is trustworthy."
        )

    return {
        "url": original,
        "hostname": host,
        "registered_domain": domain_parts["registered_domain"],
        "verdict": verdict,
        "risk_level": risk_level,
        "risk_score": score,
        "reasons": reasons,
        "url_parameters": {
            "count": len(query_params),
            "keys": param_keys,
            "flagged": flagged_params,
        },
        "method": "url_heuristics",
        "advice": advice,
        "disclaimer": (
            "ScamShield inspects the URL as text only. "
            "It does not visit the link, verify website ownership, "
            "or guarantee that a website is safe."
        )
    }


def analyze_upi_link(upi_url: str) -> dict:
    """Specialized analyzer for UPI deep links (upi://pay?...) to detect fraudulent collect requests."""
    parsed = urlsplit(upi_url)
    params = dict(parse_qsl(parsed.query))
    reasons = [
        "This is a direct UPI Payment link (upi://pay)."
    ]
    score = 40
    payee = params.get("pa", "unknown")
    note = params.get("tn", "").lower()
    amount = params.get("am", "")

    if any(keyword in note for keyword in ["refund", "cashback", "reward", "lottery", "prize", "kyc"]):
        reasons.append(
            f"The payment note mentions '{note}', but in UPI you only enter a PIN to SEND money, never to receive refunds or rewards."
        )
        score += 45

    if amount:
        reasons.append(f"This link requests an immediate transfer of ₹{amount}.")

    score = min(score, 100)
    verdict = "suspicious" if score >= 25 else "safe"
    risk_level = "high" if score >= 65 else "medium"

    return {
        "url": upi_url,
        "hostname": "upi-payment-gateway",
        "registered_domain": "upi",
        "verdict": verdict,
        "risk_level": risk_level,
        "risk_score": score,
        "reasons": reasons,
        "url_parameters": {
            "count": len(params),
            "keys": list(params.keys()),
            "flagged": ["tn"] if "refund" in note or "prize" in note else [],
        },
        "method": "upi_intent_heuristics",
        "advice": (
            "Never approve or enter your UPI PIN on unsolicited payment links. "
            "Receiving money in UPI does NOT require entering a PIN."
        ),
        "disclaimer": "ScamShield UPI inspection. Always verify payee VPA before approving any transaction."
    }
