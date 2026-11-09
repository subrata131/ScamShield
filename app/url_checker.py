
import ipaddress
import re
from difflib import SequenceMatcher
from urllib.parse import parse_qsl, unquote, urlsplit

import tldextract


# Use the package's bundled Public Suffix List.
# This avoids requiring a network request during URL analysis.
DOMAIN_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())

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
    "icici", "hdfc", "youtube", "telegram"
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


def normalize_name(name: str) -> str:
    """Normalize a domain label for brand comparison."""
    name = name.lower().translate(LOOKALIKE_MAP)
    return re.sub(r"[^a-z]", "", name)


def get_domain_parts(host: str):
    """Return registered domain and subdomain information."""
    extracted = DOMAIN_EXTRACTOR(host)

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


def detect_brand_impersonation(host: str, domain_parts: dict):
    """
    Detect likely brand impersonation.

    Examples:
    amaz0n-billing.com
    amazon.com.fake-login.example
    amazan-login.com
    """
    registered_label = domain_parts["domain_label"]
    subdomain_labels = domain_parts["subdomain"].split(".")
    host_labels = host.split(".")

    normalized_registered = normalize_name(registered_label)

    for brand in BRANDS:
        normalized_brand = normalize_name(brand)

        # Exact brand domain label: amazon.com
        if normalized_registered == normalized_brand:
            # A brand in a subdomain of a different registered domain
            # is still suspicious.
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
        # amazon.com.fake-login.example
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

    # 3. Punycode / encoded internationalized domain
    if any(label.startswith("xn--") for label in host.split(".")):
        add_finding(
            "The domain contains an encoded internationalized hostname.",
            20
        )

    # 4. URL shortener
    if host in SHORTENERS or any(
        host.endswith("." + shortener) for shortener in SHORTENERS
    ):
        add_finding(
            "This is a URL-shortening service. Its final destination is hidden.",
            25
        )

    # 5. IP address instead of a domain
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

    # 6. Domain and subdomain analysis
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

    # 7. Suspicious keywords in the hostname
    matched_words = sorted(
        word for word in SUSPICIOUS_WORDS if word in host
    )

    if matched_words:
        add_finding(
            "The hostname contains potentially deceptive words: "
            + ", ".join(matched_words) + ".",
            15
        )

    # 8. Brand impersonation and typosquatting
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

    # 9. URL Query Parameter Checking
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

    # 10. Final risk calculation
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
