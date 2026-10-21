"""
PhishNet AI - Core Phishing Detection and URL Feature Extraction Engine
Module: detector.py

This module implements an explainable rule-based cybersecurity analysis engine
for URLs. It extracts lexical, structural, and behavioral indicators, calculates
a weighted heuristic risk score (0-100), and provides plain-English explanations
and actionable security recommendations.
"""

import ipaddress
import re
from urllib.parse import parse_qs, unquote, urlparse, urlsplit

# Try importing tldextract for robust Public Suffix List parsing.
# Fallback to an internal public suffix list for offline / standalone use.
try:
    import tldextract
    _TLD_EXTRACTOR = tldextract.TLDExtract(include_psl_raw_matches=True)
except Exception:
    _TLD_EXTRACTOR = None


# Known high-profile target brands commonly impersonated in phishing campaigns
TARGET_BRANDS = {
    "paypal", "apple", "google", "microsoft", "netflix", "amazon",
    "facebook", "instagram", "whatsapp", "chase", "wellsfargo",
    "bankofamerica", "citibank", "binance", "coinbase", "steam",
    "roblox", "outlook", "yahoo", "dropbox", "adobe", "spotify",
    "ebay", "twitter", "x", "linkedin", "irs", "usps", "dhl", "fedex"
}

# Suspicious keywords frequently used in phishing domains and paths
SUSPICIOUS_KEYWORDS = {
    "login", "signin", "sign-in", "log-in", "verify", "verification",
    "secure", "security", "account", "update", "banking", "authenticate",
    "authentication", "wallet", "support", "confirm", "confirmation",
    "credential", "password", "billing", "invoice", "recover", "recovery",
    "safety", "validation", "validate", "alert", "notification"
}

# High-risk / frequently abused top-level domains in malicious campaigns
HIGH_RISK_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "buzz", "work",
    "click", "rest", "fit", "surf", "cn", "link", "club", "cam",
    "icu", "monster", "cfd", "sbs", "quest", "beauty", "boats"
}

# Common standard web ports
STANDARD_PORTS = {80, 443, 8080, 8443}

# Known multi-part public suffixes for internal fallback
FALLBACK_MULTI_SUFFIXES = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "org.au",
    "edu.au", "gov.au", "co.in", "net.in", "org.in", "ac.in", "gov.in",
    "co.nz", "com.br", "com.mx", "com.sg", "co.za", "co.jp", "ne.jp"
}


class URLValidationError(ValueError):
    """Raised when the submitted URL string fails security or structural validation."""
    pass


def validate_and_normalize_url(raw_url: str) -> dict:
    """
    Validates input string for security constraints, rejecting dangerous schemes.
    Normalizes missing schemes for safe local analysis.
    """
    if not raw_url or not isinstance(raw_url, str):
        raise URLValidationError("URL cannot be empty.")

    cleaned = raw_url.strip()

    if len(cleaned) > 2048:
        raise URLValidationError("URL exceeds maximum safe length of 2,048 characters.")

    # Check for forbidden dangerous pseudo-schemes
    lower_raw = cleaned.lower()
    dangerous_schemes = ("javascript:", "data:", "file:", "vbscript:", "blob:", "about:", "chrome:")
    for scheme in dangerous_schemes:
        if lower_raw.startswith(scheme):
            raise URLValidationError(f"Unsupported and potentially hazardous URL scheme '{scheme}'. Only HTTP and HTTPS URLs are analyzed.")

    # Detect user-supplied scheme
    scheme_present = False
    if lower_raw.startswith("http://"):
        scheme_present = True
        normalized = cleaned
    elif lower_raw.startswith("https://"):
        scheme_present = True
        normalized = cleaned
    elif "://" in cleaned:
        # Check if an unknown or non-web scheme was used (e.g. ftp://, gopher://)
        parsed_test = urlparse(cleaned)
        if parsed_test.scheme.lower() not in ("http", "https"):
            raise URLValidationError(f"Unsupported protocol scheme '{parsed_test.scheme}'. PhishNet AI analyzes HTTP and HTTPS links.")
        scheme_present = True
        normalized = cleaned
    else:
        # User entered bare domain like 'example.com/login'
        # Default to http:// for heuristic parsing, but flag that no explicit scheme was supplied
        scheme_present = False
        normalized = "http://" + cleaned

    try:
        parsed = urlsplit(normalized)
    except Exception as e:
        raise URLValidationError(f"Malformed URL could not be parsed: {str(e)}")

    if not parsed.netloc:
        raise URLValidationError("Invalid URL: missing domain or hostname.")

    return {
        "raw_url": cleaned,
        "normalized_url": normalized,
        "scheme_present": scheme_present,
        "scheme": parsed.scheme.lower(),
        "netloc": parsed.netloc,
        "parsed": parsed
    }


def extract_domain_parts(hostname: str) -> dict:
    """
    Splits hostname into subdomain, registered domain, and suffix (TLD)
    using tldextract (Public Suffix List) or fallback rule-based parser.
    """
    clean_host = hostname.strip().lower()
    if clean_host.startswith("[") and clean_host.endswith("]"):
        clean_host = clean_host[1:-1]

    # Check if host is an IP
    is_ip, ip_version = check_is_ip(clean_host)
    if is_ip:
        return {
            "subdomain": "",
            "domain": clean_host,
            "suffix": "",
            "registered_domain": clean_host,
            "is_ip": True,
            "ip_version": ip_version
        }

    if _TLD_EXTRACTOR:
        try:
            ext = _TLD_EXTRACTOR(clean_host)
            reg_domain = f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else clean_host
            return {
                "subdomain": ext.subdomain,
                "domain": ext.domain,
                "suffix": ext.suffix,
                "registered_domain": reg_domain,
                "is_ip": False,
                "ip_version": None
            }
        except Exception:
            pass

    # Fallback PSL parser
    parts = clean_host.split(".")
    if len(parts) >= 2:
        last_two = ".".join(parts[-2:])
        if last_two in FALLBACK_MULTI_SUFFIXES and len(parts) >= 3:
            suffix = last_two
            domain = parts[-3]
            subdomain = ".".join(parts[:-3])
        else:
            suffix = parts[-1]
            domain = parts[-2]
            subdomain = ".".join(parts[:-2])
        reg_domain = f"{domain}.{suffix}"
        return {
            "subdomain": subdomain,
            "domain": domain,
            "suffix": suffix,
            "registered_domain": reg_domain,
            "is_ip": False,
            "ip_version": None
        }

    return {
        "subdomain": "",
        "domain": clean_host,
        "suffix": "",
        "registered_domain": clean_host,
        "is_ip": False,
        "ip_version": None
    }


def check_is_ip(hostname: str) -> tuple[bool, str | None]:
    """
    Determines whether the hostname is an IPv4 or IPv6 address,
    including non-standard forms like integer or hex IPs.
    """
    clean = hostname.strip().strip("[]")
    
    # Standard IPv4 or IPv6 check
    try:
        addr = ipaddress.ip_address(clean)
        return True, f"IPv{addr.version}"
    except ValueError:
        pass

    # Check integer representation (e.g. 2130706433 for 127.0.0.1)
    if clean.isdigit():
        try:
            val = int(clean)
            if 0 <= val <= 0xFFFFFFFF:
                return True, "IPv4 (Decimal Integer Obfuscation)"
        except ValueError:
            pass

    # Check hex representation (e.g. 0x7f000001)
    if clean.lower().startswith("0x"):
        try:
            val = int(clean, 16)
            if 0 <= val <= 0xFFFFFFFF:
                return True, "IPv4 (Hexadecimal Obfuscation)"
        except ValueError:
            pass

    return False, None


def analyze_url(raw_url: str) -> dict:
    """
    Executes comprehensive 15-feature phishing analysis on a given URL.
    Returns calculated risk score, risk level, detected signals,
    extracted features, normalized components, and actionable recommendations.
    """
    validated = validate_and_normalize_url(raw_url)
    parsed = validated["parsed"]
    normalized_url = validated["normalized_url"]

    # Extract Hostname and Port
    hostname = parsed.hostname or ""
    port = parsed.port
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""
    userinfo = parsed.username or ""

    domain_info = extract_domain_parts(hostname)
    registered_domain = domain_info["registered_domain"]
    subdomain = domain_info["subdomain"]
    domain_name = domain_info["domain"]
    suffix = domain_info["suffix"]
    is_ip, ip_type = check_is_ip(hostname)

    signals = []
    total_score = 0

    # ---------------------------------------------------------
    # Feature 1: URL Length
    # ---------------------------------------------------------
    url_len = len(normalized_url)
    if url_len > 120:
        pts = 10
        total_score += pts
        signals.append({
            "id": "url_length_extreme",
            "title": "Abnormally Long URL",
            "severity": "medium",
            "score_impact": pts,
            "explanation": f"The URL is unusually long ({url_len} characters). Phishers often inflate URLs with dummy tokens, redirection targets, or deep directories to obscure the destination.",
            "technical_details": f"Total character count: {url_len} (recommended standard <= 75 chars)"
        })
    elif url_len > 75:
        pts = 5
        total_score += pts
        signals.append({
            "id": "url_length_elevated",
            "title": "Elevated URL Length",
            "severity": "low",
            "score_impact": pts,
            "explanation": f"The URL is longer than typical website links ({url_len} characters). While some legitimate web applications use long URLs, this increases suspicious complexity.",
            "technical_details": f"Total character count: {url_len}"
        })

    # ---------------------------------------------------------
    # Feature 2 & 4: Dots in Hostname and Subdomains
    # ---------------------------------------------------------
    dot_count_host = hostname.count(".")
    subdomain_parts = [p for p in subdomain.split(".") if p] if subdomain else []
    subdomain_count = len(subdomain_parts)

    if not is_ip:
        if dot_count_host >= 4 or subdomain_count >= 3:
            pts = 15
            total_score += pts
            signals.append({
                "id": "excessive_subdomains",
                "title": "Excessive Subdomain Nesting",
                "severity": "high",
                "score_impact": pts,
                "explanation": f"The hostname contains {dot_count_host} dots and {subdomain_count} nested subdomains. Attackers commonly nest subdomains (e.g. login.secure.bank.com.evil.org) to make the URL look authentic on small screens.",
                "technical_details": f"Subdomains detected: '{subdomain}' ({subdomain_count} levels)"
            })
        elif dot_count_host == 3 or subdomain_count == 2:
            pts = 8
            total_score += pts
            signals.append({
                "id": "multiple_subdomains",
                "title": "Multiple Subdomains Present",
                "severity": "medium",
                "score_impact": pts,
                "explanation": f"The hostname contains multiple subdomain levels ({subdomain_count}). This is occasionally seen in complex enterprise apps, but is also used to mimic trusted brands.",
                "technical_details": f"Subdomain: '{subdomain}'"
            })

    # ---------------------------------------------------------
    # Feature 3: Hyphens in Hostname
    # ---------------------------------------------------------
    hyphen_count_host = hostname.count("-")
    if hyphen_count_host >= 3:
        pts = 15
        total_score += pts
        signals.append({
            "id": "excessive_hyphens",
            "title": "Excessive Hyphens in Domain",
            "severity": "high",
            "score_impact": pts,
            "explanation": f"The hostname contains {hyphen_count_host} hyphens. Legitimate brands rarely use multiple hyphens; phishers use concatenated hyphenated words like 'paypal-update-account-security' to spoof legitimacy.",
            "technical_details": f"Hyphens count in hostname '{hostname}': {hyphen_count_host}"
        })
    elif hyphen_count_host >= 2:
        pts = 8
        total_score += pts
        signals.append({
            "id": "multiple_hyphens",
            "title": "Multiple Hyphens in Domain",
            "severity": "medium",
            "score_impact": pts,
            "explanation": f"The hostname contains {hyphen_count_host} hyphens, which is a common heuristic signal in phishing domains trying to string together security keywords.",
            "technical_details": f"Hyphens count in hostname: {hyphen_count_host}"
        })

    # ---------------------------------------------------------
    # Feature 5: IP Address as Hostname
    # ---------------------------------------------------------
    is_ip, ip_type = check_is_ip(hostname)
    if is_ip:
        pts = 35
        total_score += pts
        signals.append({
            "id": "ip_hostname",
            "title": "IP Address Used as Hostname",
            "severity": "high",
            "score_impact": pts,
            "explanation": f"The URL points directly to an IP address ({hostname}, {ip_type}) rather than a registered domain name. Legitimate consumer-facing websites almost always use registered domain names. IP addresses are frequently used in automated phishing and malicious command & control servers.",
            "technical_details": f"Detected IP format: {ip_type} on host '{hostname}'"
        })

    # ---------------------------------------------------------
    # Feature 6: Presence of '@' Symbol in URL
    # ---------------------------------------------------------
    if "@" in raw_url or "@" in normalized_url or userinfo:
        pts = 30
        total_score += pts
        signals.append({
            "id": "at_symbol_spoofing",
            "title": "URL Authentication Symbol (@) Detected",
            "severity": "high",
            "score_impact": pts,
            "explanation": "The URL contains an '@' character. In the HTTP URL specification, browsers treat everything before the '@' as authentication credentials and only connect to the host AFTER the '@'. Attackers exploit this to display 'https://google.com@evil-site.com'.",
            "technical_details": f"Userinfo component or '@' presence found in authority section."
        })

    # ---------------------------------------------------------
    # Feature 7: Suspicious URL Redirection Patterns
    # ---------------------------------------------------------
    redirect_detected = False
    redirect_reason = ""
    # Double slashes after scheme
    if "//" in path:
        redirect_detected = True
        redirect_reason = "Double forward slash ('//') found in the URL path, commonly used to trigger client-side or open web redirects."
    
    # Query parameter open redirect patterns
    parsed_query = parse_qs(query)
    suspicious_redirect_params = {"url", "redirect", "dest", "destination", "r", "next", "target", "link", "to", "forward", "out", "view"}
    for param_name, values in parsed_query.items():
        if param_name.lower() in suspicious_redirect_params:
            for val in values:
                if val.startswith("http://") or val.startswith("https://") or "//" in val:
                    redirect_detected = True
                    redirect_reason = f"Parameter '{param_name}' contains a secondary destination URL ('{val[:40]}...'), typical of open redirect abuse."
                    break

    if redirect_detected:
        pts = 20
        total_score += pts
        signals.append({
            "id": "suspicious_redirect_pattern",
            "title": "Suspicious Redirection Pattern",
            "severity": "high",
            "score_impact": pts,
            "explanation": redirect_reason or "Suspicious URL redirection pattern identified.",
            "technical_details": "Open redirect or secondary URL injection detected in path/query parameters."
        })

    # ---------------------------------------------------------
    # Feature 8: Punycode (IDN Homograph Attack)
    # ---------------------------------------------------------
    if "xn--" in hostname.lower():
        pts = 25
        total_score += pts
        try:
            decoded_host = hostname.encode("ascii").decode("idna")
        except Exception:
            decoded_host = "(undecodable)"
        signals.append({
            "id": "punycode_homograph",
            "title": "Punycode / Internationalized Domain Detected",
            "severity": "high",
            "score_impact": pts,
            "explanation": f"The hostname uses Punycode encoding ('{hostname}'), which decodes to '{decoded_host}'. Attackers use internationalized lookalike Unicode characters (e.g., Cyrillic 'а' replacing Latin 'a') to mimic trusted domains in what is known as an IDN homograph attack.",
            "technical_details": f"Raw: '{hostname}' -> Decoded: '{decoded_host}'"
        })

    # ---------------------------------------------------------
    # Feature 9: URL Encoding in Unusual Contexts
    # ---------------------------------------------------------
    hex_encoding_in_host = "%" in hostname
    excessive_encoding = len(re.findall(r"%[0-9a-fA-F]{2}", raw_url)) >= 3
    double_encoding = "%25" in raw_url.lower()

    if hex_encoding_in_host or double_encoding:
        pts = 20
        total_score += pts
        signals.append({
            "id": "obfuscated_url_encoding",
            "title": "Severe URL Obfuscation / Double Encoding",
            "severity": "high",
            "score_impact": pts,
            "explanation": "The URL contains percent-encoded characters in the domain authority or uses double-encoding (%25), a technique used to evade network filters and intrusion detection systems.",
            "technical_details": "Percent-encoding detected in hostname or double-encoded characters found."
        })
    elif excessive_encoding:
        pts = 8
        total_score += pts
        signals.append({
            "id": "excessive_url_encoding",
            "title": "Heavy Percent-Encoding in Path/Query",
            "severity": "medium",
            "score_impact": pts,
            "explanation": "The URL contains multiple hex-encoded characters (%xx). While some web forms use this, excessive encoding is often applied to hide phishing scripts or stolen credential destinations.",
            "technical_details": f"Found {len(re.findall(r'%[0-9a-fA-F]{2}', raw_url))} percent-encoded byte sequences."
        })

    # ---------------------------------------------------------
    # Feature 10: Suspiciously Long or Complex Query Strings
    # ---------------------------------------------------------
    if len(query) > 100:
        pts = 10
        total_score += pts
        signals.append({
            "id": "long_query_string",
            "title": "Suspiciously Long Query String",
            "severity": "medium",
            "score_impact": pts,
            "explanation": f"The query string component is unusually long ({len(query)} characters). Phishers frequently embed base64-encoded user emails, tracking payloads, or redirect parameters.",
            "technical_details": f"Query string length: {len(query)} characters, {len(parsed_query)} parameters."
        })

    # ---------------------------------------------------------
    # Feature 11: Unusual Ports
    # ---------------------------------------------------------
    if port is not None and port not in STANDARD_PORTS:
        pts = 18
        total_score += pts
        signals.append({
            "id": "non_standard_port",
            "title": "Non-Standard Port Specified",
            "severity": "medium",
            "score_impact": pts,
            "explanation": f"The URL specifies a non-standard web port (:{port}). Legitimate consumer web services operate on port 80 (HTTP) or 443 (HTTPS). Unusual ports are commonly used in staging servers, proxy bypasses, or compromised personal machines.",
            "technical_details": f"Port: {port} (standard ports are 80, 443, 8080, 8443)"
        })

    # ---------------------------------------------------------
    # Feature 12: HTTP Instead of HTTPS
    # ---------------------------------------------------------
    if parsed.scheme.lower() == "http":
        pts = 12
        total_score += pts
        signals.append({
            "id": "unencrypted_http",
            "title": "Unencrypted HTTP Protocol",
            "severity": "medium",
            "score_impact": pts,
            "explanation": "The connection uses unencrypted HTTP instead of HTTPS. All traffic, including login credentials and cookies, is sent in plaintext and vulnerable to interception. Note: While HTTP is insecure, HTTPS alone does not guarantee a site is safe.",
            "technical_details": "Scheme: http:// (TLS/SSL encryption absent)"
        })

    # ---------------------------------------------------------
    # Feature 13 & 14: Deceptive Brand Impersonation & Keywords
    # ---------------------------------------------------------
    brand_impersonation_found = False
    detected_brand = None
    subdomain_lower = subdomain.lower()
    path_lower = path.lower()
    domain_lower = domain_name.lower()

    # Case A: Brand in subdomain while registered domain is something else!
    # Example: paypal.com.attacker.net or apple-support.attacker.com
    for brand in TARGET_BRANDS:
        if brand in subdomain_lower and brand != domain_lower:
            brand_impersonation_found = True
            detected_brand = brand
            break
        # Also check if brand is inside a hyphenated registered domain that is not the official brand
        # e.g., paypal-secure-login.com -> domain_lower is 'paypal-secure-login', not 'paypal'
        if brand in domain_lower and domain_lower != brand:
            # Check if security keywords are also in the domain
            has_kw = any(kw in domain_lower for kw in SUSPICIOUS_KEYWORDS)
            if has_kw or hyphen_count_host >= 2:
                brand_impersonation_found = True
                detected_brand = brand
                break

    if brand_impersonation_found and detected_brand:
        pts = 40
        total_score += pts
        signals.append({
            "id": "brand_impersonation",
            "title": f"High-Confidence Brand Impersonation ({detected_brand.capitalize()})",
            "severity": "high",
            "score_impact": pts,
            "explanation": f"The URL references brand '{detected_brand}' in its subdomain or host structure, but the actual registered domain is '{registered_domain}'. This is a classic brand impersonation technique intended to deceive users into submitting account credentials.",
            "technical_details": f"Target brand: '{detected_brand}' found in context of registered domain '{registered_domain}'"
        })

    # Case B: Suspicious action keywords (login, verify, billing, etc.) in hostname
    keywords_in_host = [kw for kw in SUSPICIOUS_KEYWORDS if kw in hostname.lower()]
    if keywords_in_host and not brand_impersonation_found:
        pts = min(20, len(keywords_in_host) * 10)
        total_score += pts
        signals.append({
            "id": "suspicious_keywords_in_host",
            "title": "Suspicious Security Keywords in Hostname",
            "severity": "medium",
            "score_impact": pts,
            "explanation": f"The hostname includes sensitive action keywords ({', '.join(keywords_in_host)}). Attackers frequently craft domains containing these words to create a false sense of urgency or authenticity.",
            "technical_details": f"Matched keywords: {keywords_in_host} inside hostname '{hostname}'"
        })

    # ---------------------------------------------------------
    # Feature 15: Misleading Hostname Structure & High-Risk TLD
    # ---------------------------------------------------------
    if suffix.lower() in HIGH_RISK_TLDS:
        pts = 15
        total_score += pts
        signals.append({
            "id": "high_abuse_tld",
            "title": f"Frequently Abused Top-Level Domain (.{suffix.lower()})",
            "severity": "medium",
            "score_impact": pts,
            "explanation": f"The domain uses the '.{suffix.lower()}' TLD. Certain generic and free/low-cost TLDs have statistically higher rates of malicious activity and phishing campaigns due to minimal registrar identity verification.",
            "technical_details": f"TLD '.{suffix.lower()}' is on the high-abuse registry watchlist."
        })

    # Detect misleading hostname structure (e.g. 'paypal.com-verify.net' or 'chase.com.security.ru')
    # Checking if a dot-like pattern or popular domain ending (.com, .org, .net) is embedded inside subdomain or host label
    embedded_tlds = re.findall(r"(com|org|net|gov|edu)[-_.]", hostname.lower()[:-len(suffix)-1] if suffix else hostname.lower())
    if embedded_tlds:
        pts = 12
        total_score += pts
        signals.append({
            "id": "embedded_tld_structure",
            "title": "Misleading Hostname Architecture",
            "severity": "high",
            "score_impact": pts,
            "explanation": f"The hostname contains fake extension prefixes ({', '.join(set(embedded_tlds))}) inside its subdomains or labels to make the URL look like a trusted site at a glance.",
            "technical_details": f"Embedded pseudo-TLD markers detected in hostname '{hostname}'"
        })
        signals.append({
            "id": "embedded_tld_structure",
            "title": "Misleading Hostname Architecture",
            "severity": "high",
            "score_impact": pts,
            "explanation": f"The hostname contains fake extension prefixes ({', '.join(set(embedded_tlds))}) inside its subdomains or labels to make the URL look like a trusted site at a glance.",
            "technical_details": f"Embedded pseudo-TLD markers detected in hostname '{hostname}'"
        })

    # ---------------------------------------------------------
    # Score Normalization & Categorization
    # ---------------------------------------------------------
    # Cap total score at 100
    final_score = min(100, max(0, total_score))

    if final_score >= 60:
        risk_level = "High"
        risk_badge_class = "risk-high"
        recommendation = (
            "CRITICAL WARNING: This URL exhibits strong indicators of a phishing or deceptive website. "
            "Do NOT enter passwords, banking details, or personal data. Do not download or execute files from this link."
        )
    elif final_score >= 30:
        risk_level = "Medium"
        risk_badge_class = "risk-medium"
        recommendation = (
            "CAUTION ADVISED: Several suspicious or non-standard URL signals were detected. "
            "Verify the official domain through an independent search engine before logging in or interacting."
        )
    else:
        risk_level = "Low"
        risk_badge_class = "risk-low"
        recommendation = (
            "No major suspicious URL indicators were detected by this scanner. "
            "However, this does NOT guarantee that the website is safe. Always verify the domain name in your browser's address bar."
        )

    # Clean components for UI display
    components = {
        "scheme": parsed.scheme.lower(),
        "hostname": hostname,
        "port": port if port else ("443 (default HTTPS)" if parsed.scheme.lower() == "https" else "80 (default HTTP)"),
        "registered_domain": registered_domain,
        "subdomain": subdomain if subdomain else "(None)",
        "path": path if path else "/",
        "query": query if query else "(None)",
        "fragment": fragment if fragment else "(None)",
        "is_ip": is_ip,
        "url_length": len(normalized_url),
        "dot_count": dot_count_host,
        "hyphen_count": hyphen_count_host
    }

    return {
        "url": raw_url,
        "normalized_url": normalized_url,
        "hostname": hostname,
        "risk_score": final_score,
        "risk_level": risk_level,
        "risk_badge_class": risk_badge_class,
        "signals_count": len(signals),
        "signals": signals,
        "components": components,
        "recommendation": recommendation,
        "is_ip": is_ip
    }


def extract_features_vector(raw_url: str) -> list[float]:
    """
    Extracts a numeric feature vector from a URL suitable for Machine Learning
    classification (e.g. Random Forest or Logistic Regression).
    Returns 12 numerical features:
    0: url_length
    1: hostname_length
    2: dot_count_host
    3: hyphen_count_host
    4: has_at_symbol (0 or 1)
    5: is_ip_host (0 or 1)
    6: is_https (0 or 1)
    7: subdomain_count
    8: path_length
    9: query_length
    10: has_suspicious_keyword (0 or 1)
    11: has_target_brand (0 or 1)
    """
    try:
        validated = validate_and_normalize_url(raw_url)
        parsed = validated["parsed"]
        host = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""
        is_ip, _ = check_is_ip(host)
        
        domain_info = extract_domain_parts(host)
        subdomain = domain_info["subdomain"]
        sub_count = len([p for p in subdomain.split(".") if p]) if subdomain else 0
        
        has_at = 1 if ("@" in raw_url or parsed.username) else 0
        is_https = 1 if parsed.scheme.lower() == "https" else 0
        
        lower_url = raw_url.lower()
        has_kw = 1 if any(kw in lower_url for kw in SUSPICIOUS_KEYWORDS) else 0
        has_brand = 1 if any(b in lower_url for b in TARGET_BRANDS) else 0
        
        return [
            float(len(raw_url)),
            float(len(host)),
            float(host.count(".")),
            float(host.count("-")),
            float(has_at),
            float(1 if is_ip else 0),
            float(is_https),
            float(sub_count),
            float(len(path)),
            float(len(query)),
            float(has_kw),
            float(has_brand)
        ]
    except Exception:
        # Fallback for heavily malformed inputs
        return [0.0] * 12
