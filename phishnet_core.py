# phishnet_core.py
import validators
from features_extractor import (
    extract_domain, contains_ip, get_domain_age_days, has_https,
    count_suspicious_words, url_length, num_dots, num_hyphens,
    get_redirect_count, ssl_certificate_valid
)
import requests
from bs4 import BeautifulSoup

def analyze_url(url):
    result = {"url": url}
    # basic validation
    result["is_valid_url"] = validators.url(url)
    if not result["is_valid_url"]:
        result["error"] = "Invalid URL format"
        result["risk_score"] = 100
        return result

    # domain parsing
    d = extract_domain(url)
    result.update(d)

    result["uses_ip"] = contains_ip(url)
    result["https"] = has_https(url)
    result["length"] = url_length(url)
    result["dots"] = num_dots(url)
    result["hyphens"] = num_hyphens(url)
    result["suspicious_word_count"] = count_suspicious_words(url)

    # domain age
    domain_for_whois = d.get("registered_domain") or d.get("domain")
    dom_age = None
    try:
        dom_age = get_domain_age_days(domain_for_whois)
    except Exception:
        dom_age = None
    result["domain_age_days"] = dom_age

    # redirects
    redirects = get_redirect_count(url)
    result["redirects_count"] = redirects

    # check SSL (domain only)
    try:
        result["ssl_valid"] = ssl_certificate_valid(d.get("registered_domain") or d.get("domain"))
    except Exception:
        result["ssl_valid"] = False

    # small content checks - try fetch page
    page_info = {"fetch_success": False, "title": None, "forms": 0, "external_favicon": False}
    try:
        r = requests.get(url, timeout=8)
        r.raise_for_status()
        page_info["fetch_success"] = True
        soup = BeautifulSoup(r.text, "html.parser")
        title = soup.title.string.strip() if soup.title and soup.title.string else ""
        page_info["title"] = title
        page_info["forms"] = len(soup.find_all("form"))
        # favicon detection
        icon = soup.find("link", rel=lambda x: x and "icon" in x.lower())
        if icon and icon.get("href"):
            href = icon.get("href")
            # external if favicon href contains a different domain or starts with http
            page_info["external_favicon"] = href.startswith("http")
    except Exception:
        pass
    result.update(page_info)

    # compute a simple risk score (0 safe -> 100 dangerous)
    score = 0
    # base rules
    if not result["https"]:
        score += 20
    if result["uses_ip"]:
        score += 25
    if result["suspicious_word_count"] >= 1:
        score += min(30, 10 * result["suspicious_word_count"])
    if result["length"] > 75:
        score += 10
    if result["dots"] > 5:
        score += 5
    if (result["hyphens"] > 3):
        score += 5
    if result["redirects_count"] and result["redirects_count"] > 2:
        score += 10
    if result.get("domain_age_days") is not None:
        if result["domain_age_days"] < 30:
            score += 25
        elif result["domain_age_days"] < 365:
            score += 10
    else:
        # unknown WHOIS - raise caution
        score += 5

    if not result.get("ssl_valid", False):
        score += 10

    if result.get("forms", 0) > 0 and ("login" in (result.get("title") or "").lower() or result["forms"] > 2):
        score += 10

    if result.get("external_favicon"):
        score += 5

    # clamp
    risk_score = max(0, min(100, score))
    result["risk_score"] = risk_score

    # label
    if risk_score >= 70:
        result["label"] = "Likely Phishing"
    elif risk_score >= 40:
        result["label"] = "Suspicious — Investigate"
    else:
        result["label"] = "Probably Safe"

    # list major reasons
    reasons = []
    if not result["https"]:
        reasons.append("No HTTPS")
    if result["uses_ip"]:
        reasons.append("URL uses IP address")
    if result["suspicious_word_count"] >= 1:
        reasons.append(f"Contains suspicious words ({result['suspicious_word_count']})")
    if result["domain_age_days"] is not None and result["domain_age_days"] < 30:
        reasons.append("Very recently registered domain")
    if result.get("redirects_count") and result["redirects_count"] > 2:
        reasons.append("Multiple redirects")
    if not result.get("ssl_valid", False):
        reasons.append("SSL certificate invalid or not trusted")
    if result.get("external_favicon"):
        reasons.append("External favicon host")
    if result.get("forms", 0) > 0:
        reasons.append(f"Has {result['forms']} forms (possible credential capture)")

    result["reasons"] = reasons
    return result

