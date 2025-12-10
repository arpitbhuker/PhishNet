# features_extractor.py
import re
import socket
import ssl
import validators
import tldextract
from datetime import datetime
import whois
import requests

SUSPICIOUS_KEYWORDS = [
    "login", "secure", "account", "update", "verify", "signin", "bank", "confirm",
    "ebay", "paypal", "amazon", "reset", "credential", "security", "verifyaccount"
]

def contains_ip(url):
    # detect if URL host is an IP address
    m = re.search(r"https?://(\d{1,3}\.){3}\d{1,3}", url)
    return bool(m)

def extract_domain(url):
    ext = tldextract.extract(url)
    domain = ".".join(part for part in (ext.subdomain, ext.domain, ext.suffix) if part)
    return {
        "subdomain": ext.subdomain,
        "domain": ext.domain,
        "suffix": ext.suffix,
        "registered_domain": ext.registered_domain
    }

def get_domain_age_days(domain):
    try:
        w = whois.whois(domain)
        # different WHOIS responses may contain creation_date as list or single
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if not creation:
            return None
        if isinstance(creation, str):
            creation = datetime.strptime(creation, "%Y-%m-%d")
        delta = datetime.utcnow() - creation
        return delta.days
    except Exception:
        return None

def has_https(url):
    return url.lower().startswith("https://")

def count_suspicious_words(url):
    url_lower = url.lower()
    return sum(1 for w in SUSPICIOUS_KEYWORDS if w in url_lower)

def url_length(url):
    return len(url)

def num_dots(url):
    return url.count(".")

def num_hyphens(url):
    return url.count("-")

def get_redirect_count(url, timeout=8):
    try:
        # allow redirects and count final history
        r = requests.get(url, timeout=timeout, allow_redirects=True)
        return len(r.history)
    except Exception:
        return None

def ssl_certificate_valid(domain, timeout=5):
    try:
        # Attempt to get cert via SSL handshake
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                # check expiry date in cert
                not_after = cert.get("notAfter")
                if not_after:
                    exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    return exp > datetime.utcnow()
        return False
    except Exception:
        return False

