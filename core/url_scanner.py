import os
import sys
import re
import ipaddress
import joblib
import numpy as np
from urllib.parse import urlparse

from core.threat_explainer import explain_threat


def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    return os.path.join(base_path, relative_path)


MODEL_PATH = resource_path("model/phishing_model.pkl")
SCALER_PATH = resource_path("model/scaler.pkl")

try:
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
except Exception as e:
    print("Model loading failed:", e)
    model = None
    scaler = None


def is_ip_address(value):
    try:
        clean_value = str(value).split(":")[0]
        ipaddress.ip_address(clean_value)
        return True
    except:
        return False


def normalize_url(url):
    url = str(url).strip()

    if not url:
        return None, "Empty URL. Please enter a website URL."

    dangerous_schemes = ["javascript:", "data:", "file:", "ftp:"]

    if any(url.lower().startswith(scheme) for scheme in dangerous_schemes):
        return None, "Unsupported or dangerous URL scheme."

    if url in ["http://", "https://"]:
        return None, "Incomplete URL. Please enter a full domain."

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    domain = parsed.netloc.lower().strip()

    if not domain:
        return None, "Invalid URL format."

    if domain in ["localhost"]:
        return url, None

    if is_ip_address(domain):
        return url, None

    if "." not in domain:
        return None, "Invalid domain. Please enter a real website like google.com or https://example.com"

    return url, None


def extract_features(url):
    parsed = urlparse(url)
    netloc = parsed.netloc.lower()
    full_url = url.lower()

    features = []

    suspicious = [
        "login", "verify", "bank", "secure", "update",
        "free", "account", "paypal", "amazon", "gift",
        "claim", "password", "otp", "signin", "billing"
    ]

    shorteners = [
        "bit.ly", "tinyurl.com", "goo.gl", "t.co",
        "ow.ly", "shorturl.at", "cutt.ly", "rebrand.ly"
    ]

    features.append(len(url))
    features.append(1 if url.startswith("https://") else 0)
    features.append(url.count("."))
    features.append(1 if any(word in full_url for word in suspicious) else 0)
    features.append(max(len(netloc.split(".")) - 2, 0) if netloc else 0)
    features.append(1 if "@" in url else 0)
    features.append(1 if is_ip_address(netloc) else 0)
    features.append(netloc.count("-"))
    features.append(sum(c.isdigit() for c in netloc))
    features.append(1 if any(s in full_url for s in shorteners) else 0)

    return features


def rule_based_score(url):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    full_url = url.lower()

    score = 0
    reasons = []

    risky_tlds = [".xyz", ".top", ".info", ".tk", ".ru", ".cn", ".zip"]
    brand_keywords = ["paypal", "amazon", "microsoft", "google", "netflix", "bank"]
    phishing_words = [
        "login", "verify", "account", "secure", "update",
        "password", "otp", "claim", "signin", "billing"
    ]

    if not url.startswith("https://"):
        score += 15
        reasons.append("Website does not use HTTPS.")

    if any(tld in domain for tld in risky_tlds):
        score += 20
        reasons.append("Domain uses a commonly abused extension.")

    if any(word in full_url for word in phishing_words):
        score += 20
        reasons.append("URL contains phishing-related keywords.")

    if any(brand in full_url for brand in brand_keywords) and "-" in domain:
        score += 20
        reasons.append("Possible brand impersonation using hyphenated domain.")

    if "@" in url:
        score += 25
        reasons.append("URL contains @ symbol, often used for redirection tricks.")

    if is_ip_address(domain):
        score += 20
        reasons.append("URL uses raw IP address instead of a domain.")

    if domain.count("-") >= 2:
        score += 10
        reasons.append("Domain contains multiple hyphens.")

    if len(url) > 90:
        score += 10
        reasons.append("URL is unusually long.")

    if domain.count(".") >= 3:
        score += 10
        reasons.append("URL contains multiple subdomains.")

    return min(score, 100), reasons


def scan_url(url):
    normalized_url, error = normalize_url(url)

    if error:
        return {
            "url": str(url),
            "verdict": "Invalid",
            "risk_score": 0,
            "ml_confidence": 0,
            "explanation": {
                "reasons": [error],
                "possible_impacts": [
                    "CyberShield could not analyze this input as a valid website URL."
                ],
                "recommendations": [
                    "Enter a valid website URL such as https://google.com or example.com."
                ]
            }
        }

    url = normalized_url
    rule_score, rule_reasons = rule_based_score(url)

    if model is not None and scaler is not None:
        try:
            features = np.array([extract_features(url)])
            scaled_features = scaler.transform(features)

            probability = float(model.predict_proba(scaled_features)[0][1] * 100)
        except Exception as e:
            print("ML prediction failed:", e)
            probability = 0
    else:
        probability = 0

    final_score = int(max(probability, rule_score))

    if final_score >= 70:
        verdict = "Malicious"
    elif final_score >= 40:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    explanation = explain_threat(url, verdict, final_score)

    if rule_reasons:
        explanation["reasons"] = list(dict.fromkeys(explanation["reasons"] + rule_reasons))

    return {
        "url": url,
        "verdict": verdict,
        "risk_score": final_score,
        "ml_confidence": round(probability, 2),
        "explanation": explanation
    }