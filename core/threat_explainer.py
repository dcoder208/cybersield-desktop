from urllib.parse import urlparse


def explain_threat(url, verdict, risk_score):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    reasons = []
    possible_impacts = []
    recommendations = []

    suspicious_keywords = [
        "login", "verify", "bank", "secure", "update",
        "free", "account", "paypal", "amazon"
    ]

    if any(word in url.lower() for word in suspicious_keywords):
        reasons.append("URL contains suspicious keywords commonly used in phishing attacks.")
        possible_impacts.append("Credential theft or fake login page attack.")

    if not url.startswith("https://"):
        reasons.append("Website does not use HTTPS.")
        possible_impacts.append("User data may be intercepted during transmission.")

    if "-" in domain:
        reasons.append("Domain contains hyphens, often used in fake brand impersonation domains.")
        possible_impacts.append("Brand impersonation or fake service page.")

    if domain.endswith(".xyz") or domain.endswith(".top") or domain.endswith(".info"):
        reasons.append("Domain uses a high-risk or commonly abused extension.")
        possible_impacts.append("Possible phishing, scam, or malware distribution.")

    if risk_score >= 70:
        recommendations.append("Do not open this website.")
        recommendations.append("Do not enter passwords, OTPs, banking details, or personal information.")
        recommendations.append("Block or report this URL if found in emails or messages.")
    elif risk_score >= 40:
        recommendations.append("Proceed carefully and verify the website manually.")
        recommendations.append("Avoid entering sensitive information.")
    else:
        recommendations.append("No major threat indicators detected, but continue practicing safe browsing.")

    if not reasons:
        reasons.append("No strong suspicious indicators detected.")

    if not possible_impacts:
        possible_impacts.append("Low immediate risk detected.")

    return {
        "reasons": reasons,
        "possible_impacts": possible_impacts,
        "recommendations": recommendations
    }