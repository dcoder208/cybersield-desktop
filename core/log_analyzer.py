import pandas as pd
import re
from collections import Counter


def analyze_logs(file_path):
    try:
        try:
            df = pd.read_csv(file_path)
        except UnicodeDecodeError:
            df = pd.read_csv(file_path, encoding="latin1")

        if df.empty:
            return {
                "total_rows": 0,
                "risk_score": 0,
                "risk_level": "Low",
                "suspicious_ips": [],
                "brute_force_ips": [],
                "malicious_urls": [],
                "threat_events": [],
                "recommendations": ["CSV file is empty. Provide valid logs for analysis."]
            }

        df = df.fillna("")
        total_rows = len(df)

        suspicious_ips = []
        brute_force_ips = []
        malicious_urls = []
        threat_events = []

        ip_column = find_column(df, [
            "ip", "source_ip", "src_ip", "client_ip", "remote_ip",
            "host", "source", "src", "ip_address"
        ])

        status_column = find_column(df, [
            "status", "result", "login_status", "action", "outcome",
            "response", "auth_status"
        ])

        url_column = find_column(df, [
            "url", "domain", "website", "request", "uri", "path",
            "link", "destination"
        ])

        event_column = find_column(df, [
            "event", "message", "description", "activity", "log",
            "details", "reason", "alert"
        ])

        if ip_column:
            ip_counts = Counter(df[ip_column].astype(str))

            for ip, count in ip_counts.items():
                if is_valid_ip(ip) and count >= 10:
                    suspicious_ips.append({
                        "ip": ip,
                        "count": count,
                        "reason": "High number of repeated activities from same IP"
                    })

        if ip_column and status_column:
            failed_logs = df[
                df[status_column].astype(str).str.lower().str.contains(
                    "fail|failed|denied|blocked|unauthorized|invalid|error|rejected",
                    na=False,
                    regex=True
                )
            ]

            failed_counts = Counter(failed_logs[ip_column].astype(str))

            for ip, count in failed_counts.items():
                if is_valid_ip(ip) and count >= 5:
                    brute_force_ips.append({
                        "ip": ip,
                        "failed_attempts": count,
                        "reason": "Possible brute-force attack detected"
                    })

        if url_column:
            for url in df[url_column].astype(str):
                if is_suspicious_url(url):
                    malicious_urls.append(url)

        if event_column:
            suspicious_events = df[
                df[event_column].astype(str).str.lower().str.contains(
                    "malware|phishing|attack|exploit|scan|bruteforce|brute force|blocked|unauthorized|sql injection|xss|ransomware|trojan",
                    na=False,
                    regex=True
                )
            ]

            for _, row in suspicious_events.iterrows():
                event_text = str(row[event_column])
                if event_text and event_text not in threat_events:
                    threat_events.append(event_text)

        risk_score = 0
        risk_score += len(suspicious_ips) * 10
        risk_score += len(brute_force_ips) * 25
        risk_score += len(set(malicious_urls)) * 15
        risk_score += len(threat_events) * 8

        risk_score = min(risk_score, 100)

        if risk_score >= 70:
            risk_level = "High"
        elif risk_score >= 35:
            risk_level = "Medium"
        else:
            risk_level = "Low"

        return {
            "total_rows": total_rows,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "suspicious_ips": suspicious_ips[:20],
            "brute_force_ips": brute_force_ips[:20],
            "malicious_urls": list(dict.fromkeys(malicious_urls))[:25],
            "threat_events": threat_events[:25],
            "recommendations": generate_recommendations(risk_level)
        }

    except Exception as e:
        return {
            "error": f"Log analysis failed safely: {str(e)}"
        }


def find_column(df, possible_names):
    normalized_columns = {col.lower().strip(): col for col in df.columns}

    for name in possible_names:
        if name in normalized_columns:
            return normalized_columns[name]

    for col in df.columns:
        lower_col = col.lower().strip()
        for name in possible_names:
            if name in lower_col:
                return col

    return None


def is_valid_ip(value):
    pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"
    if not re.match(pattern, str(value)):
        return False

    parts = str(value).split(".")
    return all(0 <= int(part) <= 255 for part in parts)


def is_suspicious_url(url):
    url = str(url).lower().strip()

    if not url:
        return False

    suspicious_words = [
        "login", "verify", "bank", "secure", "update", "free",
        "account", "paypal", "gift", "claim", "password", "otp",
        "wallet", "signin", "billing"
    ]

    risky_tlds = [".xyz", ".top", ".info", ".ru", ".tk", ".cn", ".zip"]

    if any(word in url for word in suspicious_words):
        return True

    if any(tld in url for tld in risky_tlds):
        return True

    if "@" in url:
        return True

    if url.count("-") >= 2:
        return True

    if re.search(r"http[s]?://\d{1,3}(\.\d{1,3}){3}", url):
        return True

    return False


def generate_recommendations(risk_level):
    if risk_level == "High":
        return [
            "Immediately block suspicious IP addresses.",
            "Investigate repeated failed login attempts.",
            "Reset passwords for targeted accounts.",
            "Enable MFA for affected users.",
            "Review firewall, IDS, and authentication logs.",
            "Create an incident ticket for SOC investigation."
        ]

    if risk_level == "Medium":
        return [
            "Monitor suspicious IP addresses closely.",
            "Review authentication logs for repeated failures.",
            "Validate suspicious URLs and domains.",
            "Increase logging and alert sensitivity.",
            "Apply temporary firewall restrictions if activity continues."
        ]

    return [
        "No major threats detected.",
        "Continue monitoring logs regularly.",
        "Maintain updated firewall and authentication policies.",
        "Keep MFA enabled for important accounts."
    ]