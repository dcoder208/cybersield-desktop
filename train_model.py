import pandas as pd
import numpy as np
import joblib
import os
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import re

print("🚀 Training CyberShield Model...")

data = {
    "url": [
        "https://google.com",
        "https://facebook.com",
        "https://amazon.com",
        "https://github.com",
        "http://secure-login-bank.com",
        "http://verify-paypal-account.net",
        "http://free-money.xyz",
        "http://update-your-bank-info.com",
        "http://paypal-login-secure.xyz",
        "http://amazon-giftcard-claim.com"
    ],
    "label": [0,0,0,0,1,1,1,1,1,1]
}

df = pd.DataFrame(data)

def extract_features(url):
    parsed = urlparse(url)
    netloc = parsed.netloc.lower()

    features = []

    features.append(len(url))
    features.append(1 if url.startswith("https") else 0)
    features.append(url.count("."))

    suspicious = ["login","verify","bank","secure","update","free","account","paypal","amazon"]
    features.append(1 if any(word in url.lower() for word in suspicious) else 0)

    features.append(len(netloc.split(".")) - 2 if netloc else 0)
    features.append(1 if "@" in url else 0)
    features.append(1 if re.match(r"\d+\.\d+\.\d+\.\d+", netloc) else 0)
    features.append(netloc.count("-"))
    features.append(sum(c.isdigit() for c in netloc))

    shorteners = ["bit.ly","tinyurl.com","goo.gl"]
    features.append(1 if any(s in url for s in shorteners) else 0)

    return features

df["features"] = df["url"].apply(extract_features)

X = np.array(df["features"].tolist())
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

model = RandomForestClassifier()
model.fit(X_train, y_train)

os.makedirs("model", exist_ok=True)

joblib.dump(model, "model/phishing_model.pkl")
joblib.dump(scaler, "model/scaler.pkl")

print("✅ Model trained and saved!")