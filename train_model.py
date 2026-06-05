"""
Train a Random Forest classifier on synthetic DNS data.
Run this ONCE before launching the application:
    python train_model.py
"""
import random
import string
import base64
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, classification_report
)
import joblib
from features import extract_features

random.seed(42)
np.random.seed(42)

_WORDS = [
    "google", "facebook", "amazon", "microsoft", "apple", "twitter", "youtube",
    "netflix", "github", "stackoverflow", "reddit", "wikipedia", "linkedin",
    "mail", "shop", "blog", "cloud", "api", "www", "static", "cdn", "media",
    "login", "auth", "secure", "portal", "support", "help", "docs", "news",
    "images", "assets", "fonts", "scripts", "content", "files", "update",
]
_TLDS = ["com", "org", "net", "io", "edu", "gov", "co", "info"]
_SUBS = ["www", "mail", "api", "cdn", "static", "app", "dev", "staging",
         "beta", "media", "img", "admin", "login", "secure", ""]
_C2 = ["c2server", "tunnel", "dns-exfil", "data", "exfil", "relay",
       "payload", "botnet", "cnc", "callback", "update"]


def _gen_benign():
    sub = random.choice(_SUBS)
    domain = random.choice(_WORDS)
    tld = random.choice(_TLDS)
    return f"{sub}.{domain}.{tld}" if sub else f"{domain}.{tld}"


def _gen_malicious():
    kind = random.choice(["base64", "hex", "random"])
    size = random.randint(16, 52)
    if kind == "base64":
        raw = "".join(random.choices(string.ascii_letters + string.digits, k=size))
        payload = base64.b64encode(raw.encode()).decode().replace("=", "").lower()[:52]
    elif kind == "hex":
        payload = "".join(random.choices("0123456789abcdef", k=min(size * 2, 52)))
    else:
        payload = "".join(random.choices(string.ascii_lowercase + string.digits, k=size))
    return f"{payload}.{random.choice(_C2)}.{random.choice(_TLDS)}"


def generate_dataset(n_benign=5000, n_malicious=5000):
    print(f"Generating {n_benign} benign + {n_malicious} malicious samples...")
    X, y = [], []
    for _ in range(n_benign):
        X.append(extract_features(_gen_benign()))
        y.append(0)
    for _ in range(n_malicious):
        X.append(extract_features(_gen_malicious()))
        y.append(1)
    return np.array(X), np.array(y)


def train():
    X, y = generate_dataset()
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("Training Random Forest (100 trees)...")
    model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    acc   = accuracy_score(y_test, y_pred)
    prec  = precision_score(y_test, y_pred)
    rec   = recall_score(y_test, y_pred)
    f1    = f1_score(y_test, y_pred)

    print("\n" + "=" * 50)
    print("  MODEL PERFORMANCE EVALUATION")
    print("=" * 50)
    print(f"  Accuracy  : {acc * 100:.2f}%")
    print(f"  Precision : {prec * 100:.2f}%")
    print(f"  Recall    : {rec * 100:.2f}%")
    print(f"  F1 Score  : {f1 * 100:.2f}%")
    print("=" * 50)
    print("\nDetailed Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["Benign", "Tunneling"]))

    joblib.dump(model, "dns_rf_model.pkl")
    print("Model saved to dns_rf_model.pkl")
    return model


if __name__ == "__main__":
    train()
