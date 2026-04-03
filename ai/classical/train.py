import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import joblib
import os

DATA_PATH = os.path.join("data", "ssrf_dataset.csv")
df = pd.read_csv(DATA_PATH)
df = df.dropna()

X = df.drop(columns=["is_vulnerable", "id"])
y = df["is_vulnerable"]

categorical_features = ["method", "request_path"]
numeric_features = [
    "has_user_supplied_url_param",
    "has_ip_literal",
    "has_internal_keyword",
    "protocol_restricted",
    "hostname_validation",
    "redirects",
    "query_params",
    "suspicious_keyword"
]

preprocessor = ColumnTransformer(
    transformers=[
        ("cat", OneHotEncoder(handle_unknown="ignore"), categorical_features),
        ("num", "passthrough", numeric_features)
    ]
)

model = RandomForestClassifier(
    n_estimators=300,
    random_state=42,
    class_weight="balanced"
)

clf = Pipeline(steps=[
    ("preprocess", preprocessor),
    ("model", model),
])

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.25, random_state=42, stratify=y
)

print("[*] Training SSRF detection model...")
clf.fit(X_train, y_train)

y_pred = clf.predict(X_test)
print("\n[*] Evaluation Results:")
print("Accuracy:", accuracy_score(y_test, y_pred))
print(classification_report(y_test, y_pred))

joblib.dump(clf, "ssrf_model.joblib")
print("\n[*] Model saved to: ssrf_model.joblib")
