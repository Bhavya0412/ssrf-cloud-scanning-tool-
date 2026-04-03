import joblib
import pandas as pd

clf = joblib.load("ssrf_model.joblib")

sample = pd.DataFrame([{
    "method": "GET",
    "request_path": "/image-proxy",
    "has_user_supplied_url_param": 1,
    "has_ip_literal": 1,
    "has_internal_keyword": 1,
    "protocol_restricted": 0,
    "hostname_validation": 0,
    "redirects": 1,
    "query_params": 1,
    "suspicious_keyword": 1
}])

prediction = clf.predict(sample)[0]
print("VULNERABLE" if prediction == 1 else "SAFE")
