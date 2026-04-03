#!/usr/bin/env python3
import sys
import json
import os
import uuid
import time
from pathlib import Path
import requests

# Try to import interactsh client; if absent we fallback to local token.
try:
    from tools.interactsh_client import InteractshClient
except Exception:
    InteractshClient = None

ROOT = Path(__file__).parent.parent.parent
OUT_DIR = Path(os.environ.get("OUT_DIR", "/out"))
OUT_DIR.mkdir(parents=True, exist_ok=True)

DEFAULT_PAYLOADS = ROOT / "payloads" / "ssrf" / "default_payloads.txt"
SAFE_MODE = os.environ.get("SSRF_SAFE_MODE", "1") == "1"
OOB_BASE = os.environ.get("OOB_BASE_DOMAIN", "oob.localtest.me")

TIMEOUT = 8  # seconds per request

def generate_oob(scan_id=None):
    if InteractshClient:
        try:
            client = InteractshClient()
            info = client.register(prefix=(scan_id or str(uuid.uuid4())), ttl=3600)
            return info.get("domain"), info.get("id")
        except Exception as e:
            print("WARN: interactsh register failed:", e)
    # fallback
    token = uuid.uuid4().hex
    return f"{token}.{OOB_BASE}", token

def load_payloads(oob_domain):
    if not DEFAULT_PAYLOADS.exists():
        return [f"http://{oob_domain}"]
    lines = [ln.strip() for ln in DEFAULT_PAYLOADS.read_text().splitlines() if ln.strip()]
    out = []
    for ln in lines:
        # Skip dangerous in safe mode
        if SAFE_MODE and ("file://" in ln or ln.startswith("gopher://")):
            continue
        out.append(ln.replace("{OOB}", oob_domain))
    return out

def build_requests_for_target(target, payload):
    # target: dict with url, method, params
    method = (target.get("method") or "GET").upper()
    url = target.get("url")
    params = target.get("params") or {}
    reqs = []
    # try param injection
    if params:
        for pname in params.keys():
            # form-data style (send as form or files depending)
            data = {}
            for k in params.keys():
                if k == pname:
                    data[k] = payload
                else:
                    v = params[k]
                    if isinstance(v, dict):
                        data[k] = v.get("example") or ""
                    else:
                        data[k] = str(v)
            reqs.append({"method": method, "url": url, "params": None, "data": data, "param_name": pname})
    # also try as query param "url"
    reqs.append({"method": "GET", "url": url, "params": {"url": payload}, "data": None, "param_name": "url"})
    return reqs

def send_request(reqobj):
    try:
        if reqobj.get("data") is not None:
            r = requests.request(reqobj["method"], reqobj["url"], data=reqobj.get("data"), timeout=TIMEOUT, allow_redirects=False, verify=False)
        else:
            r = requests.request(reqobj["method"], reqobj["url"], params=reqobj.get("params"), timeout=TIMEOUT, allow_redirects=False, verify=False)
        return {"status_code": r.status_code, "headers": dict(r.headers), "body_snippet": (r.text[:2000] if r.text else "")}
    except Exception as e:
        return {"error": str(e)}

def analyze_target(target, oob_domain):
    findings = []
    payloads = load_payloads(oob_domain)
    for payload in payloads:
        reqs = build_requests_for_target(target, payload)
        for r in reqs:
            info = {"payload": payload, "param": r.get("param_name"), "method": r.get("method"), "url": r.get("url")}
            res = send_request(r)
            info["response"] = res
            # heuristics for evidence
            body = str(res.get("body_snippet") or "").lower()
            headers = " ".join([f"{k}:{v}".lower() for k, v in (res.get("headers") or {}).items()])
            triggered = False
            notes = []
            if any(x in body for x in ("iam", "accesskey", "security-credentials", "meta-data", "metadata", "instance")):
                triggered = True
                notes.append("body-matches-metadata")
            if res.get("status_code") and 300 <= int(res.get("status_code")) < 400:
                loc = (res.get("headers") or {}).get("Location", "")
                if "169.254" in loc or "metadata" in loc:
                    triggered = True
                    notes.append(f"redirects-to-internal:{loc}")
            if triggered:
                sev = "high" if "accesskey" in body or "security-credentials" in body else "medium"
                findings.append({
                    "tool": "ssrf_fuzzer",
                    "target_id": target.get("id"),
                    "endpoint": r.get("url"),
                    "param": r.get("param_name"),
                    "payload": payload,
                    "evidence": {"raw": res, "notes": notes},
                    "severity": sev,
                    "confidence": "medium"
                })
    return findings

def main():
    raw = sys.stdin.read()
    if not raw:
        print(json.dumps({"error": "no input"}))
        return
    job = json.loads(raw)
    target = job.get("target") or {}
    scan_id = job.get("id") or str(uuid.uuid4())
    oob_domain = job.get("oob_domain")
    if not oob_domain:
        oob_domain, token_id = generate_oob(scan_id)
    else:
        # still generate local token registration to keep consistent shape (best-effort)
        try:
            local_dom, local_id = generate_oob(scan_id)
        except Exception:
            pass
    findings = analyze_target(target, oob_domain)
    result = {"job_id": scan_id, "target": target.get("id"), "oob": {"domain": oob_domain}, "findings": findings}
    outpath = OUT_DIR / f"{target.get('id')}_{scan_id}.json"
    outpath.write_text(json.dumps(result, indent=2))
    print(json.dumps(result))

if __name__ == "__main__":
    main()
