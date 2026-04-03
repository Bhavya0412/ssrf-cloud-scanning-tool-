import sys
import os
import csv
import json
import requests

# Make ssrf_project importable
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from orchestrator.utils.ai_interface import classify_ssrf

# Paths
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
INPUT_DIR = os.path.join(BASE_DIR, "input")
PAYLOAD_DIR = os.path.join(BASE_DIR, "payloads", "ssrf")
OUTPUT_DIR = os.path.join(BASE_DIR, "output")

COMPANY_PROFILE_PATH = os.path.join(INPUT_DIR, "company_profile.json")
EXAMPLE_TARGETS_PATH = os.path.join(INPUT_DIR, "example_targets.json")
PAYLOAD_CSV_PATH = os.path.join(PAYLOAD_DIR, "ssrf_payloads.csv")
RESULTS_JSON_PATH = os.path.join(OUTPUT_DIR, "ssrf_ai_results.json")


# -----------------------------
# Load helpers
# -----------------------------
def load_company_profile(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_example_targets(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_payloads(path: str):
    """Load payloads from CSV, skipping localhost/127/::1."""
    rows = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            payload = (row.get("payload") or "").strip()
            if not payload:
                continue

            lower = payload.lower()
            if (
                "127.0.0.1" in lower
                or "localhost" in lower
                or "[::1]" in lower
            ):
                # Skip localhost-style payloads for this run
                continue

            rows.append(row)
    return rows


# -----------------------------
# Build scan jobs from JSON
# -----------------------------
def build_scan_jobs(company_profile, example_targets, payload_rows):
    """
    Combine:
      - ssrf_relevant services from company_profile.json
      - example targets from example_targets.json
      - non-localhost payloads from ssrf_payloads.csv
    into a list of jobs.
    """
    jobs = []

    for env in company_profile.get("cloud_environments", []):
        provider = env.get("provider")
        label = env.get("label")

        for svc in env.get("services", []):
            if not svc.get("ssrf_relevant", False):
                continue

            service_name = svc.get("name")
            base_url = svc.get("base_url")
            description = svc.get("description")

            for target in example_targets:
                target_id = target.get("id")
                target_url = target.get("url")
                method = target.get("method", "GET").upper()
                params = target.get("params", {})

                # Only params marked as type=url are interesting for SSRF
                url_params = [
                    name
                    for name, meta in params.items()
                    if isinstance(meta, dict) and meta.get("type") == "url"
                ]
                if not url_params:
                    continue

                for prow in payload_rows:
                    jobs.append(
                        {
                            "provider": provider,
                            "env_label": label,
                            "service_name": service_name,
                            "service_base_url": base_url,
                            "service_description": description,
                            "target_id": target_id,
                            "target_url": target_url,
                            "http_method": method,
                            "url_params": url_params,
                            "payload": prow["payload"],
                            "risk": prow["risk"],
                            "category": prow["category"],
                            "safe_flag": prow["safe"],
                        }
                    )
    return jobs


# -----------------------------
# Real HTTP request
# -----------------------------
def send_real_request(job):
    """
    Sends a REAL HTTP request to the external test endpoint
    (httpbin / postman-echo) with the SSRF payload injected into
    the URL parameter.

    This is SAFE: the target server simply echoes the parameter,
    it does NOT actually fetch internal metadata.
    """
    url = job["target_url"]
    method = job["http_method"]
    payload = job["payload"]
    params = {}
    data = {}

    # Put payload into all url-type params
    for p in job["url_params"]:
        if method == "GET":
            params[p] = payload
        else:
            data[p] = payload

    try:
        resp = requests.request(
            method,
            url,
            params=params,
            data=data,
            timeout=8,
        )
        info = {
            "status_code": resp.status_code,
            "ok": resp.ok,
            "reason": resp.reason,
            "url": resp.url,
        }
    except Exception as e:
        info = {
            "status_code": None,
            "ok": False,
            "reason": str(e),
            "url": url,
        }

    return info


# -----------------------------
# MAIN AI + REAL SCAN
# -----------------------------
def main():
    print("[AI-SCAN] Starting REAL SSRF AI scan (HTTP + AI)...\n")

    # Ensure output directory
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Check required files
    for path, label in [
        (COMPANY_PROFILE_PATH, "company_profile.json"),
        (EXAMPLE_TARGETS_PATH, "example_targets.json"),
        (PAYLOAD_CSV_PATH, "ssrf_payloads.csv"),
    ]:
        if not os.path.exists(path):
            print(f"[ERROR] Missing {label} at: {path}")
            return

    company_profile = load_company_profile(COMPANY_PROFILE_PATH)
    example_targets = load_example_targets(EXAMPLE_TARGETS_PATH)
    payload_rows = load_payloads(PAYLOAD_CSV_PATH)

    print(f"[AI-SCAN] Loaded {len(payload_rows)} non-localhost payloads.")
    print(f"[AI-SCAN] Loaded {len(example_targets)} example targets.\n")

    jobs = build_scan_jobs(company_profile, example_targets, payload_rows)
    total = len(jobs)

    if total == 0:
        print("[AI-SCAN] No scan jobs generated. Check input files.")
        return

    print(f"[AI-SCAN] Generated {total} scan jobs.\n")

    findings = []
    jobs_tested = 0

    for idx, job in enumerate(jobs, start=1):
        jobs_tested += 1
        payload = job["payload"]

        print(f"[{idx}/{total}] REAL request with payload:")
        print(f"   Cloud:   {job['provider']} ({job['env_label']})")
        print(f"   Service: {job['service_name']}  ({job['service_base_url']})")
        print(f"   Target:  {job['http_method']} {job['target_url']}")
        print(f"   Params:  {', '.join(job['url_params'])}")
        print(f"   Payload: {payload}")

        # -------- REAL HTTP request ----------
        http_info = send_real_request(job)
        status = http_info["status_code"]
        ok = http_info["ok"]
        reason = http_info["reason"]

        print(f"   [HTTP] -> {status} {reason}   ok={ok}")
        print(f"           Final URL: {http_info['url']}")

        # -------- AI classification ----------
        full_category = (
            f"{job['category']} | provider={job['provider']} "
            f"| service={job['service_name']} | endpoint={job['target_id']}"
        )
        decision = classify_ssrf(full_category, payload, job["risk"])

        print(
            f"   [AI]   -> Decision: {decision}   (GT safe={job['safe_flag']})\n"
        )

        record = {
            "job_index": idx,
            "provider": job["provider"],
            "environment": job["env_label"],
            "service_name": job["service_name"],
            "service_base_url": job["service_base_url"],
            "target_id": job["target_id"],
            "target_url": job["target_url"],
            "http_method": job["http_method"],
            "url_params": job["url_params"],
            "payload": payload,
            "risk": job["risk"],
            "category": job["category"],
            "safe_flag": job["safe_flag"],
            "ai_decision": decision,
            "http_status": status,
            "http_ok": ok,
            "http_reason": reason,
            "http_final_url": http_info["url"],
        }

        if decision == "VULNERABLE":
            print("==============================================")
            print("🚨  SSRF FOUND by AI on this REAL test case!")
            print("==============================================\n")
            findings.append(record)
            # EARLY STOP like you wanted
            break

        # If you want to keep testing all jobs, comment this block out
        # and just append record for SAFE too.

    # Save JSON results for reporting
    results_doc = {
        "jobs_generated": total,
        "jobs_tested": jobs_tested,
        "vulnerabilities_found": len(findings),
        "findings": findings,
    }

    with open(RESULTS_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(results_doc, f, indent=2)

    print("[AI-SCAN] Results saved to:")
    print(f"   {RESULTS_JSON_PATH}")

    if findings:
        print(f"[AI-SCAN] TOTAL VULNERABLE COMBINATIONS FOUND: {len(findings)}")
    else:
        print("[AI-SCAN] No SSRF found by AI in tested jobs.")


if __name__ == "__main__":
    main()
