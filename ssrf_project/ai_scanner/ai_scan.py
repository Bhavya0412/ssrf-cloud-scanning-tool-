import sys
import os
import csv
import json
import requests

BASE_DIR = "/app"
INPUT_DIR = "/app/input"
OUTPUT_DIR = "/app/output"
AI_DIR = "/app/ai"
PAYLOAD_CSV_PATH = "/app/input/ssrf_payloads.csv"

RESULTS_JSON_PATH = "/app/output/ssrf_ai_results.json"

sys.path.append("/app")

try:
    from orchestrator.utils.ai_interface import classify_ssrf
except Exception as e:
    print("[AI] ERROR importing ai_interface:", str(e))
    raise SystemExit(1)


def load_company_profile(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_example_targets(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_payloads(path):
    rows = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:

            payload = row.get("payload") or row.get("request_path") or ""
            payload = payload.strip()

            if not payload:
                continue

            lower = payload.lower()
            if (
                "127.0.0.1" in lower or
                "localhost" in lower or
                "[::1]" in lower
            ):
                continue

            rows.append(row)

    return rows



def build_scan_jobs(company_profile, example_targets, payload_rows):
    jobs = []

    for env in company_profile.get("cloud_environments", []):
        provider = env.get("provider")
        label = env.get("label")

        for svc in env.get("services", []):
            if not svc.get("ssrf_relevant", False):
                continue

            service_name = svc.get("name")
            base_url = svc.get("base_url")

            for target in example_targets:
                method = target.get("method", "GET").upper()
                target_url = target.get("url")
                target_id = target.get("id")
                params = target.get("params", {})

                url_params = [
                    p for p, meta in params.items()
                    if isinstance(meta, dict) and meta.get("type") == "url"
                ]

                if not url_params:
                    continue

                for prow in payload_rows:

                    jobs.append({
                        "provider": provider,
                        "env_label": label,
                        "service_name": service_name,
                        "service_base_url": base_url,
                        "target_id": target_id,
                        "target_url": target_url,
                        "http_method": method,
                        "url_params": url_params,

                        # FIXED — uses fallback correctly
                        "payload": prow.get("payload") or prow.get("request_path"),

                        # FIXED — use is_vulnerable (0/1)
                        "risk": prow.get("is_vulnerable", "0"),

                        # FIXED — category string
                        "category": f"{prow.get('method')} {prow.get('request_path')}",

                        # FIXED — safe flag
                        "safe_flag": "0" if prow.get("is_vulnerable") == "1" else "1"
                    })

    return jobs



def send_real_request(job):
    url = job["target_url"]
    method = job["http_method"]
    payload = job["payload"]

    params = {}
    data = {}

    for p in job["url_params"]:
        if method == "GET":
            params[p] = payload
        else:
            data[p] = payload

    try:
        resp = requests.request(method, url, params=params, data=data, timeout=8)
        return {
            "status_code": resp.status_code,
            "ok": resp.ok,
            "reason": resp.reason,
            "url": resp.url
        }
    except Exception as e:
        return {
            "status_code": None,
            "ok": False,
            "reason": str(e),
            "url": url
        }



def main():
    print("\n[AI-SCAN] Starting REAL SSRF + AI scan inside Docker...\n")

    company_profile_path = os.path.join(INPUT_DIR, "company_profile.json")
    example_targets_path = os.path.join(INPUT_DIR, "example_targets.json")

    if not os.path.exists(company_profile_path):
        print("[ERROR] company_profile.json missing in /app/input")
        return

    if not os.path.exists(example_targets_path):
        print("[ERROR] example_targets.json missing in /app/input")
        return

    if not os.path.exists(PAYLOAD_CSV_PATH):
        print("[ERROR] ssrf_payloads.csv missing in /app/input")
        return

    company_profile = load_company_profile(company_profile_path)
    example_targets = load_example_targets(example_targets_path)
    payload_rows = load_payloads(PAYLOAD_CSV_PATH)

    print(f"[AI-SCAN] Loaded {len(payload_rows)} non-localhost payloads")
    print(f"[AI-SCAN] Loaded {len(example_targets)} example targets\n")

    jobs = build_scan_jobs(company_profile, example_targets, payload_rows)
    total = len(jobs)

    print(f"[AI-SCAN] Total scan jobs generated: {total}\n")

    findings = []
    jobs_tested = 0


    for idx, job in enumerate(jobs, start=1):
        jobs_tested += 1
        payload = job["payload"]

        print(f"[{idx}/{total}] Testing payload:")
        print(f"   Service: {job['service_name']} ({job['service_base_url']})")
        print(f"   Endpoint: {job['http_method']} {job['target_url']}")
        print(f"   Injecting: {payload}\n")

        http_info = send_real_request(job)
        print(f"   [HTTP] -> {http_info['status_code']} {http_info['reason']} ok={http_info['ok']}")
        print(f"            Final URL: {http_info['url']}")

        category = f"{job['category']} | provider={job['provider']} | service={job['service_name']}"

        decision = classify_ssrf(category, payload, job["risk"])
        print(f"   [AI]   -> Decision: {decision} (GT safe={job['safe_flag']})\n")

        record = {
            "job_index": idx,
            "provider": job["provider"],
            "environment": job["env_label"],
            "service_name": job["service_name"],
            "service_base_url": job["service_base_url"],
            "target_id": job["target_id"],
            "target_url": job["target_url"],
            "http_method": job["http_method"],
            "payload": payload,
            "risk": job["risk"],
            "ai_decision": decision,
            "http_status": http_info["status_code"],
            "http_ok": http_info["ok"],
            "http_reason": http_info["reason"],
            "http_url": http_info["url"]
        }

        if decision == "VULNERABLE":
            findings.append(record)
            print("🚨 SSRF FOUND — stopping early.\n")
            break


    os.makedirs(OUTPUT_DIR, exist_ok=True)

    results_doc = {
        "jobs_generated": total,
        "jobs_tested": jobs_tested,
        "vulnerabilities_found": len(findings),
        "findings": findings
    }

    with open(RESULTS_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(results_doc, f, indent=2)

    print("[AI-SCAN] Results saved to /app/output/ssrf_ai_results.json")
        # ---------------------------------------------------------
    # AUTO-GENERATE PDF REPORT
    # ---------------------------------------------------------
    try:
        print("[AI-SCAN] Generating PDF report...")

        from ssrf_ai_pdf_report import generate_pdf

        pdf_path = os.path.join(OUTPUT_DIR, "ssrf_ai_report.pdf")
        generate_pdf(
            output_json_path=RESULTS_JSON_PATH,
            pdf_path=pdf_path
        )

        print(f"[AI-SCAN] PDF generated at {pdf_path}")

    except Exception as e:
        print("[AI-SCAN] PDF generation failed:", str(e))

    print("[AI-SCAN] Done.\n")


if __name__ == "__main__":
    main()
