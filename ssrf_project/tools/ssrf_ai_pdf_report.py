import os
import sys
import json
from datetime import datetime

# Make root project (ssrf) visible so we can import the report script
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.append(PROJECT_ROOT)

try:
    from generate_compliance_report import ObseraVulnerabilityReport
except ImportError as e:
    print("[REPORT] ERROR: Could not import generate_compliance_report.py")
    print("        Make sure it is located at:")
    print(f"        {os.path.join(PROJECT_ROOT, 'generate_compliance_report.py')}")
    print(f"        Import error: {e}")
    raise SystemExit(1)

# Path to the JSON created by ai_scan.py
SSRFP_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RESULTS_JSON = os.path.join(SSRFP_ROOT, "output", "ssrf_ai_results.json")


def main():
    print("=" * 70)
    print("🛡️  SSRF AI SCAN → PDF REPORT")
    print("=" * 70)

    if not os.path.exists(RESULTS_JSON):
        print("[REPORT] ERROR: ssrf_ai_results.json not found.")
        print("         Run tools/ai_scan.py first.")
        return

    with open(RESULTS_JSON, "r", encoding="utf-8") as f:
        results = json.load(f)

    vulns = results.get("findings", [])
    total_jobs = results.get("jobs_generated", 0)
    tested_jobs = results.get("jobs_tested", 0)

    print(f"[REPORT] Jobs generated : {total_jobs}")
    print(f"[REPORT] Jobs tested    : {tested_jobs}")
    print(f"[REPORT] Vulns found    : {len(vulns)}")

    # We will generate a generic vulnerability report,
    # but set target_url to indicate it's from an SSRF AI scan.
    target_label = f"SSRF AI Scan ({len(vulns)} findings)"

    report = ObseraVulnerabilityReport(
        target_url=target_label,
        scan_type="SSRF AI + Compliance Assessment",
    )

    # Output under ssrf_project/output/
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_pdf = os.path.join(
        SSRFP_ROOT, "output", f"SSRF_AI_Compliance_Report_{timestamp}.pdf"
    )

    path = report.generate_report(output_path=out_pdf)

    print()
    print("[REPORT] PDF generated:")
    print(f"         {path}")
    print("=" * 70)


if __name__ == "__main__":
    main()
