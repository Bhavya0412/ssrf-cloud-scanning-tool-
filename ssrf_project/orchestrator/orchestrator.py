#!/usr/bin/env python3
import json
import uuid
import time
import shutil
import subprocess
from pathlib import Path
from typing import List, Dict, Any

from tools.interactsh_client import create_oob_for_scan, poll_oob_events
from orchestrator.utils.oob_correlator import correlate_oob
from orchestrator.utils.cloud_integration import (
    load_config,
    run_cloud_replicator,
    load_targets_from_file,
    CloudReplicatorError,
)

from plugins.nuclei.adapter import NucleiAdapter
from plugins.ssrfmap.adapter import SSRFmapAdapter

ROOT = Path(__file__).parent.parent   # ssrf_project/
INPUT = ROOT / "input"
OUTPUT = ROOT / "output"

# FIX: default_payloads.txt was deleted — now pointing to ssrf_payloads.csv
PAYLOADS_SSRF_CSV = ROOT / "payloads" / "ssrf" / "ssrf_payloads.csv"
PAYLOADS_SSRF_TXT = ROOT / "payloads" / "ssrf" / "default_payloads.txt"
INJECTED_PAYLOADS = ROOT / "payloads" / "ssrf" / "injected_payloads.txt"

SSRF_FUZZER_DIR = ROOT / "scanners" / "ssrf_fuzzer"
OUT_REPORT = OUTPUT / "report.json"

OUTPUT.mkdir(parents=True, exist_ok=True)


def load_targets() -> List[Dict[str, Any]]:
    cfg = {}
    try:
        cfg = load_config()
    except Exception as e:
        print("[orchestrator] config.yaml not loaded or invalid:", e)

    use_cr = cfg.get("use_cloud_replicator", False)

    if use_cr:
        print("[orchestrator] Cloud replicator enabled; running to generate targets...")
        try:
            targets_path = run_cloud_replicator(cfg)
            print("[orchestrator] Cloud replicator produced targets at:", targets_path)
            return load_targets_from_file(targets_path)
        except CloudReplicatorError as e:
            print("[orchestrator] Cloud replicator error:", e)
            print("[orchestrator] Falling back to input/example_targets.json")

    default_path = INPUT / "example_targets.json"
    if default_path.exists():
        return json.loads(default_path.read_text(encoding="utf-8"))

    print("[orchestrator] No targets found.")
    return []


def _load_payload_lines() -> List[str]:
    """
    Load payloads from txt file if present, else fall back to CSV column 'payload'.
    """
    # Prefer plain txt
    if PAYLOADS_SSRF_TXT.exists():
        return [
            l.strip()
            for l in PAYLOADS_SSRF_TXT.read_text(encoding="utf-8").splitlines()
            if l.strip() and not l.startswith("#")
        ]

    # Fall back to CSV — extract 'payload' column
    if PAYLOADS_SSRF_CSV.exists():
        import csv
        lines = []
        with open(PAYLOADS_SSRF_CSV, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                p = (row.get("payload") or row.get("request_path") or "").strip()
                if p:
                    lines.append(p)
        return lines

    # Hardcoded minimal fallback
    return [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1/",
        "http://{OOB}",
    ]


def inject_payloads(oob_domain: str) -> Path:
    lines = _load_payload_lines()
    if not lines:
        lines = [f"http://{oob_domain}"]
    injected = [ln.replace("{OOB}", oob_domain) for ln in lines]
    INJECTED_PAYLOADS.parent.mkdir(parents=True, exist_ok=True)
    INJECTED_PAYLOADS.write_text("\n".join(injected), encoding="utf-8")
    return INJECTED_PAYLOADS


def run_fuzzer_job(target: Dict[str, Any], oob_domain: str) -> Dict[str, Any]:
    job = {"target": target, "id": str(uuid.uuid4()), "oob_domain": oob_domain}

    if shutil.which("docker"):
        cmd = [
            "docker", "run", "--rm", "-i",
            "-v", f"{str(SSRF_FUZZER_DIR.resolve())}:/ssrf_fuzzer:ro",
            "-v", f"{str(OUTPUT.resolve())}:/out",
            "-e", f"OOB_BASE_DOMAIN={oob_domain}",
            "ssrf-fuzzer:local"
        ]
        try:
            proc = subprocess.run(
                cmd,
                input=json.dumps(job).encode("utf-8"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=300,
            )
            if proc.returncode != 0:
                print("[orchestrator] fuzzer docker failed:",
                      proc.stderr.decode("utf-8", errors="ignore")[:400])
                return {}
            return json.loads(proc.stdout.decode("utf-8", errors="ignore") or "{}")
        except Exception as e:
            print("[orchestrator] docker run error for fuzzer:", e)
            return {}

    script = SSRF_FUZZER_DIR / "run.py"
    if not script.exists():
        print("[orchestrator] fuzzer script not found at", script)
        return {}
    try:
        proc = subprocess.run(
            ["python3", str(script)],
            input=json.dumps(job).encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=300,
            cwd=str(ROOT),   # FIX: set cwd so relative imports work
        )
        if proc.returncode != 0:
            print("[orchestrator] local fuzzer failed:",
                  proc.stderr.decode("utf-8", errors="ignore")[:400])
            return {}
        return json.loads(proc.stdout.decode("utf-8", errors="ignore") or "{}")
    except Exception as e:
        print("[orchestrator] local fuzzer run error:", e)
        return {}


def create_targets_list_for_tool(targets: List[Dict[str, Any]]) -> list:
    return [t["url"] for t in targets if t.get("url")]


def main():
    targets = load_targets()
    if not targets:
        print("[orchestrator] No targets to scan. Exiting.")
        return

    # OOB setup — graceful fallback if interactsh is unreachable
    oob_domain = f"oob-{int(time.time())}.localtest.me"
    token_id = str(uuid.uuid4())
    try:
        reg = create_oob_for_scan(prefix=f"scan-{int(time.time())}", ttl=3600)
        oob_domain = reg["domain"]
        token_id = reg["id"]
        print("[orchestrator] OOB domain:", oob_domain, "token id:", token_id)
    except Exception as e:
        print("[orchestrator] WARNING: OOB registration failed:", e)
        print("[orchestrator] Continuing with local fallback OOB domain:", oob_domain)

    injected_path = inject_payloads(oob_domain)
    print("[orchestrator] Injected payloads written to:", injected_path)

    fuzzer_results = []
    start_ts = int(time.time())
    for t in targets:
        print("[orchestrator] Running fuzzer for target:", t.get("id"))
        res = run_fuzzer_job(t, oob_domain)
        if res:
            fuzzer_results.append(res)

    nuclei_adapter = NucleiAdapter(ROOT)
    try:
        nuclei_targets = create_targets_list_for_tool(targets)
        nuclei_raw_path = nuclei_adapter.run(nuclei_targets, options={"extra_flags": []})
        nuclei_findings = nuclei_adapter.parse(nuclei_raw_path)
    except Exception as e:
        print("[orchestrator] nuclei adapter error:", e)
        nuclei_findings = []

    ssrfmap_adapter = SSRFmapAdapter(ROOT)
    try:
        ssrfmap_input = injected_path if injected_path.exists() else create_targets_list_for_tool(targets)
        ssrfmap_raw_path = ssrfmap_adapter.run(ssrfmap_input, options={})
        ssrfmap_findings = ssrfmap_adapter.parse(ssrfmap_raw_path)
    except Exception as e:
        print("[orchestrator] ssrfmap adapter error:", e)
        ssrfmap_findings = []

    all_oob_events = []
    for i in range(6):
        try:
            evs = poll_oob_events(token_id, since=start_ts)
        except Exception as e:
            print("[orchestrator] OOB poll error:", e)
            evs = []
        if evs:
            all_oob_events.extend(evs)
            break
        time.sleep(2)

    combined = fuzzer_results + nuclei_findings + ssrfmap_findings
    enriched, _ = correlate_oob(combined, {token_id: oob_domain}, since_ts=start_ts)

    report = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "oob": {"domain": oob_domain, "token_id": token_id},
        "targets_count": len(targets),
        "fuzzer_results": fuzzer_results,
        "nuclei_findings": nuclei_findings,
        "ssrfmap_findings": ssrfmap_findings,
        "oob_events": all_oob_events,
        "enriched_findings": enriched,
    }
    OUT_REPORT.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print("[orchestrator] Report written to", OUT_REPORT)


if __name__ == "__main__":
    main()