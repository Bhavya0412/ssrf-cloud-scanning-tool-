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
PAYLOADS_SSRF = ROOT / "payloads" / "ssrf" / "default_payloads.txt"
INJECTED_PAYLOADS = ROOT / "payloads" / "ssrf" / "injected_payloads.txt"
SSRF_FUZZER_DIR = ROOT / "scanners" / "ssrf_fuzzer"
OUT_REPORT = OUTPUT / "report.json"

OUTPUT.mkdir(parents=True, exist_ok=True)


def load_targets() -> List[Dict[str, Any]]:
    """
    Load targets from either:
      - cloud replicator output (if enabled in config), or
      - input/example_targets.json as fallback.
    """
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

    print("[orchestrator] No targets found (neither cloud replicator output nor example_targets.json).")
    return []


def inject_payloads(oob_domain: str) -> Path:
    """
    Replace {OOB} placeholder in payloads/ssrf/default_payloads.txt
    and write to injected_payloads.txt.
    """
    if not PAYLOADS_SSRF.exists():
        INJECTED_PAYLOADS.write_text(f"http://{oob_domain}\n", encoding="utf-8")
        return INJECTED_PAYLOADS

    lines = [
        l.strip()
        for l in PAYLOADS_SSRF.read_text(encoding="utf-8").splitlines()
        if l.strip()
    ]
    injected = [ln.replace("{OOB}", oob_domain) for ln in lines]
    INJECTED_PAYLOADS.write_text("\n".join(injected), encoding="utf-8")
    return INJECTED_PAYLOADS


def run_fuzzer_job(target: Dict[str, Any], oob_domain: str) -> Dict[str, Any]:
    """
    Run ssrf_fuzzer for a single target:
     - Prefer docker image 'ssrf-fuzzer:local'
     - Fallback: local python run.py
    """
    job = {"target": target, "id": str(uuid.uuid4()), "oob_domain": oob_domain}

    # Prefer docker first
    if shutil.which("docker"):
        cmd = [
            "docker", "run", "--rm", "-i",
            "-v", f"{str(SSRF_FUZZER_DIR.resolve())}:/ssrf_fuzzer:ro",
            "-v", f"{str(OUTPUT.resolve())}:/out",
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

    # Fallback: local Python fuzzer
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
    """
    Convert full target objects into a simple list of URLs for tools like nuclei.
    """
    urls = []
    for t in targets:
        u = t.get("url")
        if u:
            urls.append(u)
    return urls


def main():
    # 1. Load targets (from cloud replicator or fallback)
    targets = load_targets()
    if not targets:
        print("[orchestrator] No targets to scan. Exiting.")
        return

    # 2. Create OOB token for scan
    reg = create_oob_for_scan(prefix=f"scan-{int(time.time())}", ttl=3600)
    oob_domain = reg["domain"]
    token_id = reg["id"]
    print("[orchestrator] OOB domain:", oob_domain, "token id:", token_id)

    # 3. Inject payloads with {OOB} placeholder
    injected_path = inject_payloads(oob_domain)
    print("[orchestrator] Injected payloads written to:", injected_path)

    # 4. Run SSRF fuzzer per target
    fuzzer_results = []
    start_ts = int(time.time())
    for t in targets:
        print("[orchestrator] Running fuzzer for target:", t.get("id"))
        res = run_fuzzer_job(t, oob_domain)
        if res:
            fuzzer_results.append(res)

    # 5. Run Nuclei adapter (Docker preferred)
    nuclei_adapter = NucleiAdapter(ROOT)
    try:
        nuclei_targets = create_targets_list_for_tool(targets)
        nuclei_raw_path = nuclei_adapter.run(nuclei_targets, options={"extra_flags": []})
        nuclei_findings = nuclei_adapter.parse(nuclei_raw_path)
    except Exception as e:
        print("[orchestrator] nuclei adapter error:", e)
        nuclei_findings = []

    # 6. Run SSRFmap adapter (Docker preferred)
    ssrfmap_adapter = SSRFmapAdapter(ROOT)
    try:
        ssrfmap_input = injected_path if injected_path.exists() else create_targets_list_for_tool(targets)
        ssrfmap_raw_path = ssrfmap_adapter.run(ssrfmap_input, options={})
        ssrfmap_findings = ssrfmap_adapter.parse(ssrfmap_raw_path)
    except Exception as e:
        print("[orchestrator] ssrfmap adapter error:", e)
        ssrfmap_findings = []

    # 7. Poll OOB events
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

    # 8. Correlate OOB across all findings
    combined = []
    combined.extend(fuzzer_results)
    combined.extend(nuclei_findings)
    combined.extend(ssrfmap_findings)

    enriched, _ = correlate_oob(combined, {token_id: oob_domain}, since_ts=start_ts)

    # 9. Build final report
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
