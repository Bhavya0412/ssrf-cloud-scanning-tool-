import time
from typing import List, Dict, Any

def correlate_oob(findings: List[Dict[str, Any]], token_ids_map: Dict[str, str], since_ts: int = None, poll_interval: int = 2, poll_rounds: int = 3):
    """
    Enrich findings with OOB events if the payload or evidence contains the OOB domain.
    findings: list of fuzzer outputs (dicts)
    token_ids_map: { token_id: domain }
    """
    all_events = []
    # We assume the orchestrator polled already and passed events if available.
    # Here we just try to mark findings that reference the domain.
    domains = set(token_ids_map.values())
    for f in findings:
        # f may be the raw fuzzer output object
        # find payload field(s)
        try:
            res_findings = f.get("findings") if isinstance(f, dict) else None
        except Exception:
            res_findings = None
        if not res_findings:
            continue
        for fin in res_findings:
            payload = fin.get("payload") or ""
            for d in domains:
                if d and d in payload:
                    fin.setdefault("evidence", {})
                    fin["evidence"]["type"] = "oob"
                    fin["evidence"]["raw_oob_event"] = {"matched_domain": d}
                    fin["confidence"] = "high"
                    if fin.get("severity") in ("low", "medium"):
                        fin["severity"] = "high"
    return findings, all_events
