from pathlib import Path
import json, os, shutil, subprocess
import requests as req_lib
from ..plugin_base import ScannerPlugin

SSRFMAP_SERVICE_URL = os.environ.get("SSRFMAP_SERVICE_URL", "http://ssrfmap_service:8081")

class SSRFmapAdapter(ScannerPlugin):

    def __init__(self, workdir: Path, docker_name: str = "ssrfmap"):
        super().__init__(workdir)
        self.workdir = Path(self.workdir)
        self.outpath = self.workdir / "ssrfmap_out.txt"

    def _call_http_service(self, targets_list):
        try:
            resp = req_lib.post(
                f"{SSRFMAP_SERVICE_URL}/scan",
                json={"targets": targets_list},
                timeout=180
            )
            if resp.status_code == 200:
                return resp.json()
        except Exception as e:
            print(f"[SSRFmapAdapter] HTTP service call failed: {e}")
        return None

    def run(self, requests_input, options: dict = None) -> Path:
        options = options or {}
        if isinstance(requests_input, Path) and requests_input.exists():
            targets_list = [l.strip() for l in requests_input.read_text().splitlines() if l.strip()]
        elif isinstance(requests_input, list):
            targets_list = [str(t) for t in requests_input if t]
        else:
            targets_list = [str(requests_input)]

        self.workdir.mkdir(parents=True, exist_ok=True)
        if self.outpath.exists():
            self.outpath.unlink()

        result = self._call_http_service(targets_list)
        if result is not None:
            raw = result.get("raw_output", "")
            self.outpath.write_text(raw, encoding="utf-8")
            return self.outpath

        native = shutil.which("ssrfmap") or shutil.which("ssrfmap.py")
        if native:
            req_path = self.workdir / "ssrfmap_requests.txt"
            req_path.write_text("\n".join(targets_list))
            try:
                with open(self.outpath, "wb") as f:
                    subprocess.run([native, "-r", str(req_path)], stdout=f, timeout=120)
            except Exception as e:
                raise RuntimeError(f"SSRFmap failed: {e}")
            return self.outpath

        raise RuntimeError("SSRFmap service unreachable and no native binary found.")

    def parse(self, raw_output_path: Path = None):
        p = Path(raw_output_path) if raw_output_path else self.outpath
        if not p.exists():
            return []
        findings = []
        for line in p.read_text(errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            low = line.lower()
            if any(k in low for k in ("ssrf", "169.254", "metadata", "found", "vulnerable")):
                sev = "high" if ("169.254" in low or "metadata" in low) else "medium"
                findings.append({"tool": "ssrfmap", "line": line, "evidence": {"raw": line}, "severity": sev})
        return findings
