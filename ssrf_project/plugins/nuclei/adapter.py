from pathlib import Path
import json, os, shutil, subprocess
import requests as req_lib
from ..plugin_base import ScannerPlugin

NUCLEI_SERVICE_URL = os.environ.get("NUCLEI_SERVICE_URL", "http://nuclei_service:8080")

class NucleiAdapter(ScannerPlugin):

    def __init__(self, workdir: Path, docker_name: str = "nuclei"):
        super().__init__(workdir)
        self.workdir = Path(self.workdir)
        self.templates_dir = (self.workdir / "payloads" / "nuclei").resolve()
        self.output_file = (self.workdir / "nuclei_out.jsonl").resolve()

    def _call_http_service(self, targets_list):
        try:
            resp = req_lib.post(f"{NUCLEI_SERVICE_URL}/scan", json={"targets": targets_list}, timeout=360)
            if resp.status_code == 200:
                return resp.json().get("findings", [])
        except Exception as e:
            print(f"[NucleiAdapter] HTTP service call failed: {e}")
        return None

    def run(self, targets, options: dict = None) -> Path:
        options = options or {}
        if isinstance(targets, Path) and targets.exists():
            targets_list = [l.strip() for l in targets.read_text().splitlines() if l.strip()]
        elif isinstance(targets, list):
            targets_list = [str(t) for t in targets if t]
        else:
            targets_list = [str(targets)]

        self.workdir.mkdir(parents=True, exist_ok=True)
        if self.output_file.exists():
            self.output_file.unlink()

        findings = self._call_http_service(targets_list)
        if findings is not None:
            with open(self.output_file, "w", encoding="utf-8") as f:
                for finding in findings:
                    f.write(json.dumps(finding) + "\n")
            return self.output_file

        native_bin = shutil.which("nuclei")
        if native_bin:
            targets_path = self.workdir / "nuclei_targets.txt"
            with open(targets_path, "w") as f:
                f.write("\n".join(targets_list))
            cmd = [native_bin, "-l", str(targets_path), "-jsonl", "-o", str(self.output_file), "-silent", "-tags", "ssrf"]
            try:
                subprocess.run(cmd, check=True, timeout=300)
            except Exception as e:
                raise RuntimeError(f"Nuclei failed: {e}")
            return self.output_file

        raise RuntimeError("Nuclei service unreachable and no native binary found.")

    def parse(self, raw_output_path: Path = None):
        path = Path(raw_output_path) if raw_output_path else self.output_file
        if not path.exists():
            return []
        findings = []
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line: continue
                try:
                    j = json.loads(line)
                except Exception:
                    continue
                info = j.get("info", {}) or {}
                matched = j.get("matched-at") or j.get("host") or j.get("matched")
                severity = (info.get("severity") or "medium").lower()
                findings.append({"tool": "nuclei", "matched": matched, "severity": severity, "info": info, "raw": j})
        return findings
