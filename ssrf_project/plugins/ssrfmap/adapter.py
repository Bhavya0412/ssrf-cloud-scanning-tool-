# plugins/ssrfmap/adapter.py
from pathlib import Path
import subprocess
import shutil
from ..plugin_base import ScannerPlugin

class SSRFmapAdapter(ScannerPlugin):
    """
    Adapter for ssrfmap.
    Strategy:
      - If Docker available: run ssrfmap container with mounted requests file and capture stdout.
      - If native ssrfmap CLI available: run it directly.
      - Parse output heuristically (since different forks have different formats).
    """

    DOCKER_IMAGE = "ghcr.io/ganbarodigital/ssrfmap:latest"
    CONTAINER_INPUT = "/input"
    CONTAINER_OUTPUT = "/output"

    def __init__(self, workdir: Path, docker_name: str = "ssrfmap"):
        super().__init__(workdir)
        self.workdir = Path(self.workdir)
        self.outpath = self.workdir / "ssrfmap_out.txt"

    def _docker_available(self) -> bool:
        return shutil.which("docker") is not None

    def _write_requests_file(self, requests_list):
        """
        requests_list can be:
          - Path to file
          - list of raw HTTP requests (strings)
          - list of URLs
        We'll write them to workdir/ssrfmap_requests.txt
        """
        req_path = self.workdir / "ssrfmap_requests.txt"
        if isinstance(requests_list, Path) and requests_list.exists():
            shutil.copy(str(requests_list), str(req_path))
            return req_path

        with open(req_path, "w", encoding="utf-8") as fh:
            for r in requests_list:
                fh.write(f"{r}\n")
        return req_path

    def run(self, requests_input, options: dict = None) -> Path:
        """
        Run ssrfmap against requests_input.
        Returns: Path to raw output file.
        """
        options = options or {}
        req_file = self._write_requests_file(requests_input)
        self.workdir.mkdir(parents=True, exist_ok=True)
        if self.outpath.exists():
            self.outpath.unlink()

        timeout = int(options.get("timeout", 300))

        if self._docker_available():
            # Try common command patterns inside container.
            base_cmd = [
                "docker", "run", "--rm",
                "-v", f"{str(self.workdir)}:{self.CONTAINER_OUTPUT}",
                "-v", f"{str(req_file)}:{self.CONTAINER_INPUT}/requests.txt:ro",
                self.DOCKER_IMAGE,
            ]

            # Candidate commands to try inside container
            candidates = [
                base_cmd + ["ssrfmap", "-r", f"{self.CONTAINER_INPUT}/requests.txt"],
                base_cmd + ["python3", "ssrfmap.py", "-r", f"{self.CONTAINER_INPUT}/requests.txt"],
            ]

            last_err = None
            for cmd in candidates:
                try:
                    with open(self.outpath, "wb") as outfh:
                        subprocess.run(cmd, stdout=outfh, stderr=subprocess.PIPE, timeout=timeout, check=False)
                    if self.outpath.exists() and self.outpath.stat().st_size > 0:
                        return self.outpath
                except subprocess.TimeoutExpired:
                    last_err = "timeout"
                except Exception as e:
                    last_err = e
            raise RuntimeError(f"ssrfmap docker run attempts failed. Last error: {last_err}")

        # Fallback: native ssrfmap on PATH
        native_bin = shutil.which("ssrfmap") or shutil.which("ssrfmap.py")
        if native_bin:
            try:
                with open(self.outpath, "wb") as outfh:
                    subprocess.run(
                        [native_bin, "-r", str(req_file)],
                        stdout=outfh,
                        stderr=subprocess.PIPE,
                        timeout=timeout,
                        check=False,
                    )
                return self.outpath
            except subprocess.TimeoutExpired:
                raise RuntimeError("ssrfmap native run timed out")

        raise RuntimeError("Neither Docker nor native 'ssrfmap' found on PATH.")

    def parse(self, raw_output_path: Path = None):
        """
        Heuristic parser:
        - scans each line and looks for SSRF-related keywords
        Returns list of normalized findings:
          {
            "tool": "ssrfmap",
            "line": <original line>,
            "evidence": {"raw": <line>},
            "severity": "high"|"medium"
          }
        """
        p = Path(raw_output_path) if raw_output_path else self.outpath
        if not p.exists():
            return []

        text = p.read_text(errors="ignore")
        findings = []
        for ln in text.splitlines():
            line = ln.strip()
            if not line:
                continue
            low = line.lower()
            if any(k in low for k in ("ssrf", "interact", "169.254", "metadata", "computemetadata", "instance-id")):
                sev = "high" if ("169.254" in low or "metadata" in low) else "medium"
                findings.append({
                    "tool": "ssrfmap",
                    "line": line,
                    "evidence": {"raw": line},
                    "severity": sev,
                })
        return findings
