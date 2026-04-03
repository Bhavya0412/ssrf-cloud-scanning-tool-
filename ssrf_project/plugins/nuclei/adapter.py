# plugins/nuclei/adapter.py
from pathlib import Path
import subprocess
import json
import shutil
from ..plugin_base import ScannerPlugin

class NucleiAdapter(ScannerPlugin):
    """
    Nuclei adapter - runs nuclei in Docker if available, otherwise tries native binary.

    - Expects: 'targets' as Path to file OR list of URLs
    - Uses templates from payloads/nuclei
    - Produces JSONL output at workdir / 'nuclei_out.jsonl'
    """

    DOCKER_IMAGE = "projectdiscovery/nuclei:latest"
    CONTAINER_TEMPLATE_PATH = "/templates"
    CONTAINER_INPUT_PATH = "/input"
    CONTAINER_OUTPUT_PATH = "/output"

    def __init__(self, workdir: Path, docker_name: str = "nuclei"):
        super().__init__(workdir)
        self.workdir = Path(self.workdir)
        self.templates_dir = (self.workdir / "payloads" / "nuclei").resolve()
        self.output_file = (self.workdir / "nuclei_out.jsonl").resolve()

    def _write_targets_file(self, targets):
        """
        Accepts either a Path to a pre-made targets file or a Python list of target URLs.
        Writes workdir/nuclei_targets.txt and returns that path.
        """
        targets_path = self.workdir / "nuclei_targets.txt"
        if isinstance(targets, Path) and targets.exists():
            shutil.copy(str(targets), str(targets_path))
            return targets_path

        # assume iterable of strings
        with open(targets_path, "w", encoding="utf-8") as fh:
            for t in targets:
                fh.write(f"{t}\n")
        return targets_path

    def _docker_available(self) -> bool:
        return shutil.which("docker") is not None

    def run(self, targets, options: dict = None) -> Path:
        """
        Run nuclei against the given targets.
        Returns path to raw output file (JSONL).
        """
        options = options or {}
        targets_path = self._write_targets_file(targets)
        self.workdir.mkdir(parents=True, exist_ok=True)
        outpath = self.output_file
        if outpath.exists():
            outpath.unlink()

        extra_flags = options.get("extra_flags", [])
        timeout = int(options.get("timeout", 300))

        # Prefer Docker run
        if self._docker_available():
            cmd = [
                "docker", "run", "--rm",
                "-v", f"{str(self.templates_dir)}:{self.CONTAINER_TEMPLATE_PATH}:ro",
                "-v", f"{str(targets_path)}:{self.CONTAINER_INPUT_PATH}/targets.txt:ro",
                "-v", f"{str(self.workdir)}:{self.CONTAINER_OUTPUT_PATH}",
                self.DOCKER_IMAGE,
                "-l", f"{self.CONTAINER_INPUT_PATH}/targets.txt",
                "-t", f"{self.CONTAINER_TEMPLATE_PATH}",
                "-jsonl",
                "-o", f"{self.CONTAINER_OUTPUT_PATH}/nuclei_out.jsonl",
            ]
            cmd += [str(f) for f in extra_flags]
            try:
                subprocess.run(cmd, check=True, timeout=timeout)
            except subprocess.CalledProcessError as e:
                raise RuntimeError(f"Nuclei docker run failed: {e}")
            except subprocess.TimeoutExpired:
                raise RuntimeError("Nuclei docker run timed out")
            return outpath

        # Fallback: native nuclei binary
        native_bin = shutil.which("nuclei")
        if native_bin:
            cmd = [
                native_bin,
                "-l", str(targets_path),
                "-t", str(self.templates_dir),
                "-jsonl",
                "-o", str(outpath),
            ]
            cmd += [str(f) for f in extra_flags]
            try:
                subprocess.run(cmd, check=True, timeout=timeout)
            except subprocess.CalledProcessError as e:
                raise RuntimeError(f"Nuclei native run failed: {e}")
            except subprocess.TimeoutExpired:
                raise RuntimeError("Nuclei native run timed out")
            return outpath

        raise RuntimeError("Neither Docker nor a native 'nuclei' binary was found on PATH.")

    def parse(self, raw_output_path: Path = None):
        """
        Parse Nuclei JSONL output into a list of normalized findings:
         {
           "tool": "nuclei",
           "matched": <matched-at or host>,
           "severity": <severity>,
           "info": <info dict>,
           "raw": <original json object>
         }
        """
        path = Path(raw_output_path) if raw_output_path else self.output_file
        if not path.exists():
            return []

        findings = []
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    j = json.loads(line)
                except Exception:
                    continue
                info = j.get("info", {}) or {}
                matched = (
                    j.get("matched-at")
                    or j.get("host")
                    or j.get("matched")
                    or j.get("request", {}).get("url")
                )
                severity = (info.get("severity") or "medium").lower()
                findings.append({
                    "tool": "nuclei",
                    "matched": matched,
                    "severity": severity,
                    "info": info,
                    "raw": j,
                })
        return findings
