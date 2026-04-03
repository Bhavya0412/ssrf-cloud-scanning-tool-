# orchestrator/utils/cloud_integration.py

import json
import shlex
import subprocess
from pathlib import Path
from typing import List, Dict, Any

ROOT = Path(__file__).parent.parent  # orchestrator/


class CloudReplicatorError(Exception):
    pass


def _load_yaml_config(path: Path) -> Dict[str, Any]:
    """
    Load a YAML config file (config.yaml) if PyYAML is installed.
    """
    try:
        import yaml  # type: ignore
    except ImportError as e:
        raise CloudReplicatorError(
            "PyYAML is required to read orchestrator/config.yaml. "
            "Install it with: pip install pyyaml"
        ) from e

    if not path.exists():
        return {}
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise CloudReplicatorError(f"Config file {path} must contain a YAML mapping at top level.")
    return data


def load_config() -> Dict[str, Any]:
    """
    Load orchestrator/config.yaml and return it as a dict.
    """
    config_path = ROOT / "config.yaml"
    if not config_path.exists():
        return {}
    return _load_yaml_config(config_path)


def run_cloud_replicator(cfg: Dict[str, Any]) -> Path:
    """
    Run the universal cloud replicator according to config and return the path
    to the generated targets file.

    Expected structure under cfg["cloud_replicator"]:
      mode: "cli"
      command: "python -m cloud_replicator.main"
      config_path: "input/company_profile.json"
      output_targets_path: "input/targets_from_replicator.json"
      timeout_seconds: 900
    """
    cr = cfg.get("cloud_replicator", {}) or {}
    mode = cr.get("mode", "cli")
    if mode != "cli":
        raise CloudReplicatorError(f"Unsupported cloud_replicator mode: {mode}")

    command = cr.get("command")
    if not command:
        raise CloudReplicatorError("cloud_replicator.command not set in config.yaml")

    # Paths relative to project root (ssrf_project/)
    root = ROOT.parent
    config_path = root / cr.get("config_path", "input/company_profile.json")
    output_path = root / cr.get("output_targets_path", "input/targets_from_replicator.json")
    timeout = int(cr.get("timeout_seconds", 900))

    if not config_path.exists():
        raise CloudReplicatorError(
            f"Cloud replicator config file not found: {config_path}. "
            "Create this based on your company/cloud environment schema."
        )

    # Build CLI command: we assume your replicator accepts:
    #   --config <path> --output <path>
    cmd_parts = shlex.split(command)
    cmd_parts += ["--config", str(config_path), "--output", str(output_path)]

    try:
        proc = subprocess.run(
            cmd_parts,
            cwd=str(root),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise CloudReplicatorError("Cloud replicator timed out.")

    if proc.returncode != 0:
        raise CloudReplicatorError(
            f"Cloud replicator failed with code {proc.returncode}.\n"
            f"STDERR: {proc.stderr.decode('utf-8', errors='ignore')[:1000]}"
        )

    if not output_path.exists():
        raise CloudReplicatorError(
            f"Cloud replicator did not produce expected targets file at {output_path}"
        )

    return output_path


def load_targets_from_file(path: Path) -> List[Dict[str, Any]]:
    """
    Load targets (JSON list) from the given path.
    This must match the schema used in input/example_targets.json.
    """
    if not path.exists():
        raise CloudReplicatorError(f"Targets file not found: {path}")
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, list):
        raise CloudReplicatorError(f"Targets file must be JSON list, got {type(data)}")
    return data
