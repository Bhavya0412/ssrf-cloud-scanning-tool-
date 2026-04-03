# SSRF Project (SSRF-only skeleton)

This project contains a starter SSRF scanner orchestrator with Out-Of-Band (OOB) Interactsh integration.

Structure:
- orchestrator/        - orchestration logic and correlator
- scanners/ssrf_fuzzer - fuzzer that injects payloads and produces findings
- tools/               - interactsh OOB client
- plugins/             - scanner plugin adapters (nuclei, ssrfmap)
- payloads/            - payload lists and templates
- input/               - example target files
- output/              - scan outputs and report

Quick start (dev):
1. Edit `input/example_targets.json` with your targets.
2. Option A (local Python fuzzer):
   - Run: `python3 orchestrator/orchestrator.py`
3. Option B (Docker; build fuzzer image):
   - Build: `cd scanners/ssrf_fuzzer && docker build -t ssrf-fuzzer:local .`
   - Run: `python3 orchestrator/orchestrator.py` (it will prefer docker)

Environment variables:
- INTERACTSH_SERVER (optional) — Interactsh base URL (default: https://interactsh.com)
- INTERACTSH_TOKEN (optional) — API token for Interactsh
- SSRF_SAFE_MODE (default "1") — if "1" disables dangerous payloads like file:// and gopher://

Notes:
- Always test only on targets you are authorized to scan.
- Use a self-hosted Interactsh for company use to avoid leaking data to public services.
