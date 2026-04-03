#!/usr/bin/env python3
"""
interactsh_client.py

Simple, robust Interactsh-compatible client for OOB (Out-Of-Band) testing.

Features:
 - register(prefix, ttl): create a unique OOB domain / token on the Interactsh server
 - poll(token_id, since=None, wait=0): poll for callbacks related to a token (or all if token_id None)
 - delete(token_id): optionally delete / retire a registration
 - helper wrappers: create_oob_for_scan, poll_oob_events

Configuration (via ENV):
 - INTERACTSH_SERVER : base URL of the server (default: https://interactsh.com)
 - INTERACTSH_TOKEN  : optional bearer token / API key if server requires auth
 - INTERACTSH_VERIFY : "0" to disable TLS verify (not recommended), otherwise TLS verify on
 - INTERACTSH_TIMEOUT: default HTTP timeout seconds (default 15)

Notes:
 - Self-hosted Interactsh forks may have slightly different response shapes.
   The client normalizes common shapes but you should adapt if your server differs.
 - Polling behavior: you can poll repeatedly in your orchestrator (recommended) with a short delay.
"""

from __future__ import annotations
import os
import time
import typing as t
import json
import base64
import requests
from requests.adapters import HTTPAdapter, Retry

# --- Configuration from environment ---
INTERACTSH_SERVER = os.environ.get("INTERACTSH_SERVER", "https://interactsh.com").rstrip("/")
INTERACTSH_TOKEN = os.environ.get("INTERACTSH_TOKEN")  # optional
INTERACTSH_VERIFY = False if os.environ.get("INTERACTSH_VERIFY") in ("0", "false", "False") else True
INTERACTSH_TIMEOUT = int(os.environ.get("INTERACTSH_TIMEOUT", "15"))

# --- Endpoints (some servers use slightly different endpoints) ---
# Default assumption: server exposes /register, /poll, /delete (JSON)
# If your server uses other endpoints, create InteractshClient(server="https://...") and override attrs.
DEFAULT_REGISTER_PATH = "/register"
DEFAULT_POLL_PATH = "/poll"
DEFAULT_DELETE_PATH = "/delete"

# --- Types ---
RegisterResult = t.TypedDict("RegisterResult", {"domain": str, "id": str, "secret": t.Optional[str], "raw": dict, "expiry": int})
OobEvent = t.TypedDict("OobEvent", {"id": str, "type": str, "domain": str, "timestamp": int, "raw": dict})

# --- Helpers ---

def _build_session() -> requests.Session:
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=0.3, status_forcelist=(500,502,503,504), allowed_methods=("GET","POST"))
    session.mount("https://", HTTPAdapter(max_retries=retries))
    session.mount("http://", HTTPAdapter(max_retries=retries))
    return session

# --- Client ---

class InteractshError(Exception):
    pass

class InteractshClient:
    """
    Interactsh client.

    Example:
        client = InteractshClient(server="https://oob.example", token="MYTOKEN")
        reg = client.register(prefix="scan-123", ttl=1800)
        # reg -> {'domain': 'abcde.oob.example', 'id': 'abcd1234', 'secret': '...', 'expiry': 1234567890}
        # inject reg['domain'] into payloads for scanners
        events = client.poll(reg['id'], since=int(time.time())-30)
    """

    def __init__(self, server: t.Optional[str] = None, token: t.Optional[str] = None,
                 verify: bool = None, timeout: int = None,
                 register_path: str = DEFAULT_REGISTER_PATH,
                 poll_path: str = DEFAULT_POLL_PATH,
                 delete_path: str = DEFAULT_DELETE_PATH):
        self.server = (server or INTERACTSH_SERVER).rstrip("/")
        self.token = token or INTERACTSH_TOKEN
        self.verify = verify if verify is not None else INTERACTSH_VERIFY
        self.timeout = timeout or INTERACTSH_TIMEOUT
        self.register_url = self.server + register_path
        self.poll_url = self.server + poll_path
        self.delete_url = self.server + delete_path
        self._session = _build_session()

    def _headers(self) -> dict:
        h = {"User-Agent": "ssrf-orchestrator/1.0"}
        if self.token:
            # Accept common token header forms
            h["Authorization"] = f"Bearer {self.token}"
        return h

    def register(self, prefix: t.Optional[str] = None, ttl: int = 3600) -> RegisterResult:
        """
        Register a new OOB session.

        Returns:
            {
              "domain": "<token>.<oob-domain>",
              "id": "<registration id>",
              "secret": "<optional secret>",
              "raw": <raw-json-response>,
              "expiry": <unix-epoch>
            }
        """
        payload = {"ttl": int(ttl)}
        if prefix:
            payload["prefix"] = prefix
        try:
            r = self._session.post(self.register_url, json=payload, headers=self._headers(), timeout=self.timeout, verify=self.verify)
        except requests.RequestException as e:
            raise InteractshError(f"register request failed: {e}") from e

        if r.status_code not in (200, 201):
            raise InteractshError(f"register failed: status={r.status_code} body={r.text}")

        try:
            data = r.json()
        except ValueError:
            # If server returns non-json, include raw text
            raise InteractshError(f"register returned non-JSON: {r.text}")

        # Normalize common response fields (self-host variants differ)
        domain = data.get("domain") or data.get("oob_domain") or data.get("interact_domain") or data.get("domain_name")
        ident = data.get("id") or data.get("secret_id") or data.get("token_id") or data.get("unique_id")
        secret = data.get("secret") or data.get("token") or data.get("client_secret")
        expiry = int(time.time()) + int(ttl)

        if not domain:
            # Some servers return base64-encoded registration info; try decoding 'data' or 'raw'
            # Fallback: try to find in response fields
            # For now, raise helpful error
            raise InteractshError(f"register: server response did not include a domain. Raw: {data}")

        return {"domain": domain, "id": ident or domain, "secret": secret, "raw": data, "expiry": expiry}

    def poll(self, token_id: t.Optional[str] = None, since: t.Optional[int] = None) -> t.List[OobEvent]:
        """
        Poll for OOB events. Use token_id to restrict to a single registration if supported.

        Returns a list of normalized events:
          { id, type ('dns'|'http'|'tcp'...), domain, timestamp, raw }
        """
        payload: dict[str, t.Any] = {}
        if token_id:
            payload["id"] = token_id
        if since:
            payload["since"] = int(since)

        try:
            r = self._session.post(self.poll_url, json=payload, headers=self._headers(), timeout=self.timeout, verify=self.verify)
        except requests.RequestException as e:
            raise InteractshError(f"poll request failed: {e}") from e

        if r.status_code != 200:
            raise InteractshError(f"poll failed: status={r.status_code} body={r.text}")

        try:
            data = r.json()
        except ValueError:
            raise InteractshError(f"poll returned non-JSON: {r.text}")

        # Server may return {"data": [...]} or a plain list. Normalize.
        events_raw = data.get("data") if isinstance(data, dict) and "data" in data else data

        normalized: t.List[OobEvent] = []
        if not events_raw:
            return normalized

        for ev in events_raw:
            # ev may be dict with multiple shapes. Normalize common fields.
            # Try common keys:
            ts = ev.get("timestamp") or ev.get("ts") or ev.get("time") or ev.get("time", None)
            proto = ev.get("protocol") or ev.get("proto") or ev.get("type") or ev.get("request", {}).get("protocol") if isinstance(ev, dict) else None
            host = ev.get("host") or ev.get("domain") or ev.get("r") or ev.get("qname") or ev.get("request", {}).get("host")
            eid = ev.get("id") or ev.get("uuid") or ev.get("event_id") or host or str(ts)

            # make timestamp int if possible
            try:
                ts_i = int(ts) if ts is not None else int(time.time())
            except Exception:
                ts_i = int(time.time())

            normalized.append({
                "id": str(eid),
                "type": str(proto) if proto else "unknown",
                "domain": str(host) if host else "",
                "timestamp": ts_i,
                "raw": ev
            })

        return normalized

    def delete(self, token_id: str) -> dict:
        """
        Delete / retire a registration. Not all servers support delete; handle errors.
        Returns raw server response (parsed JSON) on success.
        """
        payload = {"id": token_id}
        try:
            r = self._session.post(self.delete_url, json=payload, headers=self._headers(), timeout=self.timeout, verify=self.verify)
        except requests.RequestException as e:
            raise InteractshError(f"delete request failed: {e}") from e

        if r.status_code not in (200, 202, 204):
            raise InteractshError(f"delete failed: status={r.status_code} body={r.text}")
        if r.status_code == 204 or not r.text:
            return {}
        try:
            return r.json()
        except ValueError:
            return {"raw": r.text}

# --- Convenience helper functions for orchestrator usage ---

def create_oob_for_scan(prefix: t.Optional[str] = None, ttl: int = 3600,
                        server: t.Optional[str] = None, token: t.Optional[str] = None) -> RegisterResult:
    """
    Create and return a registration dict for a scan.
    """
    client = InteractshClient(server=server, token=token)
    return client.register(prefix=prefix, ttl=ttl)

def poll_oob_events(token_id: t.Optional[str] = None, since: t.Optional[int] = None,
                    server: t.Optional[str] = None, token: t.Optional[str] = None) -> t.List[OobEvent]:
    client = InteractshClient(server=server, token=token)
    return client.poll(token_id, since)

def delete_oob_registration(token_id: str, server: t.Optional[str] = None, token: t.Optional[str] = None) -> dict:
    client = InteractshClient(server=server, token=token)
    return client.delete(token_id)

# --- Example usage (for dev / tests) ---
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Interactsh client quick test")
    parser.add_argument("--register", "-r", action="store_true", help="Register and print returned domain")
    parser.add_argument("--poll", "-p", metavar="TOKEN_ID", help="Poll events for token id (or 'all' for global)")
    parser.add_argument("--server", "-s", help="Override server URL")
    parser.add_argument("--ttl", type=int, default=600, help="TTL seconds for register")
    args = parser.parse_args()

    cli = InteractshClient(server=args.server) if args.server else InteractshClient()
    if args.register:
        info = cli.register(prefix=f"test-{int(time.time())}", ttl=args.ttl)
        print("REGISTERED:", json.dumps(info, indent=2))
        print("Inject this domain into payloads:", info["domain"])
        print("Token id:", info["id"])
    if args.poll:
        tid = None if args.poll.lower() in ("all","none") else args.poll
        events = cli.poll(tid, since=int(time.time())-3600)
        print("EVENTS:", json.dumps(events, indent=2))
