#!/usr/bin/env python3
"""Fetch subdomains from SecurityTrails API.

Usage: securitytrails_fetch.py <api_key> <domain>
Output: one subdomain per line to stdout

Handles:
  - AWS CGNAT IPs (100.x.x.x) filtered out before connect
  - Transient network errors → retries with delay
  - TLS handshake timeouts → tries each routable IP in turn
"""
import sys
import json
import socket
import ssl
import http.client
import time

HOSTNAME    = "api.securitytrails.com"
PORT        = 443
RETRIES     = 5    # retries on transient network failure (VMware NAT can be intermittent)
RETRY_DELAY = 8    # seconds between attempts — give NAT time to recover
IP_TIMEOUT  = 8    # per-IP connect+TLS timeout


def _routable_ips() -> list:
    """DNS lookup, filtering CGNAT (100.x.x.x) addresses."""
    try:
        results = socket.getaddrinfo(HOSTNAME, PORT, type=socket.SOCK_STREAM)
    except OSError:
        return []
    seen, out = set(), []
    for r in results:
        ip = r[4][0]
        if ip not in seen and not ip.startswith("100."):
            seen.add(ip)
            out.append(ip)
    return out


class _DirectHTTPS(http.client.HTTPSConnection):
    """Connect to a specific IP while keeping real hostname for SNI/cert."""

    def __init__(self, ip, hostname, port, timeout):
        super().__init__(hostname, port, timeout=timeout)
        self._ip = ip

    def connect(self):
        sock = socket.create_connection((self._ip, self.port), timeout=self.timeout)
        ctx  = ssl.create_default_context()
        self.sock = ctx.wrap_socket(sock, server_hostname=self.host)


def _try_curl(api_key: str, domain: str) -> list | None:
    """Fallback: use curl subprocess (has its own resolver, more resilient under NAT stress)."""
    import subprocess
    url = f"https://{HOSTNAME}/v1/domain/{domain}/subdomains?children_only=false&include_inactive=true"
    try:
        result = subprocess.run(
            ["curl", "-sS", "--max-time", str(IP_TIMEOUT * 2),
             "-H", f"apikey: {api_key}",
             "-H", "Accept: application/json",
             url],
            capture_output=True, text=True, timeout=IP_TIMEOUT * 3
        )
        if result.returncode != 0:
            sys.stderr.write(f"[securitytrails] curl failed: {result.stderr.strip()}\n")
            return None
        data = json.loads(result.stdout)
        return data.get("subdomains", [])
    except Exception as exc:
        sys.stderr.write(f"[securitytrails] curl fallback failed: {exc}\n")
        return None


def _try_once(api_key: str, domain: str) -> list | None:
    """One attempt: re-resolve DNS, try each IP. Returns list or None on full failure."""
    ips = _routable_ips()
    if not ips:
        sys.stderr.write(f"[securitytrails] DNS failed for {HOSTNAME} — trying curl fallback\n")
        return _try_curl(api_key, domain)

    path = f"/v1/domain/{domain}/subdomains?children_only=false&include_inactive=true"
    headers = {"apikey": api_key, "Accept": "application/json"}

    for ip in ips:
        try:
            conn = _DirectHTTPS(ip, HOSTNAME, PORT, timeout=IP_TIMEOUT)
            conn.request("GET", path, headers=headers)
            resp = conn.getresponse()
            data = json.loads(resp.read())
            conn.close()
            if resp.status == 200:
                return data.get("subdomains", [])
            # 401/403 → key issue, no point retrying
            if resp.status in (401, 403):
                sys.stderr.write(f"[securitytrails] HTTP {resp.status} — check API key\n")
                return []
            # 429 → rate limit
            if resp.status == 429:
                sys.stderr.write(f"[securitytrails] HTTP 429 — rate limited\n")
                return []
        except Exception as exc:
            sys.stderr.write(f"[securitytrails] {ip} failed: {exc}\n")
            continue

    # All direct IPs failed — try curl as last resort
    sys.stderr.write(f"[securitytrails] all direct IPs failed — trying curl fallback\n")
    return _try_curl(api_key, domain)


def main():
    if len(sys.argv) < 3:
        sys.stderr.write("Usage: securitytrails_fetch.py <api_key> <domain>\n")
        sys.exit(1)

    api_key = sys.argv[1]
    domain  = sys.argv[2]

    for attempt in range(1, RETRIES + 1):
        result = _try_once(api_key, domain)
        if result is not None:
            for sub in result:
                print(f"{sub}.{domain}")
            return
        if attempt < RETRIES:
            sys.stderr.write(f"[securitytrails] attempt {attempt}/{RETRIES} failed, retrying in {RETRY_DELAY}s…\n")
            time.sleep(RETRY_DELAY)

    sys.stderr.write(f"[securitytrails] all {RETRIES} attempts failed\n")
    sys.exit(0)


if __name__ == "__main__":
    main()
