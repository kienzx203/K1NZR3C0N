#!/usr/bin/env python3
"""Fetch subdomains from SecurityTrails API.

Usage: securitytrails_fetch.py <api_key> <domain>
Output: one subdomain per line to stdout
"""
import sys
import json
import urllib.request

def main():
    if len(sys.argv) < 3:
        sys.stderr.write("Usage: securitytrails_fetch.py <api_key> <domain>\n")
        sys.exit(1)

    api_key = sys.argv[1]
    domain  = sys.argv[2]
    url = (
        f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        f"?children_only=false&include_inactive=true"
    )

    req = urllib.request.Request(
        url,
        headers={"apikey": api_key, "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.load(resp)
            for sub in data.get("subdomains", []):
                print(f"{sub}.{domain}")
    except Exception as exc:
        sys.stderr.write(f"[securitytrails] {exc}\n")
        sys.exit(0)

if __name__ == "__main__":
    main()
