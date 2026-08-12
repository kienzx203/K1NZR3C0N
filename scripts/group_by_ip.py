#!/usr/bin/env python3
"""Group resolved hosts by IP from dnsx `-resp` output.

Input format (dnsx -a -aaaa -cname -resp): lines like
    sub.target.com [1.2.3.4]
    sub.target.com [cname.example.com,1.2.3.4]

Writes three files under --output-dir:
    unique_ips.txt     one IPv4 per line, sorted
    ip_to_hosts.json   {ip: [hosts...]}
    shared_hosting.txt IPs with >1 distinct host, tab-separated "ip\\thost1,host2,..."
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

_LINE_RE = re.compile(r'^([^\s\[]+)\s*\[([^\]]+)\]')
_IPV4_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')


def parse_resp_file(path: Path) -> dict[str, set[str]]:
    """Return {ip: {hosts pointing to it}}."""
    ip_to_hosts: dict[str, set[str]] = {}
    for raw in path.read_text(encoding='utf-8', errors='ignore').splitlines():
        m = _LINE_RE.match(raw.strip())
        if not m:
            continue
        host, bracket = m.group(1).strip().lower(), m.group(2)
        for part in bracket.split(','):
            ip = part.strip()
            if _IPV4_RE.match(ip):
                ip_to_hosts.setdefault(ip, set()).add(host)
    return ip_to_hosts


def write_outputs(ip_to_hosts: dict[str, set[str]], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    unique_ips = sorted(ip_to_hosts, key=lambda ip: tuple(int(x) for x in ip.split('.')))
    (output_dir / 'unique_ips.txt').write_text(
        '\n'.join(unique_ips) + ('\n' if unique_ips else ''), encoding='utf-8'
    )

    as_lists = {ip: sorted(hosts) for ip, hosts in ip_to_hosts.items()}
    (output_dir / 'ip_to_hosts.json').write_text(
        json.dumps(as_lists, indent=2, sort_keys=True), encoding='utf-8'
    )

    shared = sorted(
        ((ip, hosts) for ip, hosts in as_lists.items() if len(hosts) > 1),
        key=lambda item: (-len(item[1]), item[0]),
    )
    shared_lines = [f'{ip}\t{",".join(hosts)}' for ip, hosts in shared]
    (output_dir / 'shared_hosting.txt').write_text(
        '\n'.join(shared_lines) + ('\n' if shared_lines else ''), encoding='utf-8'
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='Group resolved hosts by IP from dnsx -resp output.')
    parser.add_argument('--input', required=True, help='dnsx -resp output file')
    parser.add_argument('--output-dir', required=True, help='Directory to write unique_ips.txt / ip_to_hosts.json / shared_hosting.txt')
    return parser


def main() -> int:
    args = build_parser().parse_args()
    ip_to_hosts = parse_resp_file(Path(args.input))
    write_outputs(ip_to_hosts, Path(args.output_dir))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
