"""Network & DNS diagnostics + one-click fix.

The classic silent killer on this box: after a NIC/DHCP change the
systemd-resolved stub (127.0.0.53) loses its uplink DNS and every
system-DNS-dependent recon tool dies while steps still report "ok".
The fix (static /etc/resolv.conf) is NIC-independent, so it survives
any future card-network swap.
"""
from __future__ import annotations

import ipaddress
import shutil
import socket
import subprocess
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(tags=["network"])

RESOLV_CONF = Path("/etc/resolv.conf")
STUB_LINK = "/run/systemd/resolve/stub-resolv.conf"
DEFAULT_NS = ["1.1.1.1", "8.8.8.8"]
PROBE_HOSTS = ["dns.google", "api.github.com"]
_STUB_MARKER = "# This is /run/systemd/resolve/stub-resolv.conf"


def _system_dns_ok() -> tuple[bool, str]:
    err = "no probe attempted"
    for host in PROBE_HOSTS:
        try:
            socket.getaddrinfo(host, 443, socket.AF_UNSPEC, socket.SOCK_STREAM)
            return True, f"resolved {host}"
        except OSError as e:
            err = str(e)
    return False, err


def _direct_dns_ok() -> tuple[bool, str]:
    # Probe BOTH public resolvers with patient timeouts: lossy links (VMware
    # NAT) drop the first UDP packet often — a single 3s/1-try probe misreports
    # "broken" while glibc (which retries ~20s) resolves fine.
    for ns in ("1.1.1.1", "8.8.8.8"):
        try:
            r = subprocess.run(
                ["dig", "+short", "+time=4", "+tries=2", f"@{ns}", "google.com"],
                capture_output=True, text=True, timeout=12,
            )
            out = r.stdout.strip()
            if r.returncode == 0 and out:
                return True, f"{ns} → {out.splitlines()[0]}"
        except Exception:
            continue
    return False, "no public resolver reachable (1.1.1.1 & 8.8.8.8 both failed)"


# Raw-IP TLS probes: no DNS, no cert trust needed (-k) — any HTTP status back
# proves outbound TCP/443. Multiple IPs because some NATs blackhole specific
# destinations (8.8.8.8:443 blocked while google web IPs pass).
_TLS_PROBE_IPS = ["142.250.198.206", "1.1.1.1", "8.8.8.8"]


def _https_ok() -> tuple[bool, str]:
    for ip in _TLS_PROBE_IPS:
        try:
            r = subprocess.run(
                ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}",
                 "--max-time", "8", f"https://{ip}/"],
                capture_output=True, text=True, timeout=12,
            )
            code = r.stdout.strip()
            if code and code != "000":
                return True, f"{ip} → HTTP {code}"
        except Exception:
            continue
    return False, "outbound TCP/443 failed to all probe IPs"


def _read_resolv() -> tuple[list[str], str]:
    try:
        text = RESOLV_CONF.read_text(errors="replace")
    except OSError as e:
        return [], f"unreadable: {e}"
    ns = [
        parts[1]
        for parts in (line.split() for line in text.splitlines())
        if parts and parts[0] == "nameserver" and len(parts) > 1
    ]
    return ns, text


@router.get("/network/check")
def network_check() -> dict:
    sys_ok, sys_detail = _system_dns_ok()
    dir_ok, dir_detail = _direct_dns_ok()
    tls_ok, tls_detail = _https_ok()
    nameservers, resolv_text = _read_resolv()

    # Verdict from the probes that matter for recon tools (system DNS + HTTPS).
    # direct_dns is informational only — glibc falls back across nameservers.
    if sys_ok and tls_ok:
        verdict, hint = "ok", "Name resolution and outbound HTTPS are healthy."
    elif not sys_ok and not dir_ok:
        verdict, hint = "no_internet", "Outbound UDP/53 blocked — check VM NIC, gateway or firewall."
    elif not sys_ok:
        verdict, hint = "dns_broken", (
            "System resolver is dead while public resolvers work — the typical "
            "post-NIC-change breakage. Press Fix to write a static resolv.conf."
        )
    else:
        verdict, hint = "https_broken", "DNS resolves but the HTTPS probe failed."

    try:
        ips = subprocess.run(["hostname", "-I"], capture_output=True,
                             text=True, timeout=5).stdout.split()
    except Exception:
        ips = []

    return {
        "verdict": verdict,
        "hint": hint,
        "system_dns": {"ok": sys_ok, "detail": sys_detail[:160]},
        "direct_dns": {"ok": dir_ok, "detail": dir_detail[:160]},
        "https": {"ok": tls_ok, "detail": tls_detail[:160]},
        "nameservers": nameservers,
        "is_stub": resolv_text.lstrip().startswith(_STUB_MARKER),
        "ips": ips,
    }


def _probe_ns(ns: str, attempts: int = 3) -> bool:
    # VMware NAT drops single UDP/53 packets at random — one probe would
    # false-negative a perfectly usable resolver. Require 3 attempts.
    for _ in range(attempts):
        try:
            r = subprocess.run(
                ["dig", "+short", "+time=2", "+tries=1", f"@{ns}", "google.com"],
                capture_output=True, text=True, timeout=6,
            )
            if r.returncode == 0 and r.stdout.strip():
                return True
        except Exception:
            pass
    return False


def _gateway_ip() -> str | None:
    try:
        r = subprocess.run(["ip", "route"], capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            parts = line.split()
            if parts and parts[0] == "default" and "via" in parts:
                return parts[parts.index("via") + 1]
    except Exception:
        pass
    return None


def _auto_detect_resolvers() -> list[str]:
    """Probe candidate resolvers and return the ones that actually answer.

    Order matters: Go-based recon tools (subfinder/gau/waybackurls…) use the
    FIRST nameserver with little patience. VMware NAT blackholes 1.1.1.1 but
    its gateway DNS proxy works — so the gateway must come first when alive.
    """
    candidates: list[str] = []
    gw = _gateway_ip()
    if gw:
        candidates.append(gw)
    candidates += [n for n in DEFAULT_NS if n != gw]
    working = [ns for ns in candidates if _probe_ns(ns)]
    return working[:3]


class NetworkFix(BaseModel):
    nameservers: list[str] | None = None   # None = auto-detect working resolvers
    restore_stub: bool = False


@router.post("/network/fix")
def network_fix(body: NetworkFix) -> dict:
    if body.restore_stub:
        r = subprocess.run(["ln", "-sf", STUB_LINK, str(RESOLV_CONF)],
                           capture_output=True, timeout=5)
        if r.returncode != 0:
            raise HTTPException(500, f"restore failed: {r.stderr.decode()[:200]}")
        action = "restored systemd-resolved stub symlink"
    else:
        if body.nameservers:
            ns = [n.strip() for n in body.nameservers if n.strip()][:3]
            for n in ns:
                try:
                    ipaddress.IPv4Address(n)
                except ValueError:
                    raise HTTPException(400, f"Invalid IPv4 nameserver: {n}")
        else:
            ns = _auto_detect_resolvers()
            warn = ""
            if not ns:
                # Flaky hypervisor NATs flap between dead/alive windows — a
                # best-effort list still lets glibc/Go fall back to whichever
                # resolver is alive at query time. Hard-failing would leave
                # resolv.conf pointing at a dead stub instead.
                gw = _gateway_ip()
                ns = ([gw] if gw else []) + [n for n in DEFAULT_NS if n != gw]
                ns = ns[:3]
                warn = (" WARNING: all probes silent right now — wrote best-effort "
                        "list; re-run Auto-Fix when the uplink stabilizes.")
        try:
            if RESOLV_CONF.exists():
                bak = RESOLV_CONF.with_name(
                    f"resolv.conf.bak-{datetime.now():%Y%m%d-%H%M%S}"
                )
                shutil.copy2(RESOLV_CONF, bak)
                for old in sorted(RESOLV_CONF.parent.glob("resolv.conf.bak-*"))[:-5]:
                    old.unlink(missing_ok=True)
            RESOLV_CONF.write_text("".join(f"nameserver {n}\n" for n in ns))
            action = (f"auto-detected working resolvers → /etc/resolv.conf: "
                      f"{', '.join(ns)}.{warn}")
        except OSError as e:
            raise HTTPException(500, f"write failed (service not root?): {e}")

    return {"action": action, **network_check()}
