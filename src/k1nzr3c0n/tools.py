"""Tool registry and in-place update engine.

Categories:
  gh_binary    – download pre-built binary from GitHub Releases
  pip          – pip3 install --upgrade
  git          – git pull + pip install -r requirements.txt
  rebuild_only – no pre-built binary; update by re-running install.sh step
"""
from __future__ import annotations

import fnmatch
import gzip
import json
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Optional

BIN_DIR = Path("/usr/local/bin")
WORDLISTS_DIR = Path(os.environ.get("K1NZR3C0N_BASE", "/opt/k1nzr3c0n")) / "wordlists"

# Optional GitHub token — raises rate limit from 60 to 5,000 req/hr
_GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")


# ── Low-level helpers ──────────────────────────────────────────────────────────

_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[A-Za-z]|\r')


def _sh(cmd: list[str], timeout: int = 8) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        raw = (r.stdout or "") + (r.stderr or "")
        return _ANSI_RE.sub('', raw)
    except Exception:
        return ""


def _ver(output: str, pattern: str) -> Optional[str]:
    m = re.search(pattern, output, re.IGNORECASE | re.MULTILINE)
    if not m:
        return None
    # Return first non-None group
    for g in (m.groups() or [m.group(0)]):
        if g:
            return g.strip()
    return None


def _download(url: str, dest: Path, timeout: int = 120) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": "k1nzr3c0n/3"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        dest.write_bytes(r.read())


def _install(src: Path, dest_name: str) -> None:
    target = BIN_DIR / dest_name
    # Write to a sibling temp file then atomically rename — avoids ETXTBSY
    # when the binary is currently executing (rename() swaps the inode; running
    # processes keep using the old one while new executions pick up the new file).
    tmp = target.with_name(dest_name + ".__installing__")
    try:
        shutil.copy2(str(src), str(tmp))
        mode = tmp.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH
        tmp.chmod(mode)
        os.replace(str(tmp), str(target))
    except Exception:
        tmp.unlink(missing_ok=True)
        raise


# ── GitHub / PyPI API ─────────────────────────────────────────────────────────

def _gh_headers() -> dict:
    h = {"User-Agent": "k1nzr3c0n/3", "Accept": "application/vnd.github+json"}
    if _GITHUB_TOKEN:
        h["Authorization"] = f"Bearer {_GITHUB_TOKEN}"
    return h


def _gh_release(repo: str) -> dict:
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    req = urllib.request.Request(url, headers=_gh_headers())
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())


def _gh_latest(repo: str) -> Optional[str]:
    try:
        tag = _gh_release(repo).get("tag_name", "")
        return tag.lstrip("v") or None
    except Exception:
        return None


def _gh_asset_url(repo: str, globs: list[str]) -> tuple[str, str]:
    """Return (version_str, download_url) for the first matching asset."""
    data = _gh_release(repo)
    ver = data.get("tag_name", "").lstrip("v")
    assets = data.get("assets", [])
    for glob in globs:
        pat = glob.format(ver=ver)
        for a in assets:
            if fnmatch.fnmatch(a["name"], pat):
                return ver, a["browser_download_url"]
    names = [a["name"] for a in assets]
    raise ValueError(f"No matching asset in {repo}: tried {globs}, got {names}")


def get_latest_with_url(tool: dict) -> tuple[Optional[str], Optional[str]]:
    """Return (version, download_url) for a gh_binary tool in a single API call.

    Caches the asset URL so update tasks can skip a second GitHub API round-trip.
    """
    try:
        ver, url = _gh_asset_url(tool["repo"], tool["asset_globs"])
        return ver, url
    except Exception:
        return None, None


def _pypi_latest(pkg: str) -> Optional[str]:
    try:
        with urllib.request.urlopen(f"https://pypi.org/pypi/{pkg}/json", timeout=10) as r:
            return json.loads(r.read())["info"]["version"]
    except Exception:
        return None


def _pip_version(pkg: str) -> Optional[str]:
    return _ver(_sh(["pip3", "show", pkg]), r"^Version:\s*([\d.a-z]+)")


# ── Archive extraction ─────────────────────────────────────────────────────────

def _from_zip(archive: Path, binary_name: str, dest_name: str) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(tmp)
        hits = list(Path(tmp).rglob(binary_name))
        if not hits:
            raise FileNotFoundError(f"{binary_name} not in {archive.name}")
        _install(hits[0], dest_name)


def _from_tar(archive: Path, binary_name: str, dest_name: str) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        with tarfile.open(archive, "r:*") as tf:
            tf.extractall(tmp)
        hits = list(Path(tmp).rglob(binary_name))
        if not hits:
            # Fallback: any file without extension
            hits = [p for p in Path(tmp).rglob("*") if p.is_file() and "." not in p.name]
        if not hits:
            raise FileNotFoundError(f"{binary_name} not in {archive.name}")
        _install(hits[0], dest_name)


def _from_gz(archive: Path, dest_name: str) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / dest_name
        with gzip.open(archive, "rb") as fi, open(out, "wb") as fo:
            shutil.copyfileobj(fi, fo)
        _install(out, dest_name)


def _from_zip_tar(archive: Path, binary_name: str, dest_name: str) -> None:
    """Handle assets that are a .zip containing a single .tar.gz (e.g. RustScan)."""
    with tempfile.TemporaryDirectory() as tmp:
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(tmp)
        tar_files = list(Path(tmp).glob("*.tar.gz")) + list(Path(tmp).glob("*.tar"))
        if not tar_files:
            raise FileNotFoundError(f"No tar.gz inside {archive.name}")
        with tarfile.open(tar_files[0], "r:*") as tf:
            tf.extractall(tmp)
        hits = list(Path(tmp).rglob(binary_name))
        if not hits:
            hits = [p for p in Path(tmp).rglob("*") if p.is_file() and "." not in p.name]
        if not hits:
            raise FileNotFoundError(f"{binary_name} not in {archive.name}")
        _install(hits[0], dest_name)


# ── Per-category update functions ─────────────────────────────────────────────

def _update_gh_binary(tool: dict, cached_url: str = None, cached_ver: str = None) -> str:
    with tempfile.TemporaryDirectory() as tmp:
        if cached_url and cached_ver:
            ver, url = cached_ver, cached_url
        else:
            ver, url = _gh_asset_url(tool["repo"], tool["asset_globs"])
        tmp_file = Path(tmp) / "dl"
        _download(url, tmp_file)
        fmt = tool["asset_fmt"]
        dest = tool.get("dest", tool["name"])
        arc_bin = tool.get("bin_in_arc", tool["name"])
        if fmt == "zip":
            _from_zip(tmp_file, arc_bin, dest)
        elif fmt == "tar":
            _from_tar(tmp_file, arc_bin, dest)
        elif fmt == "gz":
            _from_gz(tmp_file, dest)
        elif fmt == "zip_tar":
            _from_zip_tar(tmp_file, arc_bin, dest)
        elif fmt == "binary":
            _install(tmp_file, dest)
        elif fmt == "deb":
            deb = Path(tmp) / "pkg.deb"
            shutil.copy2(str(tmp_file), str(deb))
            r = subprocess.run(["dpkg", "-i", str(deb)], capture_output=True, timeout=60)
            if r.returncode != 0:
                raise RuntimeError(r.stderr.decode()[:300])
        else:
            raise ValueError(f"Unknown asset_fmt: {fmt}")
        return ver


def _update_pip(tool: dict) -> str:
    r = subprocess.run(
        ["pip3", "install", "--upgrade", tool["pypi"], "--break-system-packages"],
        capture_output=True, text=True, timeout=180,
    )
    if r.returncode != 0:
        raise RuntimeError(r.stderr[:400])
    # Re-extract arjun wordlists if this is arjun
    if tool["pypi"] == "arjun":
        _refresh_arjun_wordlists()
    return _pip_version(tool["pypi"]) or "?"


def _refresh_arjun_wordlists() -> None:
    """Copy updated arjun param wordlists to /app/wordlists/."""
    import glob as _glob
    for src_glob, dest in [
        ("/usr/**/arjun/db/medium.txt", "params-medium.txt"),
        ("/usr/**/arjun/db/large.txt", "params-large.txt"),
    ]:
        hits = _glob.glob(src_glob, recursive=True)
        if hits:
            shutil.copy2(hits[0], str(WORDLISTS_DIR / dest))


def _update_git(tool: dict) -> str:
    git_dir = tool["git_dir"]
    r = subprocess.run(
        ["git", "-C", git_dir, "pull", "--ff-only"],
        capture_output=True, text=True, timeout=120,
    )
    if r.returncode != 0:
        raise RuntimeError((r.stdout + r.stderr)[:400])
    # Skip requirements.txt re-install — the deps were installed at image build time.
    # Re-installing can downgrade system packages (e.g. OneForAll pins SQLAlchemy==1.3)
    # which breaks k1nzr3c0n itself. New deps are picked up on the next image rebuild.
    out = _sh(["git", "-C", git_dir, "rev-parse", "--short", "HEAD"])
    return out.strip() or "?"


def _update_wordlist(wl: dict) -> str:
    dest = WORDLISTS_DIR / wl["file"]
    with tempfile.TemporaryDirectory() as tmp:
        tmp_file = Path(tmp) / "dl"
        _download(wl["url"], tmp_file)
        extract = wl.get("extract")
        if extract == "tar":
            glob_pat = wl.get("extract_glob", "*")
            with tarfile.open(tmp_file, "r:gz") as tf:
                hits = [m for m in tf.getmembers() if fnmatch.fnmatch(m.name, glob_pat) and m.isfile()]
                if hits:
                    tf.extract(hits[0], tmp)
                    shutil.copy2(str(Path(tmp) / hits[0].name), str(dest))
                else:
                    raise FileNotFoundError(f"No {glob_pat} in wordlist archive")
        else:
            shutil.copy2(str(tmp_file), str(dest))
    lines = sum(1 for _ in open(dest, "rb"))
    return f"{lines} lines"


# ── Tool registry ─────────────────────────────────────────────────────────────

TOOLS: list[dict[str, Any]] = [

    # ── ProjectDiscovery (all use same zip pattern) ────────────────────────
    {
        "name": "subfinder",
        "display": "subfinder",
        "desc": "Passive subdomain discovery (cert transparency + APIs)",
        "cat": "gh_binary",
        "repo": "projectdiscovery/subfinder",
        "asset_globs": ["subfinder_{ver}_linux_amd64.zip", "subfinder_*_linux_amd64.zip"],
        "asset_fmt": "zip",
        "bin_in_arc": "subfinder",
        "version_cmd": ["subfinder", "-version"],
        "version_re": r"v(\d+\.\d[\d.]*)",
    },
    {
        "name": "httpx",
        "display": "httpx",
        "desc": "HTTP probe + tech detection + status",
        "cat": "gh_binary",
        "repo": "projectdiscovery/httpx",
        "asset_globs": ["httpx_{ver}_linux_amd64.zip", "httpx_*_linux_amd64.zip"],
        "asset_fmt": "zip",
        "bin_in_arc": "httpx",
        "version_cmd": ["httpx", "-version"],
        "version_re": r"v(\d+\.\d[\d.]*)",
    },
    {
        "name": "dnsx",
        "display": "dnsx",
        "desc": "DNS resolution + bulk validation",
        "cat": "gh_binary",
        "repo": "projectdiscovery/dnsx",
        "asset_globs": ["dnsx_{ver}_linux_amd64.zip", "dnsx_*_linux_amd64.zip"],
        "asset_fmt": "zip",
        "bin_in_arc": "dnsx",
        "version_cmd": ["dnsx", "-version"],
        "version_re": r"Current Version[:\s]+v?([\d.]+)",
    },
    {
        "name": "naabu",
        "display": "naabu",
        "desc": "Fast full-range port scanner",
        "cat": "gh_binary",
        "repo": "projectdiscovery/naabu",
        "asset_globs": ["naabu_{ver}_linux_amd64.zip", "naabu_*_linux_amd64.zip"],
        "asset_fmt": "zip",
        "bin_in_arc": "naabu",
        "version_cmd": ["naabu", "-version"],
        "version_re": r"Current Version[:\s]+v?([\d.]+)",
    },
    {
        "name": "nuclei",
        "display": "nuclei",
        "desc": "Template-based vulnerability scanner",
        "cat": "gh_binary",
        "repo": "projectdiscovery/nuclei",
        "asset_globs": ["nuclei_{ver}_linux_amd64.zip", "nuclei_*_linux_amd64.zip"],
        "asset_fmt": "zip",
        "bin_in_arc": "nuclei",
        "version_cmd": ["nuclei", "-version"],
        "version_re": r"v(\d+\.\d[\d.]*)",
    },
    {
        "name": "chaos",
        "display": "chaos",
        "desc": "ProjectDiscovery subdomain dataset client",
        "cat": "gh_binary",
        "repo": "projectdiscovery/chaos-client",
        "asset_globs": ["chaos-client_{ver}_linux_amd64.zip", "chaos_*_linux_amd64.zip"],
        "asset_fmt": "zip",
        "bin_in_arc": "chaos-client",
        "version_cmd": ["chaos", "-version"],
        "version_re": r"Current Version[:\s]+v?([\d.]+)",
    },
    {
        "name": "katana",
        "display": "katana",
        "desc": "Active JS/endpoint crawler",
        "cat": "gh_binary",
        "repo": "projectdiscovery/katana",
        "asset_globs": ["katana_{ver}_linux_amd64.zip", "katana_*_linux_amd64.zip"],
        "asset_fmt": "zip",
        "bin_in_arc": "katana",
        "version_cmd": ["katana", "-version"],
        "version_re": r"v(\d+\.\d[\d.]*)",
    },
    {
        "name": "afrog",
        "display": "afrog",
        "desc": "PoC-based vulnerability scanner (complements nuclei)",
        "cat": "gh_binary",
        "repo": "zan8in/afrog",
        "asset_globs": ["afrog_{ver}_linux_amd64.zip", "afrog_*_linux_amd64.zip"],
        "asset_fmt": "zip",
        "bin_in_arc": "afrog",
        # afrog -v starts a server; extract version from Go module path embedded in binary
        "version_cmd": [
            "python3", "-c",
            "import re; d=open('/usr/local/bin/afrog','rb').read();"
            " m=re.search(rb'afrog/v[0-9]+@v([0-9.]+)', d);"
            " print(m.group(1).decode() if m else '')"
        ],
        "version_re": r"(\d+\.\d+\.\d+)",
    },
    # ── ProjectDiscovery — recon utilities ────────────────────────────────
    {
        "name": "shuffledns",
        "display": "shuffledns",
        "desc": "Mass DNS resolver with wildcard detection — wraps massdns",
        "cat": "gh_binary",
        "repo": "projectdiscovery/shuffledns",
        "asset_globs": ["shuffledns_{ver}_linux_amd64.zip", "shuffledns_*_linux_amd64.zip"],
        "asset_fmt": "zip",
        "bin_in_arc": "shuffledns",
        "version_cmd": ["shuffledns", "-version"],
        "version_re": r"v(\d+\.\d[\d.]*)",
    },
    {
        "name": "mapcidr",
        "display": "mapcidr",
        "desc": "CIDR/IP operations — expand ranges, aggregate, filter, convert ASN→IP",
        "cat": "gh_binary",
        "repo": "projectdiscovery/mapcidr",
        "asset_globs": ["mapcidr_{ver}_linux_amd64.zip", "mapcidr_*_linux_amd64.zip"],
        "asset_fmt": "zip",
        "bin_in_arc": "mapcidr",
        "version_cmd": ["mapcidr", "-version"],
        "version_re": r"v(\d+\.\d[\d.]*)",
    },
    {
        "name": "cdncheck",
        "display": "cdncheck",
        "desc": "CDN detection — Cloudflare, Akamai, Fastly, CloudFront, WAF fingerprint",
        "cat": "gh_binary",
        "repo": "projectdiscovery/cdncheck",
        "asset_globs": ["cdncheck_{ver}_linux_amd64.zip", "cdncheck_*_linux_amd64.zip"],
        "asset_fmt": "zip",
        "bin_in_arc": "cdncheck",
        "version_cmd": ["cdncheck", "-version"],
        "version_re": r"v(\d+\.\d[\d.]*)",
    },
    {
        "name": "asnmap",
        "display": "asnmap",
        "desc": "ASN → IP range mapping — find all IP space owned by an organization",
        "cat": "gh_binary",
        "repo": "projectdiscovery/asnmap",
        "asset_globs": ["asnmap_{ver}_linux_amd64.zip", "asnmap_*_linux_amd64.zip"],
        "asset_fmt": "zip",
        "bin_in_arc": "asnmap",
        "version_cmd": ["asnmap", "-version"],
        "version_re": r"v(\d+\.\d[\d.]*)",
    },
    {
        "name": "notify",
        "display": "notify",
        "desc": "Push findings to Slack/Discord/Telegram/email in real-time",
        "cat": "gh_binary",
        "repo": "projectdiscovery/notify",
        "asset_globs": ["notify_{ver}_linux_amd64.zip", "notify_*_linux_amd64.zip"],
        "asset_fmt": "zip",
        "bin_in_arc": "notify",
        "version_cmd": ["notify", "-version"],
        "version_re": r"Version:\s*v?(\d+\.\d[\d.]*)",
    },

    {
        "name": "tlsx",
        "display": "tlsx",
        "desc": "TLS/SSL certificate scanner — cipher suites, SAN, expiry, misconfigs",
        "cat": "gh_binary",
        "repo": "projectdiscovery/tlsx",
        "asset_globs": ["tlsx_{ver}_linux_amd64.zip", "tlsx_*_linux_amd64.zip"],
        "asset_fmt": "zip",
        "bin_in_arc": "tlsx",
        "version_cmd": ["tlsx", "-version"],
        "version_re": r"v(\d+\.\d[\d.]*)",
    },
    {
        "name": "alterx",
        "display": "alterx",
        "desc": "Subdomain permutation engine — generates wordlist-based variations",
        "cat": "gh_binary",
        "repo": "projectdiscovery/alterx",
        "asset_globs": ["alterx_{ver}_linux_amd64.zip", "alterx_*_linux_amd64.zip"],
        "asset_fmt": "zip",
        "bin_in_arc": "alterx",
        "version_cmd": ["alterx", "-version"],
        "version_re": r"v(\d+\.\d[\d.]*)",
    },
    {
        "name": "uncover",
        "display": "uncover",
        "desc": "Internet asset discovery via Shodan, Fofa, Censys, Hunter, Netlas",
        "cat": "gh_binary",
        "repo": "projectdiscovery/uncover",
        "asset_globs": ["uncover_{ver}_linux_amd64.zip", "uncover_*_linux_amd64.zip"],
        "asset_fmt": "zip",
        "bin_in_arc": "uncover",
        "version_cmd": ["uncover", "-version"],
        "version_re": r"v(\d+\.\d[\d.]*)",
    },
    {
        "name": "interactsh-client",
        "display": "interactsh",
        "desc": "OOB interaction server — detect blind SSRF, RCE, XXE, log4j",
        "cat": "gh_binary",
        "repo": "projectdiscovery/interactsh",
        "asset_globs": ["interactsh-client_{ver}_linux_amd64.zip", "interactsh-client_*_linux_amd64.zip"],
        "asset_fmt": "zip",
        "bin_in_arc": "interactsh-client",
        "version_cmd": ["interactsh-client", "-version"],
        "version_re": r"Version:\s*v?(\d+\.\d[\d.]*)",
    },
    {
        "name": "cvemap",
        "display": "cvemap",
        "desc": "CVE/NVD intelligence — CVSS, EPSS, KEV, nuclei template mapping",
        "cat": "gh_binary",
        "repo": "projectdiscovery/cvemap",
        "asset_globs": ["vulnx_{ver}_linux_amd64.zip", "vulnx_*_linux_amd64.zip"],
        "asset_fmt": "zip",
        "bin_in_arc": "vulnx",
        "dest": "cvemap",
        "version_cmd": ["cvemap", "-version"],
        "version_re": r"version\s+(\d+\.\d[\d.]*)",
    },

    {
        "name": "urlfinder",
        "display": "urlfinder",
        "desc": "Passive URL extraction from Wayback, CommonCrawl, OTX, URLScan",
        "cat": "gh_binary",
        "repo": "projectdiscovery/urlfinder",
        "asset_globs": ["urlfinder_{ver}_linux_amd64.zip", "urlfinder_*_linux_amd64.zip"],
        "asset_fmt": "zip",
        "bin_in_arc": "urlfinder",
        "version_cmd": ["urlfinder", "-version"],
        "version_re": r"v(\d+\.\d[\d.]*)",
    },

    # ── Other GitHub binary tools ──────────────────────────────────────────
    {
        "name": "cariddi",
        "display": "cariddi",
        "desc": "Web crawler with endpoint, error-pattern, and secret detection",
        "cat": "gh_binary",
        "repo": "edoardottt/cariddi",
        "asset_globs": ["cariddi_{ver}_linux_amd64.zip", "cariddi_*_linux_amd64.zip"],
        "asset_fmt": "zip",
        "bin_in_arc": "cariddi",
        "version_cmd": ["cariddi", "--version"],
        "version_re": r"(\d+\.\d[\d.]*)",
    },
    {
        "name": "jaeles",
        "display": "jaeles",
        "desc": "Signature-based web security scanner — custom YAML vulnerability templates",
        "cat": "gh_binary",
        "repo": "jaeles-project/jaeles",
        "asset_globs": ["jaeles-*linux*.zip"],
        "asset_fmt": "zip",
        "bin_in_arc": "jaeles",
        "version_cmd": ["jaeles"],    # banner shows "Jaeles beta v0.17.1" on first line
        "version_re": r"v(\d+\.\d[\d.]*)",
    },
    {
        "name": "crlfuzz",
        "display": "crlfuzz",
        "desc": "CRLF injection scanner — HTTP response splitting, header injection",
        "cat": "gh_binary",
        "repo": "dwisiswant0/crlfuzz",
        "asset_globs": ["crlfuzz_{ver}_linux_amd64.tar.gz", "crlfuzz_*_linux_amd64.tar.gz"],
        "asset_fmt": "tar",
        "bin_in_arc": "crlfuzz",
        "version_cmd": ["crlfuzz", "--version"],
        "version_re": r"(\d+\.\d[\d.]*)",
    },
    {
        "name": "metabigor",
        "display": "metabigor",
        "desc": "OSINT meta tool — IP/ASN/org lookup, network range discovery",
        "cat": "gh_binary",
        "repo": "j3ssie/metabigor",
        "asset_globs": ["metabigor_v{ver}_linux_amd64.tar.gz", "metabigor_*_linux_amd64.tar.gz"],
        "asset_fmt": "tar",
        "bin_in_arc": "metabigor",
        "version_cmd": None,  # no --version flag; binary presence is enough
        "version_re": None,
    },
    {
        "name": "cero",
        "display": "cero",
        "desc": "TLS certificate SAN extractor via SNI — passive subdomain discovery from certs",
        "cat": "gh_binary",
        "repo": "glebarez/cero",
        "asset_globs": ["cero-linux-amd64"],
        "asset_fmt": "binary",
        "dest": "cero",
        "version_cmd": None,
        "version_re": None,
    },
    {
        "name": "gxss",
        "display": "gxss",
        "desc": "Reflected XSS sink detector — test params for unsafe reflection without encoding",
        "cat": "gh_binary",
        "repo": "KathanP19/Gxss",
        "asset_globs": ["Gxss_{ver}_Linux_x86_64.tar.gz", "Gxss_*_Linux_x86_64.tar.gz"],
        "asset_fmt": "tar",
        "bin_in_arc": "Gxss",
        "dest": "gxss",
        "version_cmd": None,
        "version_re": None,
    },
    {
        "name": "dnstake",
        "display": "dnstake",
        "desc": "DNS takeover detection — identify vulnerable CNAME and NS records",
        "cat": "gh_binary",
        "repo": "pwnesia/dnstake",
        "asset_globs": ["dnstake_{ver}_linux_amd64.tar.gz", "dnstake_*_linux_amd64.tar.gz"],
        "asset_fmt": "tar",
        "bin_in_arc": "dnstake",
        "version_cmd": None,  # no version flag; binary presence is enough
        "version_re": None,
    },
    {
        "name": "gobuster",
        "display": "gobuster",
        "desc": "Directory / DNS / vhost brute-force",
        "cat": "gh_binary",
        "repo": "OJ/gobuster",
        "asset_globs": ["gobuster_Linux_x86_64.tar.gz", "gobuster_*_linux_amd64.tar.gz"],
        "asset_fmt": "tar",
        "bin_in_arc": "gobuster",
        "version_cmd": ["gobuster", "--version"],
        "version_re": r"(\d+\.\d[\d.]*)",
    },
    {
        "name": "ffuf",
        "display": "ffuf",
        "desc": "Fast web fuzzer",
        "cat": "gh_binary",
        "repo": "ffuf/ffuf",
        "asset_globs": ["ffuf_{ver}_linux_amd64.tar.gz", "ffuf_*_linux_amd64.tar.gz"],
        "asset_fmt": "tar",
        "bin_in_arc": "ffuf",
        "version_cmd": ["ffuf", "-V"],
        "version_re": r"([\d]+\.[\d]+\.[\d]+)",
    },
    {
        "name": "feroxbuster",
        "display": "feroxbuster",
        "desc": "Recursive content discovery",
        "cat": "gh_binary",
        "repo": "epi052/feroxbuster",
        "asset_globs": ["x86_64-linux-feroxbuster.zip"],
        "asset_fmt": "zip",
        "bin_in_arc": "feroxbuster",
        "version_cmd": ["feroxbuster", "--version"],
        "version_re": r"(\d+\.\d[\d.]*)",
    },
    {
        "name": "gowitness",
        "display": "gowitness",
        "desc": "Headless screenshots via Chromium",
        "cat": "gh_binary",
        "repo": "sensepost/gowitness",
        "asset_globs": ["gowitness-{ver}-linux-amd64", "gowitness_*_linux_amd64"],
        "asset_fmt": "binary",
        "dest": "gowitness",
        "version_cmd": ["gowitness", "version"],
        "version_re": r"gowitness:\s*([\d.]+)",
    },
    {
        "name": "findomain",
        "display": "findomain",
        "desc": "Subdomain discovery (cert transparency + APIs)",
        "cat": "gh_binary",
        "repo": "findomain/findomain",
        "asset_globs": ["findomain-linux.zip", "findomain_*_linux_amd64.zip"],
        "asset_fmt": "zip",
        "bin_in_arc": "findomain",
        "version_cmd": ["findomain", "--version"],
        "version_re": r"(\d+\.\d[\d.]*)",
    },
    {
        "name": "amass",
        "display": "amass",
        "desc": "OWASP passive subdomain enumeration",
        "cat": "gh_binary",
        "repo": "owasp-amass/amass",
        "asset_globs": ["amass_linux_amd64.tar.gz", "amass_*_linux_amd64.tar.gz"],
        "asset_fmt": "tar",
        "bin_in_arc": "amass",
        "version_cmd": ["amass", "-version"],
        "version_re": r"v(\d+\.\d[\d.]*)",
    },
    {
        "name": "x8",
        "display": "x8",
        "desc": "Diff-based hidden parameter discovery",
        "cat": "gh_binary",
        "repo": "sh1yo/x8",
        "asset_globs": ["x86_64-linux-x8.gz"],
        "asset_fmt": "gz",
        "dest": "x8",
        "version_cmd": ["x8", "--version"],
        "version_re": r"x8\s+([\d.]+)",
    },
    {
        "name": "fallparams",
        "display": "fallparams",
        "desc": "Crawl-based parameter discovery",
        "cat": "gh_binary",
        "repo": "ImAyrix/fallparams",
        "asset_globs": ["fallparams_{ver}_linux_amd64.zip", "fallparams_*_linux_amd64.zip"],
        "asset_fmt": "zip",
        "bin_in_arc": "fallparams",
        "version_cmd": None,   # fallparams has no version flag
        "version_re": None,
    },
    {
        "name": "kr",
        "display": "kiterunner",
        "desc": "API route discovery (Assetnote wordlists)",
        "cat": "gh_binary",
        "repo": "assetnote/kiterunner",
        "asset_globs": ["kiterunner_{ver}_linux_amd64.tar.gz", "kiterunner_*_linux_amd64.tar.gz"],
        "asset_fmt": "tar",
        "bin_in_arc": "kr",
        "dest": "kr",
        "version_cmd": None,        # kr has no --version flag
        "version_re": None,
    },
    {
        "name": "gau",
        "display": "gau",
        "desc": "Passive URL mining (Wayback + Common Crawl + OTX)",
        "cat": "gh_binary",
        "repo": "lc/gau",
        "asset_globs": ["gau_{ver}_linux_amd64.tar.gz", "gau_*_linux_amd64.tar.gz"],
        "asset_fmt": "tar",
        "bin_in_arc": "gau",
        "version_cmd": ["gau", "--version"],
        "version_re": r"(\d+\.\d[\d.]*)",
    },
    {
        "name": "dalfox",
        "display": "dalfox",
        "desc": "XSS scanner — reflected, stored, DOM-based, blind payload injection",
        "cat": "gh_binary",
        "repo": "hahwul/dalfox",
        "asset_globs": ["dalfox-*-linux-x86_64.tar.gz"],
        "asset_fmt": "tar",
        "bin_in_arc": "dalfox",
        "version_cmd": ["dalfox", "--version"],
        "version_re": r"(\d+\.\d[\d.]*)",
    },
    {
        "name": "trufflehog",
        "display": "trufflehog",
        "desc": "Secret/credential scanner — git, S3, endpoints, JavaScript",
        "cat": "gh_binary",
        "repo": "trufflesecurity/trufflehog",
        "asset_globs": ["trufflehog_{ver}_linux_amd64.tar.gz", "trufflehog_*_linux_amd64.tar.gz"],
        "asset_fmt": "tar",
        "bin_in_arc": "trufflehog",
        "version_cmd": ["trufflehog", "--version"],
        "version_re": r"(\d+\.\d[\d.]*)",
    },
    {
        "name": "gitleaks",
        "display": "gitleaks",
        "desc": "Git repository secret scanning (hardcoded credentials, tokens)",
        "cat": "gh_binary",
        "repo": "gitleaks/gitleaks",
        "asset_globs": ["gitleaks_{ver}_linux_x64.tar.gz", "gitleaks_*_linux_x64.tar.gz"],
        "asset_fmt": "tar",
        "bin_in_arc": "gitleaks",
        "version_cmd": ["gitleaks", "version"],
        "version_re": r"(\d+\.\d[\d.]*)",
    },
    {
        "name": "puredns",
        "display": "puredns",
        "desc": "Mass DNS resolver with wildcard filtering and bruteforce",
        "cat": "gh_binary",
        "repo": "d3mondev/puredns",
        "asset_globs": ["puredns-Linux-amd64.tgz"],
        "asset_fmt": "tar",
        "bin_in_arc": "puredns",
        "version_cmd": ["puredns", "--version"],
        "version_re": r"v(\d+\.\d[\d.]*)",
    },
    {
        "name": "gospider",
        "display": "gospider",
        "desc": "Fast web spider — JS parsing, form extraction, endpoint discovery",
        "cat": "gh_binary",
        "repo": "jaeles-project/gospider",
        "asset_globs": ["gospider_{ver}_linux_amd64.zip", "gospider_*_linux_amd64.zip"],
        "asset_fmt": "zip",
        "bin_in_arc": "gospider",
        "version_cmd": ["gospider", "--version"],
        "version_re": r"(\d+\.\d[\d.]*)",
    },
    {
        "name": "hakrawler",
        "display": "hakrawler",
        "desc": "Simple fast web crawler for endpoint and JS link discovery",
        "cat": "rebuild_only",  # no release binaries; installed via go install
        "version_cmd": None,
        "version_re": None,
    },
    {
        "name": "trivy",
        "display": "trivy",
        "desc": "Container, IaC, cloud vulnerability scanner (Aqua Security)",
        "cat": "gh_binary",
        "repo": "aquasecurity/trivy",
        "asset_globs": ["trivy_{ver}_Linux-64bit.tar.gz", "trivy_*_Linux-64bit.tar.gz"],
        "asset_fmt": "tar",
        "bin_in_arc": "trivy",
        "version_cmd": ["trivy", "--version"],
        "version_re": r"Version:\s*([\d.]+)",
    },
    {
        "name": "subzy",
        "display": "subzy",
        "desc": "Subdomain takeover detection",
        "cat": "rebuild_only",  # upstream repo removed; no longer publishes release binaries
    },
    {
        "name": "fuzzuli",
        "display": "fuzzuli",
        "desc": "Dynamic backup-file wordlist fuzzer",
        "cat": "rebuild_only",  # musana/fuzzuli stopped publishing release binaries (all releases have 0 assets)
    },
    {
        "name": "rustscan",
        "display": "rustscan",
        "desc": "Ultra-fast port scanner (Rust)",
        "cat": "gh_binary",
        "repo": "RustScan/RustScan",
        "asset_globs": ["x86_64-linux-rustscan.tar.gz.zip"],
        "asset_fmt": "zip_tar",
        "bin_in_arc": "rustscan",
        "dest": "rustscan",
        "version_cmd": ["rustscan", "--version"],
        "version_re": r"(\d+\.\d[\d.]*)",
    },

    # ── Bug bounty essentials (gh_binary) ─────────────────────────────────
    {
        "name": "jsapiscan",
        "display": "jsapiscan",
        "desc": "Extract API endpoints and parameters from JavaScript source files",
        "cat": "gh_binary",
        "repo": "ruisika/jsapiscan",
        "asset_globs": ["JSAPIscan_linux_amd64"],
        "asset_fmt": "binary",
        "dest": "jsapiscan",
        "version_cmd": None,
        "version_re": None,
    },
    {
        "name": "subjs",
        "display": "subjs",
        "desc": "Collect JavaScript file URLs from a host list — feeds linkfinder/secretfinder",
        "cat": "gh_binary",
        "repo": "lc/subjs",
        "asset_globs": ["subjs_{ver}_linux_amd64.tar.gz", "subjs_*_linux_amd64.tar.gz"],
        "asset_fmt": "tar",
        "bin_in_arc": "subjs",
        "version_cmd": ["subjs", "--version"],
        "version_re": r"version[:\s]+(\d+\.\d[\d.]*)",
    },
    {
        "name": "s3scanner",
        "display": "S3Scanner",
        "desc": "Scan for open S3, GCS, Azure Blob Storage and DigitalOcean Spaces buckets",
        "cat": "gh_binary",
        "repo": "sa7mon/S3Scanner",
        "asset_globs": ["S3Scanner_Linux_x86_64.tar.gz"],
        "asset_fmt": "tar",
        "bin_in_arc": "S3Scanner",
        "dest": "s3scanner",
        "version_cmd": ["s3scanner", "--version"],
        "version_re": r"(\d+\.\d[\d.]*)",
    },
    {
        "name": "unfurl",
        "display": "unfurl",
        "desc": "URL decomposition — extract keys, values, domains, paths for analysis",
        "cat": "rebuild_only",  # tomnomnom releases are stale; installed via go install in builder
        "version_cmd": None,
        "version_re": None,
    },
    {
        "name": "qsreplace",
        "display": "qsreplace",
        "desc": "Replace URL query string values — injection fuzzing pipelines",
        "cat": "rebuild_only",  # tomnomnom; go install in builder
        "version_cmd": None,
        "version_re": None,
    },
    {
        "name": "meg",
        "display": "meg",
        "desc": "Fetch many paths for many hosts — efficient bulk HTTP requester",
        "cat": "rebuild_only",  # tomnomnom; go install in builder
        "version_cmd": None,
        "version_re": None,
    },

    # ── No pre-built binary (require image rebuild) ────────────────────────
    {
        "name": "assetfinder",
        "display": "assetfinder",
        "desc": "Subdomain discovery via Facebook graph + cert APIs",
        "cat": "rebuild_only",
        "version_cmd": ["assetfinder", "--help"],
        "version_re": None,
    },
    {
        "name": "waybackurls",
        "display": "waybackurls",
        "desc": "Wayback Machine historical URL dump",
        "cat": "rebuild_only",
        "version_cmd": ["waybackurls", "--help"],
        "version_re": None,
    },
    {
        "name": "anew",
        "display": "anew",
        "desc": "Append new unique lines to a file — dedup streaming utility",
        "cat": "rebuild_only",  # no release binaries; installed via go install
        "version_cmd": None,
        "version_re": None,
    },
    {
        "name": "nmap",
        "display": "nmap",
        "desc": "Network port scanner (apt package)",
        "cat": "rebuild_only",
        "version_cmd": ["nmap", "--version"],
        "version_re": r"Nmap version ([\d.]+)",
    },
    {
        "name": "nikto",
        "display": "nikto",
        "desc": "Web server scanner — outdated software, CGI, dangerous files",
        "cat": "rebuild_only",
        "version_cmd": ["nikto", "-Version"],
        "version_re": r"(\d+\.\d[\d.]*)",
    },
    {
        "name": "ssh-audit",
        "display": "ssh-audit",
        "desc": "SSH configuration auditor — ciphers, key exchange, CVEs",
        "cat": "rebuild_only",
        "version_cmd": ["ssh-audit", "--version"],
        "version_re": r"(\d+\.\d[\d.]*)",
    },
    {
        "name": "sslscan",
        "display": "sslscan",
        "desc": "TLS/SSL cipher and protocol version scanner",
        "cat": "rebuild_only",
        "version_cmd": ["sslscan", "--version"],
        "version_re": r"(\d+\.\d[\d.]*)",
    },
    {
        "name": "testssl",
        "display": "testssl.sh",
        "desc": "Comprehensive TLS testing — BEAST, POODLE, DROWN, CRIME, RC4...",
        "cat": "rebuild_only",
        "version_cmd": ["testssl", "--version"],
        "version_re": r"(\d+\.\d[\d.]*)",
    },
    {
        "name": "onesixtyone",
        "display": "onesixtyone",
        "desc": "Fast SNMP community string brute-force scanner",
        "cat": "rebuild_only",
        "version_cmd": None,
        "version_re": None,
    },
    {
        "name": "snmpwalk",
        "display": "snmpwalk",
        "desc": "SNMP MIB tree walk and full OID enumeration",
        "cat": "rebuild_only",
        "version_cmd": ["snmpwalk", "--version"],
        "version_re": r"(\d+\.\d[\d.]*)",
    },
    {
        "name": "redis-cli",
        "display": "redis-cli",
        "desc": "Redis client — unauthenticated access probe and info dump",
        "cat": "rebuild_only",
        "version_cmd": ["redis-cli", "--version"],
        "version_re": r"(\d+\.\d[\d.]*)",
    },
    {
        "name": "masscan",
        "display": "masscan",
        "desc": "Internet-scale port scanner — 10Gbps+ async SYN scanner",
        "cat": "rebuild_only",
        "version_cmd": ["masscan", "--version"],
        "version_re": r"(\d+\.\d[\d.]*)",
    },
    {
        "name": "searchsploit",
        "display": "searchsploit",
        "desc": "Offline ExploitDB CLI — search CVEs and public exploits by service/version",
        "cat": "rebuild_only",
        "version_cmd": None,   # shell script; no reliable --version flag
        "version_re": None,
    },
    {
        "name": "wpscan",
        "display": "wpscan",
        "desc": "WordPress vulnerability scanner — themes, plugins, users, config leaks",
        "cat": "rebuild_only",  # Ruby gem
        "version_cmd": ["wpscan", "--version"],
        "version_re": r"(\d+\.\d[\d.]*)",
    },
    {
        "name": "whatweb",
        "display": "whatweb",
        "desc": "Web fingerprinting — identify CMS, server, framework, JS libs (1800+ plugins)",
        "cat": "rebuild_only",  # git clone; Ruby
        "version_cmd": ["whatweb", "--version"],
        "version_re": r"(\d+\.\d[\d.]*)",
    },
    {
        "name": "massdns",
        "display": "massdns",
        "desc": "High-performance DNS stub resolver — backbone for shuffledns and puredns",
        "cat": "rebuild_only",  # compiled from C source
        "version_cmd": ["massdns", "--version"],
        "version_re": r"(\d+\.\d[\d.]*)",
    },
    {
        "name": "tplmap",
        "display": "tplmap",
        "desc": "Server-side template injection (SSTI) detection and exploitation",
        "cat": "rebuild_only",  # git clone; Python
        "version_cmd": None,
        "version_re": None,
    },
    {
        "name": "nosqlmap",
        "display": "nosqlmap",
        "desc": "Automated NoSQL injection and exploitation (MongoDB, CouchDB, Redis, Cassandra)",
        "cat": "rebuild_only",  # git clone; Python
        "version_cmd": None,
        "version_re": None,
    },
    {
        "name": "dnsvalidator",
        "display": "dnsvalidator",
        "desc": "Validate and filter reliable public DNS resolvers for fast scanning",
        "cat": "rebuild_only",  # git clone; Python
        "version_cmd": None,
        "version_re": None,
    },
    {
        "name": "ghauri",
        "display": "ghauri",
        "desc": "Advanced SQL injection — blind, time-based, error-based, stacked queries",
        "cat": "rebuild_only",  # git clone; Python (not on PyPI)
        "version_cmd": ["ghauri", "--version"],
        "version_re": r"(\d+\.\d[\d.]*)",
    },
    {
        "name": "takeover",
        "display": "takeover",
        "desc": "Subdomain takeover via fingerprinting 50+ hosting service signatures",
        "cat": "rebuild_only",  # git clone; Python (m4ll0k/takeover)
        "version_cmd": None,
        "version_re": None,
    },
    {
        "name": "gotator",
        "display": "gotator",
        "desc": "Fast subdomain permutation generator",
        "cat": "rebuild_only",  # go install; no release binaries
        "version_cmd": None,
        "version_re": None,
    },
    {
        "name": "gauplus",
        "display": "gauplus",
        "desc": "Extended URL archive harvester — builds on gau with extra sources",
        "cat": "rebuild_only",  # repo archived; go install
        "version_cmd": None,
        "version_re": None,
    },
    {
        "name": "byp4xx",
        "display": "byp4xx",
        "desc": "40x bypass tool — HTTP method + header tricks to circumvent access controls",
        "cat": "rebuild_only",  # no releases; go install
        "version_cmd": None,
        "version_re": None,
    },
    {
        "name": "gf",
        "display": "gf",
        "desc": "Pattern-based grep wrapper — pre-built filters for XSS, SQLi, SSRF, redirect...",
        "cat": "rebuild_only",  # tomnomnom; no releases; go install
        "version_cmd": None,
        "version_re": None,
    },
    {
        "name": "httprobe",
        "display": "httprobe",
        "desc": "HTTP/HTTPS probe — quickly identify live web servers from a host list",
        "cat": "rebuild_only",  # tomnomnom; releases stale; go install
        "version_cmd": None,
        "version_re": None,
    },
    {
        "name": "kxss",
        "display": "kxss",
        "desc": "XSS-prone URL finder — detect parameters that reflect without HTML encoding",
        "cat": "rebuild_only",  # no releases; go install
        "version_cmd": None,
        "version_re": None,
    },
    {
        "name": "hakrevdns",
        "display": "hakrevdns",
        "desc": "Bulk reverse DNS lookup — map IP ranges to hostnames",
        "cat": "rebuild_only",  # no releases; go install
        "version_cmd": None,
        "version_re": None,
    },
    {
        "name": "subjack",
        "display": "subjack",
        "desc": "Subdomain takeover checker — fingerprints 50+ service vulnerability signatures",
        "cat": "rebuild_only",  # old releases; go install
        "version_cmd": None,
        "version_re": None,
    },
    {
        "name": "jsubfinder",
        "display": "jsubfinder",
        "desc": "Extract subdomains hidden inside JavaScript bundles and source maps",
        "cat": "rebuild_only",  # no releases; go install
        "version_cmd": None,
        "version_re": None,
    },
    {
        "name": "graphw00f",
        "display": "graphw00f",
        "desc": "GraphQL engine fingerprinting — Apollo, Hasura, Graphene, Strawberry, etc.",
        "cat": "rebuild_only",  # git clone; Python
        "version_cmd": None,
        "version_re": None,
    },
    {
        "name": "linkfinder",
        "display": "linkfinder",
        "desc": "Discover hidden endpoints and parameters in JavaScript files",
        "cat": "rebuild_only",  # git clone; Python
        "version_cmd": None,
        "version_re": None,
    },
    {
        "name": "secretfinder",
        "display": "secretfinder",
        "desc": "Find API keys, tokens and hardcoded secrets in JavaScript files",
        "cat": "rebuild_only",  # git clone; Python
        "version_cmd": None,
        "version_re": None,
    },
    {
        "name": "corsy",
        "display": "corsy",
        "desc": "CORS misconfiguration scanner — origin validation bypass, null origin",
        "cat": "rebuild_only",  # git clone; Python
        "version_cmd": None,
        "version_re": None,
    },
    {
        "name": "cloud_enum",
        "display": "cloud_enum",
        "desc": "Enumerate exposed AWS S3, Azure Blob and GCP Storage buckets",
        "cat": "rebuild_only",  # git clone; Python
        "version_cmd": None,
        "version_re": None,
    },
    {
        "name": "pagodo",
        "display": "pagodo",
        "desc": "Passive Google dork automation — search ~5000 dorks per target",
        "cat": "rebuild_only",  # git clone; Python
        "version_cmd": None,
        "version_re": None,
    },

    # ── Python pip tools ───────────────────────────────────────────────────
    {
        "name": "dirsearch",
        "display": "dirsearch",
        "desc": "Web path discovery",
        "cat": "pip",
        "pypi": "dirsearch",
        "version_cmd": None,
        "version_re": None,
    },
    {
        "name": "arjun",
        "display": "arjun",
        "desc": "HTTP parameter discovery (also provides param wordlists)",
        "cat": "pip",
        "pypi": "arjun",
        "version_cmd": None,
        "version_re": None,
    },
    {
        "name": "sublist3r",
        "display": "sublist3r",
        "desc": "Subdomain discovery (Google/Bing/Baidu/Netcraft)",
        "cat": "pip",
        "pypi": "sublist3r",
        "version_cmd": None,
        "version_re": None,
    },
    {
        "name": "sqlmap",
        "display": "sqlmap",
        "desc": "Automatic SQL injection detection and exploitation",
        "cat": "pip",
        "pypi": "sqlmap",
        "version_cmd": ["sqlmap", "--version"],
        "version_re": r"(\d+\.\d[\d.]*)",
    },
    {
        "name": "theharvester",
        "display": "theHarvester",
        "desc": "OSINT harvesting — emails, names, subdomains, IPs, URLs",
        "cat": "pip",
        "pypi": "theHarvester",
        "version_cmd": None,
        "version_re": None,
    },
    {
        "name": "waymore",
        "display": "waymore",
        "desc": "Extended URL miner — Wayback + Common Crawl + AlienVault + URLScan",
        "cat": "pip",
        "pypi": "waymore",
        "version_cmd": ["waymore", "--version"],
        "version_re": r"(\d+\.\d[\d.]*)",
    },
    {
        "name": "paramspider",
        "display": "paramspider",
        "desc": "URL parameter mining from web archives for fuzzing and injection",
        "cat": "pip",
        "pypi": "paramspider",
        "version_cmd": None,
        "version_re": None,
    },
    {
        "name": "dnsgen",
        "display": "dnsgen",
        "desc": "Domain name permutation generator from wordlists — feeds puredns/shuffledns",
        "cat": "pip",
        "pypi": "dnsgen",
        "version_cmd": None,
        "version_re": None,
    },
    {
        "name": "wafw00f",
        "display": "wafw00f",
        "desc": "WAF fingerprinting — identify Cloudflare, Imperva, Akamai, Barracuda, F5...",
        "cat": "pip",
        "pypi": "wafw00f",
        "version_cmd": ["wafw00f", "--version"],
        "version_re": r"(\d+\.\d[\d.]*)",
    },
    {
        "name": "sslyze",
        "display": "sslyze",
        "desc": "Fast TLS/SSL scanner — cert chain, heartbleed, ROBOT, CRIME, BREACH",
        "cat": "pip",
        "pypi": "sslyze",
        "version_cmd": ["sslyze", "--version"],
        "version_re": r"(\d+\.\d[\d.]*)",
    },
    {
        "name": "shodan",
        "display": "shodan",
        "desc": "Shodan CLI — query CVEs, exposed hosts, org exposure from the command line",
        "cat": "pip",
        "pypi": "shodan",
        "version_cmd": ["shodan", "--version"],
        "version_re": r"(\d+\.\d[\d.]*)",
    },
    {
        "name": "wfuzz",
        "display": "wfuzz",
        "desc": "Web fuzzer — directory, parameter, auth bypass with advanced payload injection",
        "cat": "pip",
        "pypi": "wfuzz",
        "version_cmd": ["wfuzz", "--version"],
        "version_re": r"(\d+\.\d[\d.]*)",
    },
    {
        "name": "censys",
        "display": "censys",
        "desc": "Censys Python API CLI — query internet-wide scan data for hosts and certs",
        "cat": "pip",
        "pypi": "censys",
        "version_cmd": ["censys", "--version"],
        "version_re": r"(\d+\.\d[\d.]*)",
    },
    {
        "name": "photon",
        "display": "photon",
        "desc": "Incredibly fast crawler — extracts endpoints, secrets, keys, files in one pass",
        "cat": "pip",
        "pypi": "photon",
        "version_cmd": None,
        "version_re": None,
    },
    {
        "name": "VHostScan",
        "display": "VHostScan",
        "desc": "Virtual host scanner — discover hidden vhosts via hostname brute-force",
        "cat": "pip",
        "pypi": "VHostScan",
        "version_cmd": None,
        "version_re": None,
    },

    # ── Git clone tools ────────────────────────────────────────────────────
    {
        "name": "oneforall",
        "display": "OneForAll",
        "desc": "Comprehensive subdomain enumeration (~60 sources)",
        "cat": "git",
        "repo": "shmilylty/OneForAll",
        "git_dir": "/opt/OneForAll",
        "version_cmd": None,
        "version_re": None,
    },
]


# ── Wordlist registry ─────────────────────────────────────────────────────────

WORDLISTS: list[dict[str, Any]] = [
    {
        "name": "common",
        "display": "SecLists common.txt",
        "file": "common.txt",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
        "extract": None,
    },
    {
        "name": "subdomains-20k",
        "display": "SecLists subdomains 20k",
        "file": "subdomains-top1million-20000.txt",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt",
        "extract": None,
    },
    {
        "name": "subdomains-110k",
        "display": "SecLists subdomains 110k",
        "file": "subdomains-top1million-110000.txt",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt",
        "extract": None,
    },
    {
        "name": "routes-kite",
        "display": "Assetnote kiterunner routes",
        "file": "routes-large.kite",
        "url": "https://wordlists-cdn.assetnote.io/data/kiterunner/routes-small.kite.tar.gz",
        "extract": "tar",
        "extract_glob": "*.kite",
    },
    {
        "name": "raft-directories",
        "display": "Raft medium directories",
        "file": "raft-medium-directories.txt",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt",
        "extract": None,
    },
    {
        "name": "raft-files",
        "display": "Raft medium files",
        "file": "raft-medium-files.txt",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-files.txt",
        "extract": None,
    },
    {
        "name": "burp-params",
        "display": "Burp parameter names",
        "file": "burp-parameter-names.txt",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt",
        "extract": None,
    },
    {
        "name": "snmp-communities",
        "display": "SNMP default communities",
        "file": "snmp-default-communities.txt",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/SNMP/snmp-default-community-strings-onesixtyone.txt",
        "extract": None,
    },
]


# ── Public interface ──────────────────────────────────────────────────────────

def get_tool(name: str) -> Optional[dict]:
    return next((t for t in TOOLS if t["name"] == name), None)


def get_wordlist(name: str) -> Optional[dict]:
    return next((w for w in WORDLISTS if w["name"] == name), None)


def get_installed_version(tool: dict) -> Optional[str]:
    cat = tool["cat"]

    if cat == "pip":
        return _pip_version(tool["pypi"])

    if cat == "git":
        out = _sh(["git", "-C", tool.get("git_dir", ""), "rev-parse", "--short", "HEAD"])
        return out.strip() or None

    cmd = tool.get("version_cmd")
    if not cmd:
        # For tools with no version flag, check binary exists
        binary = BIN_DIR / tool.get("dest", tool["name"])
        return "installed" if binary.exists() else None

    output = _sh(cmd)
    pattern = tool.get("version_re")
    if not pattern:
        return "installed" if output.strip() else None

    version = _ver(output, pattern)
    if version is not None:
        return version
    # Pattern didn't match but binary produced output — it is installed, version undetectable.
    # Returning "installed" prevents false "not installed" reports when the version output
    # format changes between releases (e.g. build-number-only versions, year-based versions).
    if output.strip():
        return "installed"
    return None


def get_latest_version(tool: dict) -> Optional[str]:
    cat = tool["cat"]
    repo = tool.get("repo")

    if cat in ("gh_binary", "git"):
        return _gh_latest(repo) if repo else None

    if cat == "rebuild_only":
        return _gh_latest(repo) if repo else None

    if cat == "pip":
        return _pypi_latest(tool["pypi"])

    return None


def is_outdated(installed: Optional[str], latest: Optional[str]) -> bool:
    if not installed or not latest or installed in ("installed", "?"):
        return False
    # Git commit hashes (7–40 hex chars) cannot be meaningfully compared to version tags
    if re.fullmatch(r"[0-9a-f]{7,40}", installed):
        return False

    def _norm(v: str) -> tuple[int, ...]:
        v = v.lstrip("v").split("-")[0]
        parts = [x for x in re.split(r"[._]", v) if x.isdigit()]
        return tuple(int(x) for x in parts) if parts else (0,)

    return _norm(latest) > _norm(installed)


def update_tool(tool: dict, cached_url: str = None, cached_ver: str = None) -> str:
    """Perform in-place update. Returns new version string. Raises on failure."""
    cat = tool["cat"]
    if cat == "rebuild_only":
        raise RuntimeError(f"{tool['name']} requires image rebuild — cannot update in-place")
    if cat == "gh_binary":
        return _update_gh_binary(tool, cached_url=cached_url, cached_ver=cached_ver)
    if cat == "pip":
        return _update_pip(tool)
    if cat == "git":
        return _update_git(tool)
    raise ValueError(f"Unknown category: {cat}")


def update_wordlist(wl: dict) -> str:
    """Re-download a wordlist. Returns '<N> lines'."""
    return _update_wordlist(wl)
