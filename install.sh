#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════
# K1NZR3C0N — All-in-one installer v12
# Kali Linux 2025 / Ubuntu 22.04+  |  Run: sudo bash install.sh
# v5: timeout cmd wrapper, fixed else/fi syntax, apt-first, no API calls
# ═══════════════════════════════════════════════════════════════════════
set -euo pipefail

# ── CONFIG ───────────────────────────────────────────────────────────
# Secrets live in install-secrets.env (gitignored, NEVER commit) — the script
# itself is safe to share/copy. Override the location via SECRETS_FILE env.
APP_DIR="/opt/k1nzr3c0n"
SECRETS_FILE="${SECRETS_FILE:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/install-secrets.env}"
if [[ -f "$SECRETS_FILE" ]]; then
  set -a; . "$SECRETS_FILE"; set +a
else
  echo "[!] $SECRETS_FILE not found — continuing with EMPTY keys."
  echo "    Create it (KEY=value lines) and re-run, or seed later via /keys UI"
  echo "    or: bash install.sh --seed-only"
fi
# Defaults — keeps `set -u` happy when keys are absent
APP_REPO="${APP_REPO:-}"
GITHUB_TOKEN="${GITHUB_TOKEN:-}"
OPENROUTER_API_KEY="${OPENROUTER_API_KEY:-}"
SECURITYTRAILS_KEY="${SECURITYTRAILS_KEY:-}"
SHODAN_API_KEY="${SHODAN_API_KEY:-}"
VIRUSTOTAL_KEY="${VIRUSTOTAL_KEY:-}"
BEVIGIL_KEY="${BEVIGIL_KEY:-}"
FOFA_KEY="${FOFA_KEY:-}"
CENSYS_API_ID="${CENSYS_API_ID:-}"
CENSYS_API_SECRET="${CENSYS_API_SECRET:-}"
CHAOS_API_KEY="${CHAOS_API_KEY:-}"
CERTSPOTTER_KEY="${CERTSPOTTER_KEY:-}"
CRIMINALIP_KEY="${CRIMINALIP_KEY:-}"
DNSDUMPSTER_KEY="${DNSDUMPSTER_KEY:-}"
GOOGLE_CSE_KEY="${GOOGLE_CSE_KEY:-}"
GOOGLE_CX="${GOOGLE_CX:-}"
INTELX_KEY="${INTELX_KEY:-}"
LEAKIX_KEY="${LEAKIX_KEY:-}"
NETLAS_KEY="${NETLAS_KEY:-}"
URLSCAN_KEY="${URLSCAN_KEY:-}"
WHOISXMLAPI_KEY="${WHOISXMLAPI_KEY:-}"

# ── Hardcoded versions — zero API calls ──────────────────────────────
VER_GOWITNESS="v3.1.1"
VER_FEROXBUSTER="v2.13.1"
VER_TRUFFLEHOG="v3.88.27"
VER_GITLEAKS="v8.26.0"
VER_TRIVY="v0.63.0"
VER_X8="v4.3.0"
VER_FALLPARAMS="v2.1.0"
VER_CARIDDI="1.3.8"
VER_CRLFUZZ="1.4.1"
VER_METABIGOR="1.2.0"
VER_S3SCANNER="v3.3.0"

GRN='\033[0;32m'; YLW='\033[1;33m'; BLU='\033[0;34m'; NC='\033[0m'; STEP=0
step() { STEP=$((STEP+1)); echo -e "\n${BLU}[$STEP]${NC} ${GRN}$*${NC}"; }
ok()   { echo -e "  ${GRN}✓${NC} $*"; }
warn() { echo -e "  ${YLW}⚠${NC} $*"; }

# ── DOWNLOAD HELPERS ─────────────────────────────────────────────────
# timeout command + curl --max-time: double guarantee, never hangs.
# timeout 20 kills curl process after 20s regardless of what curl does.
# --max-time 18 is curl's own limit (slightly shorter as inner guard).
_curl() {
  timeout 20 curl -sL --connect-timeout 5 --max-time 18 --retry 0 "$@" 2>/dev/null
}

dl_bin() {
  local name=$1 url=$2 dst=${3:-/usr/local/bin/$1}
  echo -n "  → $name ..."
  if _curl "$url" -o "$dst"; then
    chmod +x "$dst"
    echo " ✓"
  else
    rm -f "$dst"
    echo " skip"
  fi
}

dl_tar() {
  local name=$1 url=$2 member=$3
  local tmp=/tmp/_dl_${name}.tgz
  echo -n "  → $name ..."
  if _curl "$url" -o "$tmp"; then
    tar xzf "$tmp" -C /usr/local/bin "$member" 2>/dev/null \
      || tar xzf "$tmp" --wildcards --no-anchored "*/$member" \
           --strip-components=1 -C /usr/local/bin 2>/dev/null || true
    chmod +x "/usr/local/bin/$member" 2>/dev/null || true
    rm -f "$tmp"
    echo " ✓"
  else
    rm -f "$tmp"
    echo " skip"
  fi
}

dl_zip() {
  local name=$1 url=$2 member=$3
  local tmp=/tmp/_dl_${name}.zip
  echo -n "  → $name ..."
  if _curl "$url" -o "$tmp"; then
    unzip -q -o "$tmp" -d /tmp/_unz_${name} 2>/dev/null || true
    find /tmp/_unz_${name} -maxdepth 3 -name "$member" -type f \
      -exec mv {} /usr/local/bin/${member} \; 2>/dev/null || true
    chmod +x "/usr/local/bin/$member" 2>/dev/null || true
    rm -rf "$tmp" "/tmp/_unz_${name}"
    echo " ✓"
  else
    rm -rf "$tmp" "/tmp/_unz_${name}"
    echo " skip"
  fi
}

[[ $EUID -ne 0 ]] && { echo "Run as root: sudo bash install.sh"; exit 1; }
export GIT_TERMINAL_PROMPT=0

# ── --seed-only: skip install, just sync keys to DB ──────────────────
# Usage: bash install.sh --seed-only
if [[ "${1:-}" == "--seed-only" ]]; then
  echo -e "${GRN}Seeding API keys → DB (app must be running on :8000)${NC}"
  _put_key() {
    local p=$1 v=$2; [[ -z "$v" ]] && return
    local r; r=$(curl -sf -X PUT "http://localhost:8000/api/v1/keys/$p" \
      -H "Content-Type: application/json" -d "{\"value\":\"$v\"}" 2>/dev/null)
    [[ "$r" == *"provider"* ]] && echo -e "  ${GRN}✓${NC} $p" || echo -e "  ${YLW}⚠${NC} $p"
  }
  _put_key github         "$GITHUB_TOKEN"
  _put_key securitytrails "$SECURITYTRAILS_KEY"
  _put_key shodan         "$SHODAN_API_KEY"
  _put_key virustotal     "$VIRUSTOTAL_KEY"
  _put_key bevigil        "$BEVIGIL_KEY"
  _put_key fofa           "$FOFA_KEY"
  _put_key chaos          "$CHAOS_API_KEY"
  _put_key certspotter    "$CERTSPOTTER_KEY"
  _put_key criminalip     "$CRIMINALIP_KEY"
  _put_key dnsdumpster    "$DNSDUMPSTER_KEY"
  _put_key google_cse     "$GOOGLE_CSE_KEY"
  _put_key google_cx      "$GOOGLE_CX"
  _put_key intelx         "$INTELX_KEY"
  _put_key leakix         "$LEAKIX_KEY"
  _put_key netlas         "$NETLAS_KEY"
  _put_key urlscan        "$URLSCAN_KEY"
  _put_key whoisxmlapi    "$WHOISXMLAPI_KEY"
  [[ -n "$CENSYS_API_ID" && -n "$CENSYS_API_SECRET" ]] && \
    _put_key censys "${CENSYS_API_ID}:${CENSYS_API_SECRET}"
  echo -e "${GRN}Done — 17 keys → http://localhost:8000/keys${NC}"
  exit 0
fi

echo -e "${GRN}K1NZR3C0N Installer v12 — $(date)${NC}"

# ══════════════════════════════════════════════════════════
# [1] System packages
# ══════════════════════════════════════════════════════════
step "System packages"  # s1
apt-get update -qq
apt-get install -y --no-install-recommends \
  python3 python3-pip git curl wget ca-certificates unzip \
  nmap libpcap-dev jq chromium \
  ssh-audit sslscan onesixtyone snmp \
  redis-server masscan \
  libssl-dev libnet-ssleay-perl perl \
  ruby ruby-dev build-essential make gcc \
  cloud-guest-utils 2>/dev/null || true
systemctl enable redis-server --now 2>/dev/null || true
ok "System packages done"

# ══════════════════════════════════════════════════════════
# [2] Go 1.24
# ══════════════════════════════════════════════════════════
step "Go runtime"  # s2
if ! command -v go &>/dev/null; then
  wget -q https://go.dev/dl/go1.24.0.linux-amd64.tar.gz -O /tmp/go.tar.gz
  rm -rf /usr/local/go
  tar -C /usr/local -xzf /tmp/go.tar.gz
  rm /tmp/go.tar.gz
  echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> /root/.bashrc
fi
export PATH=$PATH:/usr/local/go/bin:/root/go/bin
ok "Go $(go version | awk '{print $3}')"

# ══════════════════════════════════════════════════════════
# [3] Go tools  (~15 min first run, ~1 min if cached)
# ══════════════════════════════════════════════════════════
step "Go tools"  # s3
export CGO_ENABLED=0
GO_TOOLS=(
  github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  github.com/projectdiscovery/httpx/cmd/httpx@latest
  github.com/projectdiscovery/dnsx/cmd/dnsx@latest
  github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  github.com/projectdiscovery/chaos-client/cmd/chaos@latest
  github.com/projectdiscovery/katana/cmd/katana@latest
  github.com/projectdiscovery/tlsx/cmd/tlsx@latest
  github.com/projectdiscovery/alterx/cmd/alterx@latest
  github.com/projectdiscovery/uncover/cmd/uncover@latest
  github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
  github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest
  github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest
  github.com/projectdiscovery/asnmap/cmd/asnmap@latest
  github.com/projectdiscovery/notify/cmd/notify@latest
  github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
  github.com/projectdiscovery/cvemap/cmd/cvemap@latest
  github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest
  github.com/OJ/gobuster/v3@latest
  github.com/ffuf/ffuf/v2@latest
  github.com/tomnomnom/assetfinder@latest
  github.com/tomnomnom/waybackurls@latest
  github.com/lc/gau/v2/cmd/gau@latest
  github.com/tomnomnom/anew@latest
  github.com/tomnomnom/unfurl@latest
  github.com/tomnomnom/qsreplace@latest
  github.com/tomnomnom/meg@latest
  github.com/tomnomnom/gf@latest
  github.com/tomnomnom/httprobe@latest
  github.com/hakluke/hakrawler@latest
  github.com/hakluke/hakrevdns@latest
  github.com/d3mondev/puredns/v2@latest
  github.com/lc/subjs@latest
  github.com/Josue87/gotator@latest
  github.com/Emoe/kxss@latest
  github.com/lobuhi/byp4xx@latest
  github.com/haccer/subjack@latest
  github.com/ThreatUnkown/jsubfinder@latest
  github.com/bp0lr/gauplus@latest
  github.com/gwen001/github-subdomains@latest
  github.com/incogbyte/shosubgo@latest
  github.com/PentestPad/subzy@latest
  github.com/musana/fuzzuli@latest
)
for t in "${GO_TOOLS[@]}"; do
  n=$(basename "${t%%@*}")
  echo -n "  → $n ..."
  go install "$t" 2>/dev/null && echo " ok" || echo " skip"
done
CGO_ENABLED=1 go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest 2>/dev/null \
  && ok "naabu (CGO)" || warn "naabu skip (needs libpcap-dev)"
cp ~/go/bin/* /usr/local/bin/ 2>/dev/null || true
ok "Go tools → /usr/local/bin"

# ══════════════════════════════════════════════════════════
# [4] Pre-built binaries
#   • apt install first (fastest, no download)
#   • timeout 20 + --max-time 18 = guaranteed max 20s each
#   • if fails → print "skip" and continue; NEVER hangs
# ══════════════════════════════════════════════════════════
step "Pre-built binaries"  # s4

echo "  Installing from apt (fast)..."
apt-get install -y --no-install-recommends feroxbuster amass rustscan 2>/dev/null || true
ok "apt: feroxbuster amass rustscan"

# ── gowitness ────────────────────────────────────────────
dl_bin gowitness \
  "https://github.com/sensepost/gowitness/releases/download/${VER_GOWITNESS}/gowitness-${VER_GOWITNESS}-linux-amd64"

# ── feroxbuster (fallback if apt failed) ─────────────────
if ! command -v feroxbuster &>/dev/null; then
  dl_zip feroxbuster \
    "https://github.com/epi052/feroxbuster/releases/download/${VER_FEROXBUSTER}/x86_64-linux-feroxbuster.zip" \
    feroxbuster
else
  ok "feroxbuster (apt)"
fi

# ── findomain (direct binary, no zip) ────────────────────
dl_bin findomain \
  "https://github.com/Edu4rdSHL/findomain/releases/latest/download/findomain-linux"

# ── rustscan (fallback if apt failed) ────────────────────
if ! command -v rustscan &>/dev/null; then
  echo -n "  → rustscan ..."
  _curl "https://github.com/RustScan/RustScan/releases/download/2.3.0/rustscan_2.3.0_amd64.deb" \
    -o /tmp/_rustscan.deb
  dpkg -i /tmp/_rustscan.deb 2>/dev/null && echo " ✓" || echo " skip"
  rm -f /tmp/_rustscan.deb
else
  ok "rustscan (apt)"
fi

# ── kiterunner ───────────────────────────────────────────
echo -n "  → kiterunner ..."
if _curl "https://github.com/assetnote/kiterunner/releases/download/v1.0.2/kiterunner_1.0.2_linux_amd64.tar.gz" \
     -o /tmp/_kr.tgz; then
  tar xzf /tmp/_kr.tgz -C /tmp/_kr_out 2>/dev/null || mkdir -p /tmp/_kr_out
  tar xzf /tmp/_kr.tgz -C /tmp/_kr_out/ 2>/dev/null || true
  find /tmp/_kr_out -name 'kr' -type f -exec mv {} /usr/local/bin/kr \; 2>/dev/null
  chmod +x /usr/local/bin/kr 2>/dev/null; echo " ✓"
else
  echo " skip"
fi
rm -rf /tmp/_kr.tgz /tmp/_kr_out

# ── amass (fallback if apt failed) ───────────────────────
if ! command -v amass &>/dev/null; then
  echo -n "  → amass ..."
  if _curl "https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_linux_amd64.tar.gz" \
       -o /tmp/_amass.tgz; then
    mkdir -p /tmp/_amass_out
    tar xzf /tmp/_amass_out 2>/dev/null || true
    find /tmp/_amass_out -name 'amass' -type f -exec mv {} /usr/local/bin/amass \; 2>/dev/null
    chmod +x /usr/local/bin/amass 2>/dev/null; echo " ✓"
  else
    echo " skip"
  fi
  rm -rf /tmp/_amass.tgz /tmp/_amass_out
else
  ok "amass (apt)"
fi

# ── x8 ───────────────────────────────────────────────────
echo -n "  → x8 ..."
if _curl "https://github.com/sh1yo/x8/releases/download/${VER_X8}/x86_64-linux-x8.gz" \
     -o /tmp/_x8.gz; then
  gunzip -f /tmp/_x8.gz 2>/dev/null
  mv /tmp/_x8 /usr/local/bin/x8 2>/dev/null
  chmod +x /usr/local/bin/x8 2>/dev/null; echo " ✓"
else
  echo " skip"
fi

# ── fallparams ───────────────────────────────────────────
dl_zip fallparams \
  "https://github.com/ImAyrix/fallparams/releases/download/${VER_FALLPARAMS}/fallparams_${VER_FALLPARAMS#v}_linux_amd64.zip" \
  fallparams

# ── testssl (git clone, no binary download) ───────────────
echo -n "  → testssl ..."
if [[ ! -d /opt/testssl ]]; then
  git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl -q 2>/dev/null || true
fi
ln -sf /opt/testssl/testssl.sh /usr/local/bin/testssl 2>/dev/null
chmod +x /opt/testssl/testssl.sh 2>/dev/null || true
echo " ✓"

# ── gospider ─────────────────────────────────────────────
dl_zip gospider \
  "https://github.com/jaeles-project/gospider/releases/download/v1.2/gospider_v1.2_linux_amd64.zip" \
  gospider

# ── trufflehog ───────────────────────────────────────────
dl_tar trufflehog \
  "https://github.com/trufflesecurity/trufflehog/releases/download/${VER_TRUFFLEHOG}/trufflehog_${VER_TRUFFLEHOG#v}_linux_amd64.tar.gz" \
  trufflehog

# ── gitleaks ─────────────────────────────────────────────
dl_tar gitleaks \
  "https://github.com/gitleaks/gitleaks/releases/download/${VER_GITLEAKS}/gitleaks_${VER_GITLEAKS#v}_linux_x64.tar.gz" \
  gitleaks

# ── trivy ────────────────────────────────────────────────
dl_tar trivy \
  "https://github.com/aquasecurity/trivy/releases/download/${VER_TRIVY}/trivy_${VER_TRIVY#v}_Linux-64bit.tar.gz" \
  trivy

# ── cariddi ──────────────────────────────────────────────
dl_zip cariddi \
  "https://github.com/edoardottt/cariddi/releases/download/v${VER_CARIDDI}/cariddi_${VER_CARIDDI}_linux_amd64.zip" \
  cariddi

# ── crlfuzz ──────────────────────────────────────────────
dl_tar crlfuzz \
  "https://github.com/dwisiswant0/crlfuzz/releases/download/v${VER_CRLFUZZ}/crlfuzz_${VER_CRLFUZZ}_linux_amd64.tar.gz" \
  crlfuzz

# ── metabigor ────────────────────────────────────────────
dl_tar metabigor \
  "https://github.com/j3ssie/metabigor/releases/download/v${VER_METABIGOR}/metabigor_v${VER_METABIGOR}_linux_amd64.tar.gz" \
  metabigor

# ── S3Scanner ────────────────────────────────────────────
echo -n "  → S3Scanner ..."
if _curl "https://github.com/sa7mon/S3Scanner/releases/download/${VER_S3SCANNER}/S3Scanner_Linux_x86_64.tar.gz" \
     -o /tmp/_s3s.tgz; then
  mkdir -p /tmp/_s3s_out
  tar xzf /tmp/_s3s.tgz -C /tmp/_s3s_out 2>/dev/null || true
  find /tmp/_s3s_out -iname 's3scanner' -type f \
    -exec mv {} /usr/local/bin/s3scanner \; 2>/dev/null
  chmod +x /usr/local/bin/s3scanner 2>/dev/null; echo " ✓"
else
  echo " skip"
fi
rm -rf /tmp/_s3s.tgz /tmp/_s3s_out

# ── nikto (Kali pre-installed) ───────────────────────────
if command -v nikto &>/dev/null; then
  ok "nikto (pre-installed)"
else
  echo -n "  → nikto ..."
  git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto -q 2>/dev/null || true
  ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto 2>/dev/null
  chmod +x /opt/nikto/program/nikto.pl 2>/dev/null; echo " ✓"
fi

# ── searchsploit (Kali pre-installed) ────────────────────
if command -v searchsploit &>/dev/null; then
  ok "searchsploit (pre-installed)"
else
  echo -n "  → searchsploit ..."
  git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb -q 2>/dev/null || true
  ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit 2>/dev/null; echo " ✓"
fi

ok "Pre-built binaries done"

# ══════════════════════════════════════════════════════════
# [5] Python pip tools
# ══════════════════════════════════════════════════════════
step "Python pip tools"  # s5
pip3 install --break-system-packages -q \
  dirsearch sublist3r arjun sqlmap theHarvester waymore \
  paramspider dnsgen wafw00f sslyze shodan wfuzz \
  censys photon VHostScan 2>/dev/null || warn "some pip tools failed (ok)"
ok "Python tools"

# ══════════════════════════════════════════════════════════
# [6] Ruby tools
# ══════════════════════════════════════════════════════════
step "Ruby tools"  # s6
if command -v wpscan &>/dev/null; then
  ok "wpscan (pre-installed)"
else
  gem install wpscan --no-document 2>/dev/null && ok "wpscan" || warn "wpscan skip"
fi
if command -v whatweb &>/dev/null; then
  ok "whatweb (pre-installed)"
else
  git clone --depth 1 https://github.com/urbanadventurer/WhatWeb.git /opt/WhatWeb -q 2>/dev/null || true
  printf '#!/bin/sh\nexec ruby /opt/WhatWeb/whatweb "$@"\n' > /usr/local/bin/whatweb
  chmod +x /usr/local/bin/whatweb; ok "whatweb"
fi

# ══════════════════════════════════════════════════════════
# [7] Git-cloned Python tools
# ══════════════════════════════════════════════════════════
step "Git-cloned tools"  # s7
# clone_tool: GIT_TERMINAL_PROMPT=0 prevents credential prompts for private/deleted repos.
# timeout 30 git clone ensures git never hangs.
# || true on all pip3 so set -e doesn't abort if requirements missing.
clone_tool() {
  local repo=$1 dir=$2 bin=$3 main=$4
  echo -n "  → $bin ..."
  if [[ ! -d "$dir" ]]; then
    timeout 30 git clone --depth 1 "$repo" "$dir" -q 2>/dev/null || { echo " skip"; return; }
  fi
  [[ -f "$dir/requirements.txt" ]] && \
    pip3 install -r "$dir/requirements.txt" --break-system-packages -q 2>/dev/null || true
  printf "#!/bin/sh\nexec python3 %s/%s \"\$@\"\n" "$dir" "$main" > "/usr/local/bin/$bin"
  chmod +x "/usr/local/bin/$bin"; echo " ✓"
}
clone_tool https://github.com/GerbenJavado/LinkFinder.git              /opt/LinkFinder   linkfinder   linkfinder.py
clone_tool https://github.com/m4ll0k/SecretFinder.git                  /opt/SecretFinder secretfinder SecretFinder.py
clone_tool https://github.com/s0md3v/Corsy.git                         /opt/Corsy        corsy        corsy.py
clone_tool https://github.com/dolevf/graphw00f.git                     /opt/graphw00f    graphw00f    main.py
clone_tool https://github.com/initstring/cloud_enum.git                /opt/cloud_enum   cloud_enum   cloud_enum.py
clone_tool https://github.com/opsdisk/pagodo.git                       /opt/pagodo       pagodo       pagodo.py
clone_tool https://github.com/epinna/tplmap.git                        /opt/tplmap       tplmap       tplmap.py
clone_tool https://github.com/punk-security/dnsReaper.git              /opt/dnsReaper    dnsreaper    main.py

echo -n "  → swaggerspy ..."
if [[ ! -d /opt/SwaggerSpy ]]; then
  timeout 30 git clone --depth 1 https://github.com/UndeadSec/SwaggerSpy.git /opt/SwaggerSpy -q 2>/dev/null || true
fi
# Upstream swaggerspy.py ships with a SyntaxError (missing comma after the
# JIRA regex entry). Wrapper patches a runtime COPY so git pull keeps working.
cat > /opt/SwaggerSpy/_k1nz_patch.py <<'SPYPATCH'
import sys
path = sys.argv[1] if len(sys.argv) > 1 else 'swaggerspy.py'
s = open(path).read()
orig = s
s = s.replace("r'ATATTAC[a-zA-Z0-9]{24,48}'\n", "r'ATATTAC[a-zA-Z0-9]{24,48}',\n")
s = s.replace("'possible_Creds' : r'(?i)(\" \\", "'possible_Creds' : r'(?i)(\\")
if s != orig:
    open(path, 'w').write(s)
SPYPATCH
cat > /usr/local/bin/swaggerspy <<'SPYWRAP'
#!/bin/sh
SRC=/opt/SwaggerSpy/swaggerspy.py
[ -f "$SRC" ] || { echo "swaggerspy: $SRC not found"; exit 1; }
RUN=/tmp/swaggerspy_k1nz_$$.py
cp "$SRC" "$RUN"
python3 /opt/SwaggerSpy/_k1nz_patch.py "$RUN" 2>/dev/null || true
python3 "$RUN" "$@"
rc=$?
rm -f "$RUN"
exit $rc
SPYWRAP
chmod +x /usr/local/bin/swaggerspy; echo " ✓"

echo -n "  → nosqlmap ..."
if [[ ! -d /opt/NoSQLMap ]]; then
  timeout 30 git clone --depth 1 https://github.com/codingo/NoSQLMap.git /opt/NoSQLMap -q 2>/dev/null || true
fi
if [[ -d /opt/NoSQLMap ]]; then
  pip3 install -r /opt/NoSQLMap/requirements.txt --break-system-packages -q 2>/dev/null || true
  printf '#!/bin/sh\nexec python3 /opt/NoSQLMap/nosqlmap.py "$@"\n' > /usr/local/bin/nosqlmap
  chmod +x /usr/local/bin/nosqlmap; echo " ✓"
else
  echo " skip"
fi

echo -n "  → ghauri ..."
if [[ ! -d /opt/ghauri ]]; then
  timeout 30 git clone --depth 1 https://github.com/r0oth3x49/ghauri.git /opt/ghauri -q 2>/dev/null || true
fi
if [[ -d /opt/ghauri ]]; then
  pip3 install /opt/ghauri/ --no-deps --break-system-packages -q 2>/dev/null || true; echo " ✓"
else
  echo " skip"
fi

echo -n "  → OneForAll ..."
if [[ ! -d /opt/OneForAll ]]; then
  timeout 60 git clone --depth 1 https://github.com/shmilylty/OneForAll.git /opt/OneForAll -q 2>/dev/null || true
fi
if [[ -d /opt/OneForAll ]]; then
  pip3 install -r /opt/OneForAll/requirements.txt --break-system-packages -q 2>/dev/null || true; echo " ✓"
else
  echo " skip"
fi

ok "Git tools done"

# ══════════════════════════════════════════════════════════
# [8] massdns
# ══════════════════════════════════════════════════════════
step "massdns"  # s8
if command -v massdns &>/dev/null; then
  ok "massdns (exists)"
else
  [[ -d /opt/massdns ]] || git clone --depth 1 https://github.com/blechschmidt/massdns.git /opt/massdns -q
  make -C /opt/massdns -s && cp /opt/massdns/bin/massdns /usr/local/bin/ && ok "massdns"
fi

# ══════════════════════════════════════════════════════════
# [9] Wordlists
# ══════════════════════════════════════════════════════════
step "Wordlists"  # s9
WL="$APP_DIR/wordlists"
mkdir -p "$WL"
dl_wl() {
  local url=$1 file=$2
  if [[ -f "$WL/$file" ]]; then
    echo "  ↷ $file (exists)"
    return
  fi
  echo -n "  → $file ..."
  if _curl "$url" -o "$WL/$file"; then
    echo " ✓"
  else
    rm -f "$WL/$file"; echo " skip"
  fi
}
dl_wl https://github.com/kienzx203/Lab_research_tools_k1nz/releases/download/tools/common.txt                                        common.txt
dl_wl https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt               subdomains-top1million-20000.txt
dl_wl https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt              subdomains-top1million-110000.txt
dl_wl https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/dns-Jhaddix.txt                                dns-Jhaddix.txt
dl_wl https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/namelist.txt                                   namelist.txt
dl_wl https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt                                                          best-dns-wordlist.txt
dl_wl https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt            raft-medium-directories.txt
dl_wl https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-files.txt                  raft-medium-files.txt
dl_wl https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt               burp-parameter-names.txt
dl_wl https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/SNMP/snmp-default-community-strings-onesixtyone.txt snmp-default-communities.txt
dl_wl https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt                                                        resolvers-trickest.txt
find /usr -path '*/arjun/db/medium.txt' -exec cp {} "$WL/params-medium.txt" \; 2>/dev/null || true
find /usr -path '*/arjun/db/large.txt'  -exec cp {} "$WL/params-large.txt"  \; 2>/dev/null || true
ok "Wordlists done"

# ══════════════════════════════════════════════════════════
# [10] App
# ══════════════════════════════════════════════════════════
step "App setup"  # s10
mkdir -p "$APP_DIR" "$APP_DIR/runs" /var/lib/k1nzr3c0n/celerybeat
if [[ -n "$APP_REPO" ]]; then
  if [[ -d "$APP_DIR/.git" ]]; then
    git -C "$APP_DIR" pull -q
  else
    git clone "$APP_REPO" "$APP_DIR" -q
  fi
  ok "Repo cloned"
else
  warn "APP_REPO empty — copy project files to $APP_DIR manually, then re-run from step 10"
fi
if [[ -f "$APP_DIR/requirements.txt" ]]; then
  # --ignore-installed: skip uninstalling Debian-managed packages (idna, etc.)
  # || true: never abort even if some packages fail
  pip3 install -r "$APP_DIR/requirements.txt" croniter \
    --break-system-packages --ignore-installed -q 2>/dev/null || true
  pip3 install -e "$APP_DIR" --no-deps --break-system-packages -q 2>/dev/null || true
  ok "Python app installed"
fi
# ── /app symlink — backward compat for any remaining /app/ refs ──────
[[ ! -e /app ]] && ln -sf "$APP_DIR" /app && ok "/app → $APP_DIR symlink" || ok "/app exists"

# Restore Go httpx (pip httpx package overwrites it)
[[ -f ~/go/bin/httpx ]] && cp ~/go/bin/httpx /usr/local/bin/httpx && ok "Go httpx restored"
# Chromium wrapper for root
printf '#!/bin/sh\nexec chromium --no-sandbox --disable-gpu "$@"\n' > /usr/local/bin/chromium-server
chmod +x /usr/local/bin/chromium-server; ok "chromium-server wrapper"

# ── opencode (AI terminal at :4040) ──────────────────────
# Binary: /root/.opencode/bin/opencode
# Config: ~/.config/opencode/opencode.jsonc  ← OPENROUTER_API_KEY
echo -n "  → opencode ..."
if [[ ! -f /root/.opencode/bin/opencode ]]; then
  curl -fsSL https://opencode.ai/install | bash 2>/dev/null && echo " ✓" || echo " skip"
else
  echo " ✓ (exists)"
fi
# Write opencode config with OPENROUTER key
mkdir -p ~/.config/opencode
cat > ~/.config/opencode/opencode.jsonc << OPENCODEEOF
{
  // opencode AI config — managed by k1nzr3c0n install script
  "provider": {
    "openrouter": {
      "apiKey": "$OPENROUTER_API_KEY"
    }
  }
}
OPENCODEEOF
ok "opencode config → ~/.config/opencode/opencode.jsonc"

# ══════════════════════════════════════════════════════════
# [11] Node.js + Frontend
# ══════════════════════════════════════════════════════════
step "Node.js + Frontend"  # s11
if ! command -v node &>/dev/null; then
  curl -fsSL https://deb.nodesource.com/setup_22.x | bash - -q 2>/dev/null
  apt-get install -y --no-install-recommends nodejs -q 2>/dev/null
fi
ok "Node $(node --version 2>/dev/null || echo unknown)"
if [[ -d "$APP_DIR/frontend" ]]; then
  cd "$APP_DIR/frontend"
  npm install -q 2>/dev/null
  npm run build -- --outDir "$APP_DIR/static" 2>/dev/null && ok "Frontend built"
  cd -
else
  warn "No frontend/ dir — build after copying project files"
fi

# ══════════════════════════════════════════════════════════
# [12] .env
# ══════════════════════════════════════════════════════════
step ".env config"  # s12
cat > "$APP_DIR/.env" << ENVEOF
K1NZR3C0N_BASE=$APP_DIR
REDIS_URL=redis://127.0.0.1:6379/0
PYTHONUNBUFFERED=1
CHROME_PATH=/usr/local/bin/chromium-server
GITHUB_TOKEN=$GITHUB_TOKEN
OPENROUTER_API_KEY=$OPENROUTER_API_KEY
SECURITYTRAILS_KEY=$SECURITYTRAILS_KEY
SHODAN_API_KEY=$SHODAN_API_KEY
VIRUSTOTAL_KEY=$VIRUSTOTAL_KEY
BEVIGIL_KEY=$BEVIGIL_KEY
FOFA_KEY=$FOFA_KEY
CENSYS_API_ID=$CENSYS_API_ID
CENSYS_API_SECRET=$CENSYS_API_SECRET
CHAOS_API_KEY=$CHAOS_API_KEY
ENVEOF
chmod 600 "$APP_DIR/.env"
ok ".env written → $APP_DIR/.env"

# ══════════════════════════════════════════════════════════
# [13] Systemd services
# ══════════════════════════════════════════════════════════
step "Systemd services"  # s13
make_svc() {
  cat > "/etc/systemd/system/$1.service" << EOF
[Unit]
Description=$2
After=network.target redis.service
Requires=redis.service
[Service]
Type=simple
User=root
WorkingDirectory=$APP_DIR
EnvironmentFile=$APP_DIR/.env
ExecStart=$3
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal
[Install]
WantedBy=multi-user.target
EOF
}
make_svc k1nzr3c0n-app    "K1NZR3C0N API"    "uvicorn k1nzr3c0n.api.main:app --host 0.0.0.0 --port 8000"
make_svc k1nzr3c0n-worker "K1NZR3C0N Worker" "celery -A k1nzr3c0n.tasks worker --loglevel=info --concurrency=4"
make_svc k1nzr3c0n-beat   "K1NZR3C0N Beat"   "celery -A k1nzr3c0n.tasks beat --loglevel=info --scheduler celery.beat:PersistentScheduler --schedule /var/lib/k1nzr3c0n/celerybeat/schedule"
systemctl daemon-reload
systemctl enable redis-server k1nzr3c0n-app k1nzr3c0n-worker k1nzr3c0n-beat 2>/dev/null || true
ok "3 services created + enabled"

# ══════════════════════════════════════════════════════════
# [14] Post-install
# ══════════════════════════════════════════════════════════
step "Post-install"  # s14
nuclei -update-templates -silent 2>/dev/null || true; ok "nuclei templates updated"
mkdir -p ~/.gf
git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns.git /tmp/_gf_pat -q 2>/dev/null || true
cp /tmp/_gf_pat/*.json ~/.gf/ 2>/dev/null || true; rm -rf /tmp/_gf_pat; ok "gf patterns"

# ── Start services ────────────────────────────────────────
systemctl daemon-reload
systemctl start k1nzr3c0n-app k1nzr3c0n-worker k1nzr3c0n-beat 2>/dev/null || true
ok "Services started"

# ── Seed API keys into SQLite DB via REST ────────────────
# /keys page reads DB, not .env → must PUT each key via API.
# Idempotent: upserts existing rows, safe to re-run.
_put_key() {
  local p=$1 v=$2
  [[ -z "$v" ]] && return
  local r; r=$(curl -sf -X PUT "http://localhost:8000/api/v1/keys/$p" \
    -H "Content-Type: application/json" \
    -d "{\"value\":\"$v\"}" 2>/dev/null)
  [[ "$r" == *"provider"* ]] && ok "DB ← $p" || warn "DB ← $p (failed — enter at /keys)"
}
_seed_all_keys() {
  _put_key github         "$GITHUB_TOKEN"
  _put_key securitytrails "$SECURITYTRAILS_KEY"
  _put_key shodan         "$SHODAN_API_KEY"
  _put_key virustotal     "$VIRUSTOTAL_KEY"
  _put_key bevigil        "$BEVIGIL_KEY"
  _put_key fofa           "$FOFA_KEY"
  _put_key chaos          "$CHAOS_API_KEY"
  _put_key certspotter    "$CERTSPOTTER_KEY"
  _put_key criminalip     "$CRIMINALIP_KEY"
  _put_key dnsdumpster    "$DNSDUMPSTER_KEY"
  _put_key google_cse     "$GOOGLE_CSE_KEY"
  _put_key google_cx      "$GOOGLE_CX"
  _put_key intelx         "$INTELX_KEY"
  _put_key leakix         "$LEAKIX_KEY"
  _put_key netlas         "$NETLAS_KEY"
  _put_key urlscan        "$URLSCAN_KEY"
  _put_key whoisxmlapi    "$WHOISXMLAPI_KEY"
  [[ -n "$CENSYS_API_ID" && -n "$CENSYS_API_SECRET" ]] && \
    _put_key censys "${CENSYS_API_ID}:${CENSYS_API_SECRET}"
}

echo -n "  Waiting for app (max 40s)"
_rdy=0
for i in $(seq 1 40); do
  curl -sf http://localhost:8000/api/v1/keys/stats &>/dev/null && { _rdy=1; break; }
  sleep 1; echo -n "."
done
if [[ $_rdy -eq 1 ]]; then
  echo " ready"
  _seed_all_keys
  ok "Keys synced to DB → http://localhost:8000/keys"
else
  echo ""
  warn "App not ready — seed manually after start: bash install.sh --seed-only"
fi


echo -e "
${GRN}╔════════════════════════════════════════╗
║   K1NZR3C0N Install Complete!          ║
╚════════════════════════════════════════╝${NC}

Open: ${BLU}http://$(hostname -I | awk '{print $1}'):8000${NC}
Keys: ${BLU}http://$(hostname -I | awk '{print $1}'):8000/keys${NC}

${YLW}Useful commands:${NC}
  systemctl status k1nzr3c0n-app
  journalctl -u k1nzr3c0n-worker -f
"
df -h /