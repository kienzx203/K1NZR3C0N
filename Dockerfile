# ── Stage 1: Build Go tools ──────────────────────────────────────────────────
FROM golang:1.24-bookworm AS gobuilder

ENV GOPATH=/root/go
ENV CGO_ENABLED=0
ENV GOTOOLCHAIN=auto

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# ProjectDiscovery
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
RUN go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
RUN go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest
RUN go install github.com/projectdiscovery/katana/cmd/katana@latest

# Other tools
RUN go install github.com/OJ/gobuster/v3@latest
RUN go install github.com/ffuf/ffuf/v2@latest
RUN go install github.com/tomnomnom/assetfinder@latest
RUN go install github.com/tomnomnom/waybackurls@latest
RUN go install github.com/lc/gau/v2/cmd/gau@latest

# Optional (will not block build if they fail)
RUN go install github.com/PentestPad/subzy@latest               || true
RUN go install github.com/musana/fuzzuli@latest                  || true
RUN go install github.com/zan8in/afrog/v3/cmd/afrog@latest       || true

# ProjectDiscovery — new tools
RUN go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest              || true
RUN go install github.com/projectdiscovery/alterx/cmd/alterx@latest          || true
RUN go install github.com/projectdiscovery/uncover/cmd/uncover@latest        || true
RUN go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest || true
RUN go install github.com/projectdiscovery/cvemap/cmd/cvemap@latest          || true

# ProjectDiscovery — recon utilities
RUN go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest  || true
RUN go install github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest        || true
RUN go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest      || true
RUN go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest          || true
RUN go install github.com/projectdiscovery/notify/cmd/notify@latest          || true

# Offensive + utility tools
RUN go install github.com/hahwul/dalfox/v2@latest               || true
RUN go install github.com/tomnomnom/anew@latest                  || true
RUN go install github.com/hakluke/hakrawler@latest               || true
RUN go install github.com/d3mondev/puredns/v2@latest             || true

# Bug bounty JS/URL pipeline utilities
RUN go install github.com/lc/subjs@latest                        || true
RUN go install github.com/tomnomnom/unfurl@latest                || true
RUN go install github.com/tomnomnom/qsreplace@latest             || true
RUN go install github.com/tomnomnom/meg@latest                   || true
RUN go install github.com/Josue87/gotator@latest                 || true

# Bug bounty recon — tomnomnom tools
RUN go install github.com/tomnomnom/gf@latest                    || true
RUN go install github.com/tomnomnom/httprobe@latest              || true

# Bug bounty recon — hakluke tools
RUN go install github.com/hakluke/hakrevdns@latest               || true

# Bug bounty recon — XSS / 403 / subdomain
RUN go install github.com/Emoe/kxss@latest                       || true
RUN go install github.com/lobuhi/byp4xx@latest                   || true
RUN go install github.com/haccer/subjack@latest                  || true
RUN go install github.com/ThreatUnkown/jsubfinder@latest         || true
RUN go install github.com/bp0lr/gauplus@latest                   || true

# ProjectDiscovery — urlfinder
RUN go install github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest || true

# fallparams has CGO tree-sitter dependency — installed via pre-built binary in runtime stage


# ── Stage 2: Build React frontend ────────────────────────────────────────────
FROM node:22-slim AS uibuilder

WORKDIR /ui
COPY frontend/package*.json ./
RUN npm install --prefer-offline

COPY frontend/ ./
RUN npm run build -- --outDir /ui/dist


# ── Stage 3: Runtime image ────────────────────────────────────────────────────
FROM debian:bookworm-slim

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip \
    git curl wget ca-certificates unzip \
    nmap libpcap-dev \
    jq \
    chromium \
    ssh-audit sslscan \
    onesixtyone snmp \
    redis-tools \
    masscan \
    libssl-dev libnet-ssleay-perl perl \
    && ln -sf /usr/bin/python3 /usr/local/bin/python \
    && rm -rf /var/lib/apt/lists/*

# nikto — not in Debian bookworm apt, install via git clone
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /opt/nikto/program/nikto.pl \
    || echo "[warn] nikto install failed"

# exploitdb (searchsploit) — not in Debian bookworm apt, install via git clone
RUN git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb \
    && ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit \
    && chmod +x /opt/exploitdb/searchsploit \
    || echo "[warn] exploitdb install failed"

# Chromium wrapper: Docker containers need --no-sandbox (no user-namespace support).
# gowitness --chrome-path points at this wrapper so --no-sandbox is always injected.
RUN printf '#!/bin/sh\nexec /usr/bin/chromium --no-sandbox --disable-gpu "$@"\n' \
    > /usr/local/bin/chromium-docker && chmod +x /usr/local/bin/chromium-docker

# ── gowitness v3 pre-built binary ─────────────────────────────────────────────
RUN GW_VER=$(curl -s https://api.github.com/repos/sensepost/gowitness/releases/latest \
      | grep '"tag_name"' | cut -d'"' -f4) \
    && curl -sL "https://github.com/sensepost/gowitness/releases/download/${GW_VER}/gowitness-${GW_VER}-linux-amd64" \
       -o /usr/local/bin/gowitness \
    && chmod +x /usr/local/bin/gowitness \
    || echo "[warn] gowitness download failed — screenshots disabled"

# Copy Go binaries from stage 1 (subfinder, httpx, dnsx, naabu, nuclei, chaos,
# katana, gobuster, ffuf, assetfinder, waybackurls, gau, subzy, fuzzuli, afrog, fallparams)
COPY --from=gobuilder /root/go/bin/ /usr/local/bin/

ENV PATH=/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin

# ── feroxbuster ──────────────────────────────────────────────────────────────
RUN FEROX_VER=$(curl -s https://api.github.com/repos/epi052/feroxbuster/releases/latest \
      | grep '"tag_name"' | cut -d'"' -f4) \
    && curl -sL "https://github.com/epi052/feroxbuster/releases/download/${FEROX_VER}/x86_64-linux-feroxbuster.zip" \
       -o /tmp/ferox.zip \
    && unzip /tmp/ferox.zip feroxbuster -d /usr/local/bin \
    && chmod +x /usr/local/bin/feroxbuster \
    && rm /tmp/ferox.zip

# ── findomain ────────────────────────────────────────────────────────────────
RUN curl -sL "https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip" \
      -o /tmp/findomain.zip \
    && unzip /tmp/findomain.zip -d /usr/local/bin \
    && chmod +x /usr/local/bin/findomain \
    && rm /tmp/findomain.zip

# ── rustscan ─────────────────────────────────────────────────────────────────
RUN curl -sL "https://github.com/RustScan/RustScan/releases/download/2.3.0/rustscan_2.3.0_amd64.deb" \
      -o /tmp/rustscan.deb \
    && dpkg -i /tmp/rustscan.deb \
    && rm /tmp/rustscan.deb

# ── kiterunner (API route discovery using Assetnote wordlists) ───────────────
RUN curl -sL "https://github.com/assetnote/kiterunner/releases/download/v1.0.2/kiterunner_1.0.2_linux_amd64.tar.gz" \
       -o /tmp/kr.tar.gz \
    && tar xzf /tmp/kr.tar.gz -C /tmp/ \
    && find /tmp -maxdepth 2 -name 'kr' -type f -exec mv {} /usr/local/bin/kr \; \
    && chmod +x /usr/local/bin/kr \
    && rm -f /tmp/kr.tar.gz \
    || echo "[warn] kiterunner download failed — API route discovery disabled"

# ── amass (OWASP passive subdomain enum) ─────────────────────────────────────
RUN AMASS_VER=$(curl -s https://api.github.com/repos/owasp-amass/amass/releases/latest \
      | grep '"tag_name"' | cut -d'"' -f4) \
    && curl -sL "https://github.com/owasp-amass/amass/releases/download/${AMASS_VER}/amass_linux_amd64.tar.gz" \
       -o /tmp/amass.tar.gz \
    && tar xzf /tmp/amass.tar.gz -C /tmp \
    && find /tmp -name 'amass' -type f -exec mv {} /usr/local/bin/amass \; \
    && chmod +x /usr/local/bin/amass \
    && rm -rf /tmp/amass.tar.gz /tmp/amass_linux_amd64 \
    || echo "[warn] amass download failed — passive subdomain enum disabled"

# ── x8 (diff-based hidden parameter discovery, Rust) ─────────────────────────
RUN X8_VER=$(curl -s https://api.github.com/repos/sh1yo/x8/releases/latest \
      | grep '"tag_name"' | cut -d'"' -f4 | head -1) \
    && curl -sL "https://github.com/sh1yo/x8/releases/download/${X8_VER}/x86_64-linux-x8.gz" \
       -o /tmp/x8.gz \
    && gunzip /tmp/x8.gz \
    && mv /tmp/x8 /usr/local/bin/x8 \
    && chmod +x /usr/local/bin/x8 \
    || echo "[warn] x8 install failed — diff-based param discovery disabled"

# ── fallparams (CGO dep — use pre-built binary from zip release) ──────────────
RUN FP_VER=$(curl -s https://api.github.com/repos/ImAyrix/fallparams/releases/latest \
      | grep '"tag_name"' | cut -d'"' -f4 | head -1) \
    && curl -sL "https://github.com/ImAyrix/fallparams/releases/download/${FP_VER}/fallparams_${FP_VER#v}_linux_amd64.zip" \
       -o /tmp/fp.zip \
    && unzip -q /tmp/fp.zip fallparams -d /usr/local/bin \
    && chmod +x /usr/local/bin/fallparams \
    && rm -f /tmp/fp.zip \
    || echo "[warn] fallparams install failed — param discovery will use arjun+x8 only"

# ── testssl.sh (comprehensive TLS testing script) ────────────────────────────
RUN TESTSSL_VER=$(curl -s https://api.github.com/repos/drwetter/testssl.sh/releases/latest \
      | grep '"tag_name"' | cut -d'"' -f4) \
    && curl -sL "https://github.com/drwetter/testssl.sh/releases/download/${TESTSSL_VER}/testssl.sh-${TESTSSL_VER}.tar.gz" \
       -o /tmp/testssl.tar.gz \
    && mkdir -p /tmp/testssl_ext \
    && tar xzf /tmp/testssl.tar.gz -C /tmp/testssl_ext \
    && find /tmp/testssl_ext -name 'testssl.sh' -exec mv {} /usr/local/bin/testssl \; \
    && chmod +x /usr/local/bin/testssl \
    && rm -rf /tmp/testssl.tar.gz /tmp/testssl_ext \
    || echo "[warn] testssl.sh install failed — SSL audit will use sslscan only"

# ── gospider (fast web spider) ────────────────────────────────────────────────
RUN GS_VER=$(curl -s https://api.github.com/repos/jaeles-project/gospider/releases/latest \
      | grep '"tag_name"' | cut -d'"' -f4) \
    && curl -sL "https://github.com/jaeles-project/gospider/releases/download/${GS_VER}/gospider_${GS_VER}_linux_amd64.zip" \
       -o /tmp/gospider.zip \
    && unzip -q /tmp/gospider.zip -d /tmp/gospider_ext \
    && find /tmp/gospider_ext -name 'gospider' -type f -exec mv {} /usr/local/bin/gospider \; \
    && chmod +x /usr/local/bin/gospider \
    && rm -rf /tmp/gospider.zip /tmp/gospider_ext \
    || echo "[warn] gospider install failed"

# ── trufflehog (secret / credential scanner) ─────────────────────────────────
RUN TH_VER=$(curl -s https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest \
      | grep '"tag_name"' | cut -d'"' -f4) \
    && VER=$(echo "$TH_VER" | sed 's/^v//') \
    && [ -n "$VER" ] \
    && curl -sL "https://github.com/trufflesecurity/trufflehog/releases/download/${TH_VER}/trufflehog_${VER}_linux_amd64.tar.gz" \
       -o /tmp/trufflehog.tar.gz \
    && tar xzf /tmp/trufflehog.tar.gz -C /usr/local/bin trufflehog \
    && chmod +x /usr/local/bin/trufflehog \
    && rm -f /tmp/trufflehog.tar.gz \
    || echo "[warn] trufflehog install failed — secret scanning disabled"

# ── gitleaks (git secret scanner) ────────────────────────────────────────────
RUN GL_VER=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest \
      | grep '"tag_name"' | cut -d'"' -f4) \
    && curl -sL "https://github.com/gitleaks/gitleaks/releases/download/${GL_VER}/gitleaks_${GL_VER#v}_linux_x64.tar.gz" \
       -o /tmp/gitleaks.tar.gz \
    && tar xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks \
    && chmod +x /usr/local/bin/gitleaks \
    && rm -f /tmp/gitleaks.tar.gz \
    || echo "[warn] gitleaks install failed"

# ── trivy (container / cloud / IaC vulnerability scanner) ────────────────────
RUN TRIVY_VER=$(curl -s https://api.github.com/repos/aquasecurity/trivy/releases/latest \
      | grep '"tag_name"' | cut -d'"' -f4) \
    && curl -sL "https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VER}/trivy_${TRIVY_VER#v}_Linux-64bit.tar.gz" \
       -o /tmp/trivy.tar.gz \
    && tar xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy \
    && chmod +x /usr/local/bin/trivy \
    && rm -f /tmp/trivy.tar.gz \
    || echo "[warn] trivy install failed"

# ── cariddi (web crawler + secret/endpoint detection) ────────────────────────
RUN CARIDDI_VER=$(curl -s https://api.github.com/repos/edoardottt/cariddi/releases/latest \
      | grep '"tag_name"' | cut -d'"' -f4 | sed 's/^v//') \
    && curl -sL "https://github.com/edoardottt/cariddi/releases/download/v${CARIDDI_VER}/cariddi_${CARIDDI_VER}_linux_amd64.zip" \
       -o /tmp/cariddi.zip \
    && unzip -q /tmp/cariddi.zip cariddi -d /usr/local/bin \
    && chmod +x /usr/local/bin/cariddi \
    && rm -f /tmp/cariddi.zip \
    || echo "[warn] cariddi install failed"

# ── jaeles (signature-based web scanner) ─────────────────────────────────────
RUN curl -sL "$(curl -s https://api.github.com/repos/jaeles-project/jaeles/releases/latest \
      | grep '"browser_download_url"' | grep 'linux' | cut -d'"' -f4 | head -1)" \
       -o /tmp/jaeles.zip \
    && unzip -q /tmp/jaeles.zip -d /tmp/jaeles_ext \
    && find /tmp/jaeles_ext -name 'jaeles' -type f -exec mv {} /usr/local/bin/jaeles \; \
    && chmod +x /usr/local/bin/jaeles \
    && rm -rf /tmp/jaeles.zip /tmp/jaeles_ext \
    || echo "[warn] jaeles install failed"

# ── crlfuzz (CRLF injection scanner) ─────────────────────────────────────────
RUN CRLFUZZ_VER=$(curl -s https://api.github.com/repos/dwisiswant0/crlfuzz/releases/latest \
      | grep '"tag_name"' | cut -d'"' -f4 | sed 's/^v//') \
    && curl -sL "https://github.com/dwisiswant0/crlfuzz/releases/download/v${CRLFUZZ_VER}/crlfuzz_${CRLFUZZ_VER}_linux_amd64.tar.gz" \
       -o /tmp/crlfuzz.tar.gz \
    && tar xzf /tmp/crlfuzz.tar.gz -C /usr/local/bin crlfuzz \
    && chmod +x /usr/local/bin/crlfuzz \
    && rm -f /tmp/crlfuzz.tar.gz \
    || echo "[warn] crlfuzz install failed"

# ── metabigor (OSINT meta tool) ───────────────────────────────────────────────
RUN META_VER=$(curl -s https://api.github.com/repos/j3ssie/metabigor/releases/latest \
      | grep '"tag_name"' | cut -d'"' -f4 | sed 's/^v//') \
    && curl -sL "https://github.com/j3ssie/metabigor/releases/download/v${META_VER}/metabigor_v${META_VER}_linux_amd64.tar.gz" \
       -o /tmp/metabigor.tar.gz \
    && tar xzf /tmp/metabigor.tar.gz -C /usr/local/bin metabigor \
    && chmod +x /usr/local/bin/metabigor \
    && rm -f /tmp/metabigor.tar.gz \
    || echo "[warn] metabigor install failed"

# ── cero (TLS SAN extractor) ──────────────────────────────────────────────────
RUN curl -sL "$(curl -s https://api.github.com/repos/glebarez/cero/releases/latest \
      | grep '"browser_download_url"' | grep 'linux-amd64' | grep -v '.sha' | cut -d'"' -f4 | head -1)" \
       -o /usr/local/bin/cero \
    && chmod +x /usr/local/bin/cero \
    || echo "[warn] cero install failed"

# ── gxss (reflected XSS sink detector) ───────────────────────────────────────
RUN GXSS_VER=$(curl -s https://api.github.com/repos/KathanP19/Gxss/releases/latest \
      | grep '"tag_name"' | cut -d'"' -f4 | sed 's/^v//') \
    && curl -sL "https://github.com/KathanP19/Gxss/releases/download/v${GXSS_VER}/Gxss_${GXSS_VER}_Linux_x86_64.tar.gz" \
       -o /tmp/gxss.tar.gz \
    && tar xzf /tmp/gxss.tar.gz -C /tmp \
    && find /tmp -maxdepth 3 -name 'Gxss' -type f -exec mv {} /usr/local/bin/gxss \; \
    && chmod +x /usr/local/bin/gxss \
    && rm -f /tmp/gxss.tar.gz \
    || echo "[warn] gxss install failed"

# ── dnstake (DNS takeover detection) ─────────────────────────────────────────
RUN DNSTAKE_VER=$(curl -s https://api.github.com/repos/pwnesia/dnstake/releases/latest \
      | grep '"tag_name"' | cut -d'"' -f4 | sed 's/^v//') \
    && curl -sL "https://github.com/pwnesia/dnstake/releases/download/v${DNSTAKE_VER}/dnstake_${DNSTAKE_VER}_linux_amd64.tar.gz" \
       -o /tmp/dnstake.tar.gz \
    && tar xzf /tmp/dnstake.tar.gz -C /usr/local/bin dnstake \
    && chmod +x /usr/local/bin/dnstake \
    && rm -f /tmp/dnstake.tar.gz \
    || echo "[warn] dnstake install failed"

# ── jsapiscan (JS API endpoint extractor) ────────────────────────────────────
RUN JSAPI_VER=$(curl -s https://api.github.com/repos/ruisika/jsapiscan/releases/latest \
      | grep '"tag_name"' | cut -d'"' -f4) \
    && curl -sL "https://github.com/ruisika/jsapiscan/releases/download/${JSAPI_VER}/JSAPIscan_linux_amd64" \
       -o /usr/local/bin/jsapiscan \
    && chmod +x /usr/local/bin/jsapiscan \
    || echo "[warn] jsapiscan install failed"

# ── S3Scanner (open cloud storage bucket scanner) ────────────────────────────
RUN S3S_VER=$(curl -s https://api.github.com/repos/sa7mon/S3Scanner/releases/latest \
      | grep '"tag_name"' | cut -d'"' -f4) \
    && curl -sL "https://github.com/sa7mon/S3Scanner/releases/download/${S3S_VER}/S3Scanner_Linux_x86_64.tar.gz" \
       -o /tmp/s3scanner.tar.gz \
    && tar xzf /tmp/s3scanner.tar.gz -C /tmp \
    && find /tmp -maxdepth 3 -name 'S3Scanner' -type f -exec mv {} /usr/local/bin/s3scanner \; \
    && chmod +x /usr/local/bin/s3scanner \
    && rm -f /tmp/s3scanner.tar.gz \
    || echo "[warn] S3Scanner install failed"

# ── Ruby gems: WPScan ────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends ruby ruby-dev build-essential \
    && rm -rf /var/lib/apt/lists/* \
    && gem install wpscan --no-document 2>/dev/null \
    || echo "[warn] wpscan install failed"

# ── Python tools ─────────────────────────────────────────────────────────────
RUN pip3 install dirsearch sublist3r arjun sqlmap theHarvester waymore paramspider dnsgen \
    --break-system-packages

RUN pip3 install wafw00f sslyze shodan wfuzz censys photon VHostScan \
    --break-system-packages \
    || echo "[warn] some pip tools failed — install individually to diagnose"

# ── OneForAll (comprehensive multi-source subdomain enum, ~60 sources) ────────
RUN git clone --depth 1 https://github.com/shmilylty/OneForAll.git /opt/OneForAll \
    && pip3 install -r /opt/OneForAll/requirements.txt --break-system-packages \
    || echo "[warn] OneForAll install failed — oneforall step will be skipped"

# ── linkfinder (JS endpoint discovery) ───────────────────────────────────────
RUN git clone --depth 1 https://github.com/GerbenJavado/LinkFinder.git /opt/LinkFinder \
    && pip3 install -r /opt/LinkFinder/requirements.txt --break-system-packages 2>/dev/null \
    && printf '#!/bin/sh\nexec python3 /opt/LinkFinder/linkfinder.py "$@"\n' \
       > /usr/local/bin/linkfinder && chmod +x /usr/local/bin/linkfinder \
    || echo "[warn] linkfinder install failed"

# ── secretfinder (JS secret/token scanner) ───────────────────────────────────
RUN git clone --depth 1 https://github.com/m4ll0k/SecretFinder.git /opt/SecretFinder \
    && pip3 install -r /opt/SecretFinder/requirements.txt --break-system-packages 2>/dev/null \
    && printf '#!/bin/sh\nexec python3 /opt/SecretFinder/SecretFinder.py "$@"\n' \
       > /usr/local/bin/secretfinder && chmod +x /usr/local/bin/secretfinder \
    || echo "[warn] secretfinder install failed"

# ── corsy (CORS misconfiguration scanner) ────────────────────────────────────
RUN git clone --depth 1 https://github.com/s0md3v/Corsy.git /opt/Corsy \
    && pip3 install requests --break-system-packages 2>/dev/null \
    && printf '#!/bin/sh\nexec python3 /opt/Corsy/corsy.py "$@"\n' \
       > /usr/local/bin/corsy && chmod +x /usr/local/bin/corsy \
    || echo "[warn] corsy install failed"

# ── graphw00f (GraphQL engine fingerprinting) ─────────────────────────────────
RUN git clone --depth 1 https://github.com/dolevf/graphw00f.git /opt/graphw00f \
    && pip3 install -r /opt/graphw00f/requirements.txt --break-system-packages 2>/dev/null \
    && printf '#!/bin/sh\nexec python3 /opt/graphw00f/main.py "$@"\n' \
       > /usr/local/bin/graphw00f && chmod +x /usr/local/bin/graphw00f \
    || echo "[warn] graphw00f install failed"

# ── cloud_enum (multi-cloud bucket enumeration) ───────────────────────────────
RUN git clone --depth 1 https://github.com/initstring/cloud_enum.git /opt/cloud_enum \
    && pip3 install -r /opt/cloud_enum/requirements.txt --break-system-packages 2>/dev/null \
    && printf '#!/bin/sh\nexec python3 /opt/cloud_enum/cloud_enum.py "$@"\n' \
       > /usr/local/bin/cloud_enum && chmod +x /usr/local/bin/cloud_enum \
    || echo "[warn] cloud_enum install failed"

# ── pagodo (passive Google dork automation) ───────────────────────────────────
RUN git clone --depth 1 https://github.com/opsdisk/pagodo.git /opt/pagodo \
    && pip3 install -r /opt/pagodo/requirements.txt --break-system-packages 2>/dev/null \
    && printf '#!/bin/sh\nexec python3 /opt/pagodo/pagodo.py "$@"\n' \
       > /usr/local/bin/pagodo && chmod +x /usr/local/bin/pagodo \
    || echo "[warn] pagodo install failed"

# ── tplmap (SSTI detection and exploitation) ──────────────────────────────────
RUN git clone --depth 1 https://github.com/epinna/tplmap.git /opt/tplmap \
    && pip3 install -r /opt/tplmap/requirements.txt --break-system-packages 2>/dev/null \
    && printf '#!/bin/sh\nexec python3 /opt/tplmap/tplmap.py "$@"\n' \
       > /usr/local/bin/tplmap && chmod +x /usr/local/bin/tplmap \
    || echo "[warn] tplmap install failed"

# ── nosqlmap (NoSQL injection and exploitation) ───────────────────────────────
RUN git clone --depth 1 https://github.com/codingo/NoSQLMap.git /opt/NoSQLMap \
    && pip3 install -r /opt/NoSQLMap/requirements.txt --break-system-packages 2>/dev/null \
    && pip3 install /opt/NoSQLMap/ --no-deps --break-system-packages 2>/dev/null \
    && printf '#!/bin/sh\nexec python3 /opt/NoSQLMap/nosqlmap.py "$@"\n' \
       > /usr/local/bin/nosqlmap && chmod +x /usr/local/bin/nosqlmap \
    || echo "[warn] nosqlmap install failed"

# ── dnsvalidator (DNS resolver validation) ────────────────────────────────────
RUN git clone --depth 1 https://github.com/vortexau/dnsvalidator.git /opt/dnsvalidator \
    && pip3 install -r /opt/dnsvalidator/requirements.txt --break-system-packages 2>/dev/null \
    && pip3 install /opt/dnsvalidator/ --no-deps --break-system-packages 2>/dev/null \
    || echo "[warn] dnsvalidator install failed"

# ── ghauri (advanced SQL injection) ──────────────────────────────────────────
RUN git clone --depth 1 https://github.com/r0oth3x49/ghauri.git /opt/ghauri \
    && pip3 install -r /opt/ghauri/requirements.txt --break-system-packages 2>/dev/null \
    && pip3 install /opt/ghauri/ --no-deps --break-system-packages 2>/dev/null \
    || echo "[warn] ghauri install failed"

# ── takeover (subdomain takeover — 50+ service fingerprints) ─────────────────
RUN git clone --depth 1 https://github.com/m4ll0k/takeover.git /opt/takeover \
    && pip3 install -r /opt/takeover/requirements.txt --break-system-packages 2>/dev/null \
    && printf '#!/bin/sh\nexec python3 /opt/takeover/takeover.py "$@"\n' \
       > /usr/local/bin/takeover && chmod +x /usr/local/bin/takeover \
    || echo "[warn] takeover install failed"

# ── whatweb (web fingerprinting — 1800+ plugins) ─────────────────────────────
RUN git clone --depth 1 https://github.com/urbanadventurer/WhatWeb.git /opt/WhatWeb \
    && cd /opt/WhatWeb && gem install bundler --no-document 2>/dev/null \
    && bundle install 2>/dev/null \
    && printf '#!/bin/sh\nexec ruby /opt/WhatWeb/whatweb "$@"\n' \
       > /usr/local/bin/whatweb && chmod +x /usr/local/bin/whatweb \
    || echo "[warn] whatweb install failed"

# ── massdns (high-performance DNS resolver — backend for shuffledns/puredns) ──
RUN git clone --depth 1 https://github.com/blechschmidt/massdns.git /opt/massdns \
    && make -C /opt/massdns \
    && cp /opt/massdns/bin/massdns /usr/local/bin/massdns \
    && chmod +x /usr/local/bin/massdns \
    || echo "[warn] massdns install failed"

# ── gf patterns (tomnomnom/gf-patterns — pre-built grep filters) ─────────────
RUN mkdir -p /root/.gf \
    && git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns.git /tmp/gf-patterns \
    && cp /tmp/gf-patterns/*.json /root/.gf/ \
    && rm -rf /tmp/gf-patterns \
    || echo "[warn] gf patterns install failed"

# ── Wordlists ────────────────────────────────────────────────────────────────
RUN mkdir -p /app/wordlists \
    && curl -sL "https://github.com/kienzx203/Lab_research_tools_k1nz/releases/download/tools/common.txt" \
       -o /app/wordlists/common.txt \
    && curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt" \
       -o /app/wordlists/subdomains-top1million-20000.txt \
    && curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt" \
       -o /app/wordlists/subdomains-top1million-110000.txt \
    && curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt" \
       -o /app/wordlists/raft-medium-directories.txt \
    && curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-files.txt" \
       -o /app/wordlists/raft-medium-files.txt \
    && curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt" \
       -o /app/wordlists/burp-parameter-names.txt \
    && curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/SNMP/snmp-default-community-strings-onesixtyone.txt" \
       -o /app/wordlists/snmp-default-communities.txt

# Param discovery wordlists — extracted from arjun's bundled db after pip install
RUN find /usr -path '*/arjun/db/medium.txt' -exec cp {} /app/wordlists/params-medium.txt \; 2>/dev/null \
    || echo "[warn] params-medium.txt not found"
RUN find /usr -path '*/arjun/db/large.txt'  -exec cp {} /app/wordlists/params-large.txt  \; 2>/dev/null \
    || echo "[warn] params-large.txt not found"

# kiterunner API routes wordlist — routes-small (~100 MB smaller than large variant)
# Override with routes-large.kite via volume mount for deeper API coverage
RUN curl -sL "https://wordlists-cdn.assetnote.io/data/kiterunner/routes-small.kite.tar.gz" \
       -o /tmp/routes.tar.gz \
    && mkdir -p /tmp/routes_ext \
    && tar xzf /tmp/routes.tar.gz -C /tmp/routes_ext \
    && find /tmp/routes_ext -name '*.kite' -exec cp {} /app/wordlists/routes-large.kite \; \
    && rm -rf /tmp/routes.tar.gz /tmp/routes_ext \
    || echo "[warn] kiterunner wordlist download failed — kiterunner step will be skipped"

# ── Pre-cache httpx DIT tech-detection model ─────────────────────────────────
RUN mkdir -p /root/.dit \
    && curl -sL "https://huggingface.co/datasets/happyhackingspace/dit/resolve/main/model.json" \
       -o /root/.dit/model.json \
    || echo "[warn] httpx DIT model pre-download failed — will download on first scan"

# ── Nuclei templates ─────────────────────────────────────────────────────────
RUN nuclei -update-templates \
    || echo "[warn] nuclei templates download failed — will retry at runtime"

# ── Qwen Code ────────────────────────────────────────────────────────────────
RUN curl -fsSL https://qwen-code-assets.oss-cn-hangzhou.aliyuncs.com/installation/install-qwen-standalone.sh | bash \
    || echo "[warn] Qwen Code install failed"

ENV PATH=/root/.local/bin:$PATH

# ── App ───────────────────────────────────────────────────────────────────────
WORKDIR /app

COPY requirements.txt pyproject.toml ./
RUN pip3 install -r requirements.txt croniter --break-system-packages

COPY src/ ./src/
RUN pip3 install -e . --no-deps --break-system-packages

COPY workflows/ ./workflows/
COPY scripts/ ./scripts/

# Copy built React UI from stage 2 → /app/static (matches STATIC_DIR in config.py)
COPY --from=uibuilder /ui/dist/ ./static/

RUN mkdir -p /app/runs

ENV K1NZR3C0N_BASE=/app
ENV REDIS_URL=redis://redis:6379/0
ENV PYTHONUNBUFFERED=1
ENV CHROME_PATH=/usr/local/bin/chromium-docker

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/api/runs/stats || exit 1

CMD ["uvicorn", "k1nzr3c0n.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
