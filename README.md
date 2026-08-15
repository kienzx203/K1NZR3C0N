# K1NZR3C0N

**Automated recon pipeline for bug bounty.** A self-hosted workflow runner that orchestrates 100+ security tools into coordinated, resumable pipelines — with a web UI for launching runs, watching live logs, browsing screenshots, triaging findings, and managing targets/scope.

> **Legal:** Only use against targets you own or have explicit written permission to test. Scope enforcement is built in (deny-wins target registry), but final responsibility is yours. The authors take no responsibility for unauthorized use.

---

## Highlights

- **One-click recon** — 3 shipped workflow templates (full recon, JS/secrets, authenticated param discovery); write your own in YAML, hot-loaded without restart
- **NAT-safe by design** — DNS-over-HTTPS resolve chain, rate-capped scans, per-host port caps; built to survive flaky VMware NAT
- **Scope safety first** — target registry with deny-wins scope checks; third-party pivot domains are an isolated, opt-in flow that never touches your vuln scanners
- **Live everything** — live log streaming over WebSocket, step progress, and Inventory that fills up *while the run is still running*
- **Structured findings** — tool outputs parsed into a queryable inventory (hosts, ports, tech, screenshots) with cross-run dedupe and new-asset alerts
- **Continuous recon** — cron-style schedules per target with Discord/Slack webhooks for new assets and critical findings

---

## Architecture

```
Browser → FastAPI (k1nzr3c0n-app :8000) → SQLite (runs/k1nzr3c0n.db)
                        ↓
                   Redis queue
                        ↓
           Celery worker (k1nzr3c0n-worker) ←→ runs/<target>/<ts>/ workspaces
           Celery beat   (k1nzr3c0n-beat)    — schedules, daily template updates
```

- **Backend**: FastAPI + SQLite — runs, logs, findings, targets, keys; serves the React UI
- **Worker**: Celery — executes workflow steps, parses outputs into findings, sends webhooks
- **Frontend**: React/Vite — dashboard, run detail with live log stream, screenshot gallery, inventory, workflow editor with variable UI
- **Deployment**: bare-metal Kali Linux, systemd services, `/opt/k1nzr3c0n/`

---

## Quick Start (Kali Linux)

**Fresh box — one-time install** (system packages, Go toolchain, ~100 tools,
wordlists, app deploy, systemd services, seeds API keys into the DB):

```bash
sudo bash install.sh
# Secrets are read from install-secrets.env (gitignored, never commit).
# Re-seed keys only, after editing that file:
sudo bash install.sh --seed-only
```

**Upgrade an existing box** — copy the deploy bundle over, then on the box:

```bash
bash deploy-to-kali.sh /path/to/k1nzr3c0n-deploy.tar.gz
```

The deploy script rsyncs the app into `/opt/k1nzr3c0n/` without touching
`runs/`, `.env`, `wordlists/`, or the database — safe to re-run. It does **not**
reinstall tools; the **Tools** page in the UI tracks installed vs latest
versions and updates them in place (nuclei templates auto-update daily).

### Managing services

```bash
bash start.sh            # start redis + app + worker + beat
bash start.sh status     # show status of all services
bash start.sh logs       # tail app logs (or: start.sh logs k1nzr3c0n-worker)
bash start.sh restart    # restart everything

# Open the UI
xdg-open http://127.0.0.1:8000
```


### Web UI tour

| Page | Purpose |
|---|---|
| **Dashboard** | Run stats, recent activity |
| **Runs** | Launch runs (workflow + target + var overrides), pause/resume/cancel, live logs + step progress |
| **Run detail** | Logs, Findings, Screenshots gallery, ST Intel, file explorer, report |
| **Inventory** | Cross-run deduped live hosts (host:port, title, tech, screenshot) — updates live during runs |
| **Findings** | All vuln/port/http/subdomain findings; status lifecycle (open/fp/resolved), notes, tags |
| **Targets** | Target registry + scope patterns + engagement mode (bounty/vdp/oos) — deny-wins scope check |
| **Schedules** | Cron-style continuous recon per target |
| **Keys** | API keys for intel providers (Shodan, SecurityTrails, …) — stored in DB, injected at run start |
| **Tools** | Tool version tracker + one-click updates, network diagnostics, **Danger Zone** (reset DB / wipe run data) |
| **Workflows** | Workflow editor with typed variable UI, history snapshots, import/export |
| **Terminal** | In-browser terminal |

---

## Workflow Templates

### 01 — Full Recon Pipeline (94 steps)

Full-coverage recon from passive enumeration to vulnerability scanning:

```
Passive subdomains (27 sources: crt.sh, certspotter, subfinder, amass, chaos,
  SecurityTrails, VirusTotal, wayback/gau/waymore, GitHub code search, …)
→ SecurityTrails intel mining (cert SANs + historical DNS → missed subs)
→ ASN/IP recon + amass intel + reverse DNS
→ Permutation (dnsgen/alterx/gotator — target-derived, no wordlists)
→ DNS resolve — DoH-first chain (puredns wildcard filter → dnsx → gap-fill)
→ TLS-SAN mining (tlsx) → even more subs
→ Port scan (naabu: Shodan passive + 105 web/app ports; ASN ranges)
→ HTTP probe (httpx on every live domain:port) → screenshots (gowitness)
→ Pivots: favicon hash · vhost fuzz · IP/PTR pivot · redirect mining
→ URL crawl (katana/hakrawler) + JS analysis (endpoints, secrets, subs)
→ Subdomain takeover + cloud storage (S3)
→ Vuln scan (nuclei + afrog; network templates for non-web ports)
→ Report
→ Deep port scan (TAIL, optional: rustscan full 1-65535 + nmap -sV, IP-deduped)
```

Opt-in **Flow 2** (`run_st_pivot_scan`, default off): scans SecurityTrails *pivot domains* (other orgs' root domains sharing NS/MX). Fully isolated — httpx + screenshots only; crawl and vuln scanners never touch them.

**Key vars** (override at run time):

| Var | Default | Purpose |
|---|---|---|
| `run_passive` / `run_permutation` / `run_nuclei` | `true` | Phase toggles |
| `run_deep_portscan` | `true` | Full-range port scan at the tail (slowest step) |
| `run_st_pivot_scan` | `false` | Flow 2 — scan ST pivot domains (scope-sensitive) |
| `web_ports` | 105 ports | Single source of truth for web/app ports |
| `max_ports_per_host` | `20` | Shared-hosting port-explosion guard |
| `naabu_rate` | `500` | Naabu packet rate (NAT-safe) |
| `nuclei_rl` / `nuclei_concurrency` | `150` / … | Nuclei rate limiting |

### 02 — JS & Secrets Recon (19 steps)

```
HTTP probe → crawl (katana + hakrawler + archives) → download JS
→ endpoint extraction (linkfinder/jsapiscan/jsubfinder) → secret scan
→ nuclei keys/exposures → gf patterns → dir brute → report
```
Supports `session_cookie` / `auth_header` for authenticated scanning.

### 03 — Authenticated Parameter Discovery (8 steps)

```
URL collection (gau/katana) → extract known params
→ brute force hidden params (arjun/x8/ffuf) with session/token headers
→ nuclei param probes → report
```

---

## Workflow YAML Format

Workflows live in `workflows/` and are hot-loaded — add or edit one and it appears in the UI immediately, no restart. Steps run in dependency order; independent steps run concurrently. Full reference: `docs/workflow-yaml.md`.

```yaml
name: my-workflow
description: 'What this does'
vars:
  my_flag: 'true'
  wordlist: ${K1NZR3C0N_BASE:-/opt/k1nzr3c0n}/wordlists/common.txt

steps:
  - id: probe
    name: HTTP probe
    when: '{vars.my_flag}'           # skip step if falsy
    optional: true                   # don't fail the run if this step fails
    skip_if_exists: true             # resume support: skip if output exists
    timeout: 30m
    run: 'httpx -l {workspace}/subs.txt -o {workspace}/alive.txt'
    outputs:
      alive: '{workspace}/alive.txt'

  - id: scan
    depends_on: ['probe']
    run: 'nuclei -l {steps.probe.alive} -jsonl -o {workspace}/nuclei.jsonl'
    outputs:
      findings: '{workspace}/nuclei.jsonl'
    requires:
      - path: '{workspace}/nuclei.jsonl'
        min_bytes: 1                 # fail step if output is empty
```

### Template variables

| Pattern | Resolves to |
|---|---|
| `{target}` | The target domain/IP |
| `{workspace}` | `runs/<target>/<timestamp>/` |
| `{vars.name}` | Workflow var (or run-time override) |
| `{steps.id.output_key}` | Output path from a previous step |

> Use `${K1NZR3C0N_BASE:-/opt/k1nzr3c0n}/` for tool/wordlist paths — resolves at bash runtime so workflows stay portable.

Advanced step features: `fanout` (parallel substeps with per-fanout timeouts), `retries`, `run_on_failed_deps`, `skip_if_exists` (resume), `requires.min_bytes` validation, `##K1Z:TIME##` step timing markers.

---

## Scope Safety

Bug bounty discipline is built into the tooling:

- **Target registry** (`Targets` page): each target has scope patterns + mode (`bounty` / `vdp` / `oos`). Deny-wins: anything not explicitly allowed is out.
- **Every discovery merge step re-filters** candidates against the target suffix — out-of-scope hosts never reach scanners.
- **Flow 2 isolation**: third-party pivot domains (ST NS/MX pivots) are opt-in and only ever get httpx + screenshots — never crawl, never vuln scan.
- **Scope audit trail**: `scope_audit` table logs allow/deny decisions per run.

---

## Tool Arsenal

Pre-installed on the Kali box; the **Tools** page tracks versions and updates in place (nuclei templates auto-update daily at 04:30).

| Category | Tools |
|---|---|
| **Subdomain Enum** | `subfinder` `amass` `assetfinder` `findomain` `sublist3r` `chaos` `OneForAll` `cero` |
| **DNS Resolution** | `dnsx` `puredns` `massdns` `dnsgen` `alterx` `gotator` |
| **Port Scanning** | `naabu` `rustscan` `nmap` `masscan` |
| **HTTP Probing** | `httpx` `cdncheck` `tlsx` `gowitness` `whatweb` `wafw00f` |
| **URL & JS** | `katana` `gau` `gauplus` `waymore` `waybackurls` `hakrawler` `cariddi` `subjs` `linkfinder` `jsubfinder` `jsapiscan` `urlfinder` |
| **Secrets** | `secretfinder` `trufflehog` `gitleaks` |
| **Param Discovery** | `arjun` `x8` `ffuf` `fallparams` `paramspider` `kiterunner` |
| **Dir Brute** | `feroxbuster` `dirsearch` `gobuster` |
| **Vuln Scanning** | `nuclei` (~13.5k templates, auto-updated) `afrog` |
| **Takeover & Cloud** | `subzy` `dnstake` `S3Scanner` `cloud_enum` |
| **Pivots & OSINT** | `asnmap` `uncover` `metabigor` `favicon hash (mmh3)` `SecurityTrails API` |
| **Utilities** | `gf` `anew` `unfurl` `qsreplace` `meg` `interactsh-client` `notify` |

---

## Output Files

Each run creates `runs/<target>/<timestamp>/`:

| File | Content |
|---|---|
| `subdomains_all.txt` / `subdomains_all_resolved.txt` | Candidate + resolved hosts |
| `naabu.jsonl` | Open ports (host/ip + port) |
| `web_targets.txt` | domain:port combinations fed to httpx |
| `httpx.jsonl` | Live hosts: status, title, tech, IP |
| `screenshots/` + `gowitness.sqlite3` | Screenshot gallery (viewable in UI) |
| `katana_urls.txt` / `js_urls.txt` | Crawled URLs, JS files |
| `nuclei_*.jsonl` / `afrog.jsonl` | Vulnerability findings |
| `takeover.txt` / `s3_buckets.txt` | Takeover + bucket results |
| `st_*.txt/.json` | SecurityTrails intel (subs, SANs, pivots, whois) |
| `rustscan_full.txt` / `nmap_service.txt` | Deep port scan (when enabled) |
| `report.md` | Final summary report |

Everything is parsed into the **Findings** table (kinds: `vuln`, `http`, `port`, `subdomain`, `url`) — the Inventory page dedupes `http` findings across runs to one row per host:port, keeping the newest sighting.

---

## Operations

### Danger Zone (Tools page)

Two reset levels, both requiring you to type `RESET` and both blocked while any run is active:

- **Wipe run data + workspaces** — clears runs/logs/findings/new-assets + all workspace dirs
- **Factory reset** — additionally clears targets + schedules

**Never deleted:** API keys, tool versions, workflow templates, nuclei templates, installed tools.

### Maintenance tasks (automatic)

| Task | Schedule |
|---|---|
| Workspace cleanup (>30 days old) | daily 02:00 |
| Tool version check | daily 04:00 |
| Nuclei templates update (`nuclei -ut`) | daily 04:30 |

### Backup / restore

```bash
python3 scripts/backup.py     # snapshot DB + workflows
python3 scripts/restore.py    # restore from snapshot
```

---

## Environment

All runtime configuration lives in `/opt/k1nzr3c0n/.env` — loaded by systemd via
`EnvironmentFile=` for both the app and the worker services. The deploy script
never overwrites it. Edit and restart services (`bash start.sh restart`).

```env
# ── System ────────────────────────────────────────────────────────────────
K1NZR3C0N_BASE=/opt/k1nzr3c0n          # install root (workflows/, runs/, …)
REDIS_URL=redis://127.0.0.1:6379/0     # Celery broker/backend
CHROME_PATH=/usr/bin/chromium          # Chromium used by gowitness screenshots

# ── App features ──────────────────────────────────────────────────────────
# Optional bearer-token auth for API + UI. EMPTY = AUTH DISABLED — leave it
# empty only on trusted networks.
K1NZR3C0N_API_TOKEN=

# Discord/Slack webhook — run completion, new assets, critical/high findings
K1NZR3C0N_WEBHOOK_URL=https://discord.com/api/webhooks/...
K1NZR3C0N_WEBHOOK_USERNAME=k1nzr3c0n   # Slack-style sender name only

# GitHub token: raises API rate limit 60 → 5,000 req/hr for tool update checks
# Create at: https://github.com/settings/tokens (no scopes needed)
GITHUB_TOKEN=github_pat_...

# OpenCode (embedded AI in the UI)
OPENROUTER_API_KEY=sk-or-...

# ── Intel provider keys ───────────────────────────────────────────────────
# PREFER THE /keys UI: keys stored in the DB are injected into every run's
# environment automatically at run start (no restart needed). Values below
# act as fallback/seed only.
SECURITYTRAILS_KEY=...
SHODAN_API_KEY=...
VIRUSTOTAL_KEY=...
CHAOS_API_KEY=...
CENSYS_API_ID=...
CENSYS_API_SECRET=...
BEVIGIL_KEY=...
FOFA_KEY=...
```

**Key resolution order:** at run start the worker overlays the DB keys
(`/keys` UI) onto the subprocess environment, so a key set in the UI wins and
takes effect on the very next run without any service restart.


---

## AI Integration

- **OpenCode** — embedded in the UI at `/opencode` (proxied, port 4040)
- **Claude Code** — `claude` CLI available system-wide
- **78 hunt skills** (`.qwen/skills/k1nzr3c0n-*`) — bug-bounty methodology for AI agents: recon analyst, JS analyst, per-vuln-class hunt playbooks (IDOR, SSRF, XSS, OAuth, race conditions, …), triage gates, report writing, evidence hygiene

---

## Project Structure

```
K1NZR3C0N/
├── install.sh                   # one-time bare-metal installer (tools + app + services)
├── install-secrets.env          # API keys for install.sh — gitignored, never commit
├── deploy-to-kali.sh            # upgrade installer (run ON the Kali box with a bundle)
├── start.sh                     # service start/stop/status/logs helper
├── .env                         # runtime secrets — gitignored, never commit
├── workflows/
│   ├── 01-full-recon-pipeline.yaml
│   ├── 02-js-secrets-recon.yaml
│   ├── 03-param-discovery.yaml
│   └── ARSENAL.md               # manual recon + payload reference
├── src/k1nzr3c0n/
│   ├── cli.py                   # k1nzr3c0n CLI entrypoint
│   ├── workflow.py              # YAML renderer + step executor
│   ├── tasks.py                 # Celery tasks (run loop, parsing, webhooks, beat jobs)
│   ├── parsers/                 # tool output → Finding rows (plugin registry)
│   ├── tools.py                 # tool catalog + version check/update
│   ├── db.py                    # SQLAlchemy models
│   ├── api/                     # FastAPI routes (runs, findings, assets, targets, …)
│   └── static/                  # built React UI
├── frontend/                    # React/Vite source
├── scripts/                     # helper scripts (ST fetch, backup, resolvers, …)
├── docs/                        # workflow YAML reference, analyst skills
├── wordlists/                   # bundled wordlists (resolvers, subs, dirs, params)
└── runs/                        # workspaces + k1nzr3c0n.db — gitignored
```

Deployed layout mirrors this at `/opt/k1nzr3c0n/` under systemd (`k1nzr3c0n-app`, `k1nzr3c0n-worker`, `k1nzr3c0n-beat`).

---

## Requirements

- Python ≥ 3.11 (`pip install -e .` — see `pyproject.toml`)
- Redis
- Kali Linux with the tool arsenal installed
- Chromium (for gowitness screenshots)
