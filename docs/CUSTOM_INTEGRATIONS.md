# Custom Integrations Added

## 1) MCP Orchestration Module
Module: `sfp_mcp_server`

### What it does
- Sends incoming SpiderFoot entities to one or more MCP-compatible HTTP endpoints.
- Merges endpoint responses and emits SpiderFoot events.

### Key options
- `mcp_endpoints` (JSON array) - preferred
- `continue_on_error`
- `max_results_per_endpoint`
- `emit_raw_response`

### Example `mcp_endpoints`
```json
[
  {
    "name": "threat-intel",
    "url": "https://mcp1.example.com/enrich",
    "api_key": "token1",
    "header": "Authorization",
    "scheme": "Bearer",
    "tool": "ti_lookup",
    "verify_tls": true,
    "enabled": true
  },
  {
    "name": "breach-intel",
    "url": "https://mcp2.example.com/enrich",
    "api_key": "token2",
    "header": "X-API-Key",
    "scheme": "",
    "tool": "breach_lookup",
    "verify_tls": true,
    "enabled": true
  }
]
```

## 2) SIEM Webhook Export
Module: `sfp__stor_siem_webhook`

### What it does
- Forwards scan events to a webhook/SIEM endpoint as JSON.

### Key options
- `webhook_url`
- `api_key`, `auth_header`, `auth_scheme`
- `event_allowlist` / `event_denylist`
- `include_source_event`

### Payload shape
```json
{
  "event": {"...": "SpiderFoot event.asDict()"},
  "module": "sfp_xxx",
  "event_type": "IP_ADDRESS",
  "data": "1.2.3.4",
  "source_event": {
    "type": "DOMAIN_NAME",
    "module": "sfp_dnsresolve",
    "data": "example.com",
    "hash": "..."
  }
}
```

## 3) Added Tool Integrations (Kali/Parrot style)

### `sfp_tool_subfinder`
- Passive subdomain discovery
- Default binary path: `/usr/local/bin/subfinder` (`subfinder_path`)

### `sfp_tool_httpx`
- HTTP probing and technology detection
- Default binary path: `/usr/local/bin/httpx` (`httpx_path`)

## 4) Historical Diff Utility
Script: `tools/scan_diff.py`

### Example
```bash
./tools/scan_diff.py \
  --db /home/www/.spiderfoot/spiderfoot.db \
  --old 48293C8C \
  --new E160BDBA \
  --limit 20
```

JSON output:
```bash
./tools/scan_diff.py --db /home/www/.spiderfoot/spiderfoot.db --old OLDGUID --new NEWGUID --json
```

## 5) Additional Kali/Parrot-style modules added

### `sfp_tool_amass`
- Subdomain discovery via OWASP Amass
- Default binary path: `/usr/local/bin/amass` (`amass_path`)
- Optional `passive_only` mode (default enabled)

### `sfp_tool_naabu`
- Fast TCP port discovery via ProjectDiscovery Naabu
- Default binary path: `/usr/local/bin/naabu` (`naabu_path`)
- Supports `top_ports`, optional netblock scanning

### `sfp_tool_katana`
- Web crawling and URL discovery via ProjectDiscovery Katana
- Default binary path: `/usr/local/bin/katana` (`katana_path`)
- Supports configurable crawl depth

### `sfp_tool_dnsx`
- DNS resolution and enrichment via ProjectDiscovery Dnsx
- Default binary path: `/usr/local/bin/dnsx` (`dnsx_path`)

### `sfp_tool_gau`
- Historical URL collection from OTX/CommonCrawl/Wayback via `gau`
- Default binary path: `/usr/local/bin/gau` (`gau_path`)

### `sfp_tool_waybackurls`
- Wayback Machine URL history collection
- Default binary path: `/usr/local/bin/waybackurls` (`waybackurls_path`)

### `sfp_tool_tlsx`
- TLS metadata and certificate extraction via ProjectDiscovery `tlsx`
- Default binary path: `/usr/local/bin/tlsx` (`tlsx_path`)

### `sfp_tool_nuclei` (enhanced defaults)
- Vulnerability scanning via ProjectDiscovery Nuclei
- Default binary path: `/usr/local/bin/nuclei` (`nuclei_path`)
- Default template path: `/root/nuclei-templates` (`template_path`)

## 6) Deep Recon GUI Preset
- Added a new use-case in **New Scan**: `Deep Recon`
- It enables an opinionated module chain:
  - `sfp_dnsresolve`, `sfp_dnsbrute`, `sfp_spider`
  - Tor discovery: `sfp_torch`, `sfp_ahmia`, `sfp_onionsearchengine`
  - `sfp_tool_subfinder`, `sfp_tool_amass`, `sfp_tool_dnsx`
  - `sfp_tool_naabu`, `sfp_tool_httpx`, `sfp_tool_katana`
  - `sfp_tool_gau`, `sfp_tool_waybackurls`, `sfp_tool_tlsx`
  - `sfp_tool_nuclei`, `sfp_tool_uncover`, `sfp_tool_dnstwist`, `sfp_tool_cmseek`, `sfp_tool_trufflehog`, `sfp_tool_searchsploit`, `sfp_tool_ffuf`
  - `sfp_tool_maigret`
  - `sfp_tool_h8mail`, `sfp_tool_bbot`
  - `sfp_tool_theharvester`, `sfp_tool_holehe`, `sfp_tool_sherlock`, `sfp_tool_phoneinfoga`, `sfp_tool_metagoofil`
  - `sfp_osint_portals`, `sfp_mcp_server`
  - API-key modules auto-added only if configured:
    - `sfp_haveibeenpwned`
    - `sfp_greynoise`
    - `sfp_intelx`

## 7) Additional OSINT Toolchain Added

### Installed tools
- `theHarvester` at `/usr/local/bin/theHarvester`
- `holehe` at `/usr/local/bin/holehe`
- `sherlock` at `/usr/local/bin/sherlock`
- `phoneinfoga` at `/usr/local/bin/phoneinfoga`
- `metagoofil` at `/usr/local/bin/metagoofil`
- `recon-ng` / `recon-cli` / `recon-web` at `/usr/local/bin/`
- `dnstwist` at `/usr/local/bin/dnstwist`
- `trufflehog` at `/usr/local/bin/trufflehog`
- `CMSeeK` source at `/opt/osint-tools/CMSeeK` (used by module via Python)
- `maigret` at `/usr/local/bin/maigret`
- `searchsploit` at `/usr/local/bin/searchsploit` with local Exploit-DB mirror at `/opt/osint-tools/exploitdb`
- `uncover` at `/usr/local/bin/uncover`
- `ffuf` at `/usr/local/bin/ffuf`
- `bbot` at `/usr/local/bin/bbot`
- `h8mail` at `/usr/local/bin/h8mail`
- `tor` service installed (`tor`, `torsocks`)

### Added SpiderFoot modules
- `sfp_tool_theharvester`
- `sfp_tool_holehe`
- `sfp_tool_sherlock`
- `sfp_tool_phoneinfoga`
- `sfp_tool_metagoofil`
- `sfp_osint_portals`
- `sfp_tool_dnstwist` (existing module, now tool installed)
- `sfp_tool_trufflehog` (existing module, now default path set)
- `sfp_tool_cmseek` (existing module, now default path set)
- `sfp_tool_searchsploit`
- `sfp_tool_maigret`
- `sfp_tool_uncover`
- `sfp_tool_ffuf`
- `sfp_tool_h8mail`
- `sfp_tool_bbot`

### Portal pivots covered by `sfp_osint_portals`
- OSINT Framework
- Epieos
- PimEyes
- TinEye
- Google Images
- HaveIBeenPwned
- GreyNoise Visualizer
- Intelligence X

## 8) Metasploit and IVRE

### Metasploit
- Docker image pulled: `metasploitframework/metasploit-framework:latest`
- Launcher script: `/usr/local/bin/msfconsole-docker`

### IVRE
- IVRE CLI installed in SpiderFoot venv and linked at `/usr/local/bin/ivre`
- Docker images pulled: `ivre/db:latest`, `ivre/web:latest`
- Note: IVRE web requires additional stack components for full web deployment.

### Installed tools on this server
- `/usr/local/bin/subfinder`
- `/usr/local/bin/httpx`
- `/usr/local/bin/naabu`
- `/usr/local/bin/amass`
- `/usr/local/bin/katana`
- `/usr/local/bin/dnsx`
- `/usr/local/bin/gau`
- `/usr/local/bin/waybackurls`
- `/usr/local/bin/tlsx`
- `/usr/local/bin/nuclei`

## 9) Automated Tool Updates (Cron)

- Updater script: `/usr/local/sbin/spiderfoot-osint-update.sh`
- Cron schedule: `/etc/cron.d/spiderfoot-osint-updates`
  - Runs daily at `03:23` (server local time)
- Log file: `/var/log/spiderfoot-osint-update.log`
- Log rotation: `/etc/logrotate.d/spiderfoot-osint-updates`

### What the updater refreshes
- Git repositories:
  - `/opt/osint-tools/exploitdb`
  - `/opt/osint-tools/CMSeeK`
  - `/opt/osint-tools/theHarvester`
  - `/opt/osint-tools/recon-ng`
  - `/opt/osint-tools/metagoofil`
- Python tool packages in SpiderFoot venv (best effort):
  - `dnstwist`, `holehe`, `sherlock-project`, `theHarvester`, `maigret`, `ivre`, `bbot`, `h8mail`
- Nuclei templates: `nuclei -ut`
- SearchSploit runtime config for root + `www` user (`~/.searchsploit_rc`)
- Restarts and verifies `spiderfoot` service at the end

## 10) HX-Like Insights View

- Added a new scan page tab: `HX Insights`
- Backend API endpoint: `/scanhx?id=<SCAN_ID>`
- Files:
  - `sfwebui.py` (`scanhx` analytics endpoint)
  - `spiderfoot/templates/scaninfo.tmpl` (new tab + visual panels)

### Included analytics
- Risk score (0-100) and risk level (`INFO` / `LOW` / `MEDIUM` / `HIGH` / `CRITICAL`)
- Correlation risk mix (`HIGH`, `MEDIUM`, `LOW`, `INFO`)
- Discovery timeline (daily event volume)
- Top modules by findings volume
- Top event types
- ATT&CK-like tactic mapping view
- IOC-focused event type breakdown
- IOC examples table
- Top entities table
- Key KPIs (total events, unique entities, modules used, domains, IPs, errors)

### Additional HX-like behavior
- Auto-refresh on the `HX Insights` tab while scans are running.
- Executive PDF report export endpoint:
  - `/scanhxreportpdf?id=<SCAN_ID>`

## 11) HX-Style UI/UX Theme Pack

- Added HX-inspired top navigation and page styling:
  - `Scan`, `Investigate`, `Monitor`, `Configure`, `Help`, `System`
- Updated header container to wider layout (`container-fluid`) for dashboard-style pages.
- New pages:
  - `Investigate` at `/investigate` (cross-scan correlation triage)
  - `Monitor` at `/monitor` (latest-vs-previous scan delta view per target)
  - `API Docs` at `/apidocs` (endpoint and request sample view)
- Graph workspace enhancements:
  - HX-style control buttons (play/pause/layout-fit/refresh/download)
  - Right-side node intelligence drawer with click-to-inspect behavior
  - Node quick action to pivot into search
- Scan overview enhancements:
  - Added `Top 5 Data Families` panel on summary/overview
- Monitor enhancements:
  - Added dashboard cards and comparison bar visualizations (risk pressure and data volume)
- Redesigned `New Scan` UI with:
  - sectioned cards (`Scan Name & Targets`, `Iteration`, `Modules`, `Options`)
  - right sidebar cards (`Professional Subscription`, `API Keys` donut)
- Styling file updated:
  - `spiderfoot/static/css/spiderfoot.css`

### Optional install commands (if tools are missing)
```bash
# ProjectDiscovery release binaries
curl -fsSL https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_*_linux_amd64.zip
curl -fsSL https://github.com/projectdiscovery/httpx/releases/latest/download/httpx_*_linux_amd64.zip
curl -fsSL https://github.com/projectdiscovery/naabu/releases/latest/download/naabu_*_linux_amd64.zip
curl -fsSL https://github.com/projectdiscovery/katana/releases/latest/download/katana_*_linux_amd64.zip
curl -fsSL https://github.com/projectdiscovery/dnsx/releases/latest/download/dnsx_*_linux_amd64.zip

# OWASP Amass release binary
curl -fsSL https://github.com/owasp-amass/amass/releases/latest/download/amass_linux_amd64.tar.gz
```

## 10) spiderFX Session Auth, User Management, and 2FA

### Session auth
- Replaced browser digest prompts with application session authentication.
- Unauthenticated requests to protected routes now redirect to `/signin`.

### Password hashing migration
- Password storage supports `pbkdf2_sha256$iterations$salt$hash`.
- Legacy plaintext credentials are transparently migrated to PBKDF2 on successful login.

### User management
- New admin panel at `/usermgmt`.
- Admin can:
  - Create users
  - Delete users
  - Enable/rotate TOTP 2FA per user
  - Disable 2FA per user
- `admin` account is protected from deletion.

### TOTP 2FA
- TOTP data file: `~/.spiderfoot/users_2fa.json`
- Compatible with Google Authenticator/Authy.
- Login flow supports password then OTP challenge for users with 2FA enabled.
