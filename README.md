# 🕷️ SpiderFX

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.7+-green)](https://www.python.org)
[![Platform Status](https://img.shields.io/badge/platform-enterprise--grade-orange)](https://github.com/surendrad24/SpiderFX)
[![Last Commit](https://img.shields.io/github/last-commit/surendrad24/SpiderFX)](https://github.com/surendrad24/SpiderFX/commits/master)

**SpiderFX** is a premium, enterprise-grade open source intelligence (OSINT) automation and attack surface mapping platform built on top of Spiderfoot. By integrating a secure, multi-tenant portal with a futuristic dark-themed **interactive HUD console**, SpiderFX brings state-of-the-art visual diagnostics, advanced scan comparisons, LLM integration, and 20+ next-generation active scanning tools to security analysts and red teams.

---

## ✨ KEY ADVANTAGES & FEATURES

> [!IMPORTANT]
> **SpiderFX** is fully customized for multi-user enterprise operations, real-time threat telemetry, and direct AI-model integration.

### 🛡️ 1. Multi-Tenant Enterprise Portal
Replaces simple open-source layouts with a secure, production-ready user access suite:
* **Role-Based User Management**: Admin panel for adjusting user access controls and credential tokens directly.
* **Authentication Suite**: Fully custom user signup, sign-in, and account security profile management.
* **API Documentation**: Pre-integrated, interactive API documentation portal to run automated scans programmatically.

### 🌌 2. Futuristic Interactive HUD Redesign
A premium, responsive cyberpunk-style interface featuring:
* **Neon Cyan & Warning Orange Themes**: Elegant high-contrast styling built entirely using responsive grid views.
* **Real-Time Scan Telemetry**: High-performance SVG dials, circular visual indicators, and pulse animations reflecting target status instantly.
* **Interactive Navigation**: Streamlined side-panels, tab triggers, and full-screen workspace scaling.

### 🤖 3. Model Context Protocol (MCP) Server
Integrates a python-based Model Context Protocol (MCP) server directly inside the OSINT framework:
* **LLM Hook**: Allows LLMs (like Gemini, Claude, and GPT-4) to read, analyze, and query active SpiderFX scans, targets, and data points contextually.
* **Cognitive Analysis**: Let AI agents summarize vulnerabilities, pinpoint domain takeovers, and orchestrate follow-up sweeps automatically.

### 🔌 4. 20+ Next-Generation OSINT Scanners
Pre-integrated with the industry's most powerful open-source command-line toolsets:
* **Subdomain & DNS Recon**: `Amass`, `Subfinder`, `DNSx`, and `Waybackurls`.
* **Vulnerability & Secret Searching**: `BBot`, `Katana`, `TruffleHog`, and `Searchsploit`.
* **Social Tracing & User profiling**: `Maigret`, `Sherlock`, and `Holehe`.
* **Active Port & Web Analyzers**: `Naabu`, `HTTPx`, `FFUF`, `GAU`, and `TLSx`.

### 🚨 5. SIEM Webhook Log Streamer
Stream parsed alerts, discovered assets, and threat intelligence events in real-time straight to your SIEM endpoints (Splunk, Elastic, Datadog, or custom webhooks) for immediate security triage.

---

## 🚀 QUICK START & INSTALLATION

### Prerequisites
* Python 3.7+
* Node.js / npm (for frontend components)
* External binaries (Amass, Subfinder, etc.) should be in your system `PATH` if using their respective active modules.

### Local Installation

```bash
# Clone the SpiderFX repository
git clone https://github.com/surendrad24/SpiderFX.git
cd SpiderFX

# Install required Python packages
pip3 install -r requirements.txt

# Start the SpiderFX server
python3 ./sf.py -l 127.0.0.1:5001
```

Once running, navigate to `http://127.0.0.1:5001` in your browser to access the secure sign-in portal and begin auditing your attack surface!

---

## 🛠️ EXTENDED OSINT TOOL PLUGINS

SpiderFX supports over 220+ scanning modules, with primary custom-built integrations listed below:

| Tool Module | Target Type | Scope & Description |
| :--- | :--- | :--- |
| **Amass** | Domain, Netblock | DNS mapping, active subdomain enumeration, and infrastructure profiling. |
| **BBot** | Domain, IP | Complete target footprinting and comprehensive OSINT active scans. |
| **Holehe** | Email | Traverses 120+ sites to trace registered profiles for a specific email address. |
| **Maigret** | Username | Performs username checks across 2,000+ social and web portals. |
| **Naabu** | IP, Hostname | Highly efficient, fast TCP/UDP port scanner. |
| **Subfinder** | Domain | High-fidelity passive subdomain discoverer. |
| **HTTPx** | Hostname, URL | Fast HTTP probe collector for response code, headers, and title extraction. |
| **Sherlock** | Username | Social media profile presence finder. |
| **TruffleHog** | URL, Git Repo | Deep commit-history parser to scan and identify exposed API secrets and tokens. |
| **Searchsploit** | Software | Queries Exploit Database to flag CVEs on discovered host packages. |

---

## 🧠 MCP SERVER INTEGRATION

To bridge SpiderFX with your LLM context:
1. Ensure your MCP client is configured.
2. The MCP schema is initialized through `modules/sfp_mcp_server.py`.
3. Provide the MCP server path in your Claude Desktop or MCP configuration file:

```json
{
  "mcpServers": {
    "spiderfx": {
      "command": "python3",
      "args": ["/path/to/SpiderFX/modules/sfp_mcp_server.py"]
    }
  }
}
```

---

## 📄 LICENSE

SpiderFX is distributed under the **MIT License**. See the `LICENSE` file for more details.
