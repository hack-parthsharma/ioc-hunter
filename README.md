# 🎯 IOC HUNTER — 24h Threat Intelligence IOC Aggregator

Real-time IOC aggregator that fetches indicators of compromise from **12+ open-source threat intelligence feeds** and displays prioritized results with threat classification, feed attribution, and executive briefings.

## 🚀 Live Demo

**https://hack-parthsharma.github.io/ioc-hunter/**

## Features

| Feature | Description |
|---------|-------------|
| **Multi-feed aggregation** | Queries 12+ threat intel feeds for IOCs published in the last 24h |
| **Auto-deduplication** | Merges identical indicators across feeds |
| **5-tier threat classification** | Critical / High / Medium / Low / Info based on source + context |
| **IOC type detection** | Auto-classifies IPs, domains, URLs, hashes, emails, CVEs |
| **Executive briefing** | Auto-generated situational summary with action items |
| **Outlook integration** | Auto-opens Outlook with pre-filled threat report |
| **Multi-format export** | CSV, JSON, or HTML report download |
| **Click-to-copy** | Click any IOC to copy to clipboard |
| **Zero dependencies** | Single HTML file, no frameworks, no build tools, no backend |

## Intel Feeds

| Feed | IOC Types | Focus |
|------|-----------|-------|
| AlienVault OTX | IP, Domain, Hash, URL, CVE | Community pulses, APT tracking |
| Abuse.ch URLhaus | URL | Malware distribution URLs |
| Abuse.ch ThreatFox | IP, Domain, Hash, URL | Malware C2, payloads |
| Abuse.ch MalBazaar | Hash (SHA256) | Malware samples |
| Abuse.ch FeodoTracker | IP | Botnet C2 servers |
| Blocklist.de | IP | Brute-force attackers |
| CINSscore | IP | Malicious scanning IPs |
| OpenPhish | URL | Phishing URLs |
| PhishTank | URL | Verified phishing pages |
| C2 IntelFeeds | IP | C2 server infrastructure |
| DigitalSide TI | IP | Malware & C2 IPs |
| CISA KEV | CVE | Actively exploited vulnerabilities |

## Setup

### Option 1: GitHub Pages (Recommended)

1. Fork this repo
2. Go to **Settings → Pages → Source → Deploy from branch → main**
3. Your dashboard is live at `https://YOUR_USERNAME.github.io/ioc-hunter/`

### Option 2: Local

Just download `index.html` and open it in any browser.

## How It Works

1. **Fetch** — Queries all 12+ feeds via their public APIs and data feeds
2. **Parse** — Extracts and normalizes IOCs from diverse response formats (JSON, CSV, plaintext)
3. **Classify** — Auto-detects IOC type (IP/domain/hash/URL/CVE) and assigns threat level
4. **Deduplicate** — Merges identical indicators, preserving highest threat rating
5. **Report** — Displays interactive dashboard + opens Outlook with the full report

## Threat Classification

| Tier | Label | Criteria |
|------|-------|----------|
| 🔴 | Critical | Active C2, ransomware, CISA KEV, APT-linked |
| 🟠 | High | Malware distribution, phishing, trojan, exploit |
| 🟡 | Medium | Scanning, spam, moderate confidence |
| 🟢 | Low | Informational, low-confidence, passive |
| 🔵 | Info | Context-only, no direct threat |

## API Keys

No API keys required for basic operation — all feeds use public endpoints.

Optional: For AlienVault OTX enhanced access, add your OTX API key in `index.html`.

## Export Formats

- **CSV** — IOC flat file for SIEM import (Splunk, QRadar, Sentinel)
- **JSON** — Structured data for automation / SOAR playbooks
- **HTML Report** — Formatted threat report with tables and statistics
- **Outlook Email** — Pre-filled email with critical IOC summary

## License

MIT
