#!/usr/bin/env python3
"""
IOC HUNTER — Threat Intelligence IOC Fetcher
Fetches IOCs from 12+ open-source threat intel feeds, classifies, deduplicates,
and outputs a JSON file for the dashboard + an HTML email report.

Run via GitHub Actions or locally:
  python ioc_fetcher.py
"""

import json
import re
import hashlib
import sys
import csv
import io
from datetime import datetime, timedelta, timezone
from urllib.request import Request, urlopen
from urllib.parse import urlencode
from urllib.error import URLError, HTTPError

# ============================================================================
# CONFIGURATION
# ============================================================================

OUTPUT_JSON = "ioc_data.json"
OUTPUT_REPORT = "ioc_report.html"
REQUEST_TIMEOUT = 30  # seconds per feed
MAX_IOCS_PER_FEED = 100

# ============================================================================
# HELPERS
# ============================================================================

def fetch_url(url, method="GET", data=None, headers=None, timeout=REQUEST_TIMEOUT):
    """Fetch a URL and return the response body as string."""
    hdrs = {"User-Agent": "IOC-Hunter/1.0"}
    if headers:
        hdrs.update(headers)
    
    req = Request(url, headers=hdrs)
    if method == "POST" and data:
        if isinstance(data, str):
            data = data.encode("utf-8")
        req.data = data
    
    try:
        with urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except (URLError, HTTPError, TimeoutError, Exception) as e:
        print(f"  ⚠ Fetch failed: {e}")
        return None


def fetch_json(url, method="GET", data=None, headers=None):
    """Fetch a URL and parse as JSON."""
    body = fetch_url(url, method=method, data=data, headers=headers)
    if body is None:
        return None
    try:
        return json.loads(body)
    except json.JSONDecodeError as e:
        print(f"  ⚠ JSON parse error: {e}")
        return None


def detect_type(ioc):
    """Auto-detect IOC type from the indicator string."""
    if not ioc:
        return "domain"
    ioc = ioc.strip()
    if re.match(r'^CVE-\d{4}-\d+', ioc, re.IGNORECASE):
        return "cve"
    if re.match(r'^[a-f0-9]{32,128}$', ioc, re.IGNORECASE):
        return "hash"
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}(:\d+)?$', ioc):
        return "ip"
    if re.match(r'^https?://', ioc, re.IGNORECASE):
        return "url"
    if '@' in ioc:
        return "email"
    if ':' in ioc and re.match(r'^\d', ioc):
        return "ip"
    return "domain"


def map_threat(keywords, confidence=None):
    """Map threat level based on keywords and confidence."""
    kw = " ".join(str(k) for k in keywords).lower()
    if any(t in kw for t in ["ransomware", "apt", "cobalt", "emotet", "c2", "actively-exploited"]):
        return "critical"
    if confidence and confidence >= 80:
        return "critical"
    if any(t in kw for t in ["malware", "trojan", "rat", "loader", "exploit", "payload", "phishing"]):
        return "high"
    if confidence and confidence >= 50:
        return "high"
    if any(t in kw for t in ["scan", "spam", "brute", "probe"]):
        return "medium"
    return "low"


def now_iso():
    return datetime.now(timezone.utc).isoformat()


# ============================================================================
# FEED FETCHERS
# ============================================================================

def fetch_urlhaus():
    """Abuse.ch URLhaus — recent malware distribution URLs."""
    print("📡 Fetching Abuse.ch URLhaus...")
    data = fetch_json(
        "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/100/",
        method="POST",
        data="",
        headers={"Content-Type": "application/json"}
    )
    if not data or "urls" not in data:
        return []
    
    iocs = []
    for u in data["urls"][:MAX_IOCS_PER_FEED]:
        iocs.append({
            "type": "url",
            "value": u.get("url", ""),
            "source": "URLhaus",
            "threat": map_threat([u.get("threat", "malware_download")]),
            "tags": list(filter(None, [u.get("threat", ""), u.get("url_status", "")])),
            "time": u.get("dateadded", now_iso())
        })
    print(f"  ✅ {len(iocs)} IOCs")
    return iocs


def fetch_threatfox():
    """Abuse.ch ThreatFox — recent IOCs (C2, payloads)."""
    print("📡 Fetching Abuse.ch ThreatFox...")
    data = fetch_json(
        "https://threatfox-api.abuse.ch/api/v1/",
        method="POST",
        data=json.dumps({"query": "get_iocs", "days": 1}),
        headers={"Content-Type": "application/json"}
    )
    if not data or "data" not in data or not isinstance(data["data"], list):
        return []
    
    iocs = []
    for i in data["data"][:MAX_IOCS_PER_FEED]:
        iocs.append({
            "type": detect_type(i.get("ioc", "")),
            "value": i.get("ioc", ""),
            "source": "ThreatFox",
            "threat": map_threat(
                [i.get("threat_type", ""), i.get("malware", "")],
                i.get("confidence_level", 0)
            ),
            "tags": list(filter(None, [
                i.get("threat_type", ""),
                i.get("malware", ""),
                i.get("malware_alias", "")
            ])),
            "time": i.get("first_seen", now_iso())
        })
    print(f"  ✅ {len(iocs)} IOCs")
    return iocs


def fetch_malbazaar():
    """Abuse.ch MalBazaar — recent malware sample hashes."""
    print("📡 Fetching Abuse.ch MalBazaar...")
    data = fetch_json(
        "https://mb-api.abuse.ch/api/v1/",
        method="POST",
        data=urlencode({"query": "get_recent", "selector": "100"}).encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    if not data or "data" not in data or not isinstance(data["data"], list):
        return []
    
    iocs = []
    for s in data["data"][:MAX_IOCS_PER_FEED]:
        sig = (s.get("signature") or "").lower()
        threat = "critical" if any(t in sig for t in ["ransom", "cobalt", "emotet"]) else \
                 "high" if any(t in sig for t in ["trojan", "rat", "loader"]) else "medium"
        iocs.append({
            "type": "hash",
            "value": s.get("sha256_hash", ""),
            "source": "MalBazaar",
            "threat": threat,
            "tags": list(filter(None, [
                s.get("signature", ""),
                s.get("file_type", ""),
                s.get("reporter", "")
            ])),
            "time": s.get("first_seen", now_iso())
        })
    print(f"  ✅ {len(iocs)} IOCs")
    return iocs


def fetch_feodo():
    """Abuse.ch FeodoTracker — botnet C2 IPs."""
    print("📡 Fetching Abuse.ch FeodoTracker...")
    data = fetch_json("https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json")
    if not data or not isinstance(data, list):
        return []
    
    iocs = []
    for e in data[:MAX_IOCS_PER_FEED]:
        ip = e.get("ip_address", e.get("dst_ip", e.get("ip", "")))
        port = e.get("port", "")
        value = f"{ip}:{port}" if port else ip
        iocs.append({
            "type": "ip",
            "value": value,
            "source": "FeodoTracker",
            "threat": "critical",
            "tags": list(filter(None, [e.get("malware", "botnet"), "c2", e.get("status", "")])),
            "time": e.get("first_seen", now_iso())
        })
    print(f"  ✅ {len(iocs)} IOCs")
    return iocs


def fetch_blocklist():
    """Blocklist.de — brute-force attacker IPs."""
    print("📡 Fetching Blocklist.de...")
    text = fetch_url("https://lists.blocklist.de/lists/all.txt")
    if not text:
        return []
    
    lines = [l.strip() for l in text.split("\n") if l.strip() and not l.startswith("#")]
    iocs = []
    for ip in lines[:MAX_IOCS_PER_FEED]:
        iocs.append({
            "type": "ip",
            "value": ip,
            "source": "Blocklist.de",
            "threat": "high",
            "tags": ["brute-force", "attacker"],
            "time": now_iso()
        })
    print(f"  ✅ {len(iocs)} IOCs")
    return iocs


def fetch_cins():
    """CINSscore — malicious scanning IPs."""
    print("📡 Fetching CINSscore...")
    text = fetch_url("https://cinsscore.com/list/ci-badguys.txt")
    if not text:
        return []
    
    lines = [l.strip() for l in text.split("\n") if l.strip() and not l.startswith("#")]
    iocs = []
    for ip in lines[:MAX_IOCS_PER_FEED]:
        iocs.append({
            "type": "ip",
            "value": ip,
            "source": "CINSscore",
            "threat": "medium",
            "tags": ["malicious", "scanning"],
            "time": now_iso()
        })
    print(f"  ✅ {len(iocs)} IOCs")
    return iocs


def fetch_openphish():
    """OpenPhish — phishing URLs."""
    print("📡 Fetching OpenPhish...")
    text = fetch_url("https://openphish.com/feed.txt")
    if not text:
        return []
    
    lines = [l.strip() for l in text.split("\n") if l.strip().startswith("http")]
    iocs = []
    for url in lines[:MAX_IOCS_PER_FEED]:
        iocs.append({
            "type": "url",
            "value": url,
            "source": "OpenPhish",
            "threat": "high",
            "tags": ["phishing", "credential-theft"],
            "time": now_iso()
        })
    print(f"  ✅ {len(iocs)} IOCs")
    return iocs


def fetch_digitalside():
    """DigitalSide Threat-Intel — malware & C2 IPs."""
    print("📡 Fetching DigitalSide TI...")
    text = fetch_url("https://raw.githubusercontent.com/davidonzo/Threat-Intel/master/lists/latestips.txt")
    if not text:
        return []
    
    lines = [l.strip() for l in text.split("\n") if l.strip() and not l.startswith("#")]
    iocs = []
    for ip in lines[:MAX_IOCS_PER_FEED]:
        iocs.append({
            "type": "ip",
            "value": ip,
            "source": "DigitalSide",
            "threat": "high",
            "tags": ["malware", "c2"],
            "time": now_iso()
        })
    print(f"  ✅ {len(iocs)} IOCs")
    return iocs


def fetch_cisa_kev():
    """CISA Known Exploited Vulnerabilities — actively exploited CVEs."""
    print("📡 Fetching CISA KEV...")
    data = fetch_json("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    if not data or "vulnerabilities" not in data:
        return []
    
    cutoff = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%d")
    iocs = []
    for v in data["vulnerabilities"]:
        if v.get("dateAdded", "") >= cutoff:
            iocs.append({
                "type": "cve",
                "value": v.get("cveID", ""),
                "source": "CISA KEV",
                "threat": "critical",
                "tags": list(filter(None, [
                    v.get("vendorProject", ""),
                    v.get("product", ""),
                    "actively-exploited"
                ])),
                "time": v.get("dateAdded", now_iso())
            })
    
    iocs = iocs[:MAX_IOCS_PER_FEED]
    print(f"  ✅ {len(iocs)} IOCs")
    return iocs


def fetch_otx():
    """AlienVault OTX — community threat pulses."""
    print("📡 Fetching AlienVault OTX...")
    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT00:00:00")
    url = f"https://otx.alienvault.com/api/v1/pulses/activity?modified_since={yesterday}&limit=20"
    data = fetch_json(url)
    if not data or "results" not in data:
        return []
    
    type_map = {
        "IPv4": "ip", "IPv6": "ip",
        "domain": "domain", "hostname": "domain",
        "URL": "url", "URI": "url",
        "FileHash-MD5": "hash", "FileHash-SHA1": "hash", "FileHash-SHA256": "hash",
        "email": "email", "CVE": "cve"
    }
    
    iocs = []
    for pulse in data["results"]:
        tags = (pulse.get("tags") or [])[:3]
        adversary = (pulse.get("adversary") or "").lower()
        tag_str = " ".join(tags).lower()
        
        if "apt" in adversary or "apt" in tag_str or "ransomware" in tag_str:
            threat = "critical"
        elif any(t in tag_str for t in ["malware", "exploit", "c2"]):
            threat = "high"
        elif any(t in tag_str for t in ["phish", "spam"]):
            threat = "medium"
        else:
            threat = "low"
        
        for ind in (pulse.get("indicators") or [])[:10]:
            ioc_type = type_map.get(ind.get("type", ""), "domain")
            iocs.append({
                "type": ioc_type,
                "value": ind.get("indicator", ""),
                "source": "OTX",
                "threat": threat,
                "tags": tags,
                "time": ind.get("created", pulse.get("created", now_iso()))
            })
    
    iocs = iocs[:MAX_IOCS_PER_FEED]
    print(f"  ✅ {len(iocs)} IOCs")
    return iocs


def fetch_c2_intel():
    """C2 IntelFeeds — C2 server infrastructure."""
    print("📡 Fetching C2 IntelFeeds...")
    text = fetch_url("https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv")
    if not text:
        return []
    
    lines = [l.strip() for l in text.split("\n") if l.strip() and not l.startswith("#") and not l.startswith("ip")]
    iocs = []
    for line in lines[:MAX_IOCS_PER_FEED]:
        parts = line.split(",")
        ip = (parts[0] if parts else "").strip()
        if not ip:
            continue
        malware = parts[1].strip() if len(parts) > 1 else ""
        iocs.append({
            "type": "ip",
            "value": ip,
            "source": "C2 Intel",
            "threat": "critical",
            "tags": list(filter(None, ["c2", malware])),
            "time": parts[2].strip() if len(parts) > 2 else now_iso()
        })
    print(f"  ✅ {len(iocs)} IOCs")
    return iocs


def fetch_phishtank():
    """PhishTank — verified phishing URLs."""
    print("📡 Fetching PhishTank...")
    # PhishTank's full JSON feed can be large; use the online-valid endpoint
    data = fetch_json("https://data.phishtank.com/data/online-valid.json")
    if not data or not isinstance(data, list):
        return []
    
    iocs = []
    for p in data[:MAX_IOCS_PER_FEED]:
        iocs.append({
            "type": "url",
            "value": p.get("url", ""),
            "source": "PhishTank",
            "threat": "high",
            "tags": list(filter(None, ["phishing", p.get("target", "")])),
            "time": p.get("verification_time", p.get("submission_time", now_iso()))
        })
    print(f"  ✅ {len(iocs)} IOCs")
    return iocs


# ============================================================================
# MAIN PIPELINE
# ============================================================================

ALL_FEEDS = [
    ("AlienVault OTX", fetch_otx),
    ("Abuse.ch URLhaus", fetch_urlhaus),
    ("Abuse.ch ThreatFox", fetch_threatfox),
    ("Abuse.ch MalBazaar", fetch_malbazaar),
    ("Abuse.ch FeodoTracker", fetch_feodo),
    ("Blocklist.de", fetch_blocklist),
    ("CINSscore", fetch_cins),
    ("OpenPhish", fetch_openphish),
    ("PhishTank", fetch_phishtank),
    ("C2 IntelFeeds", fetch_c2_intel),
    ("DigitalSide TI", fetch_digitalside),
    ("CISA KEV", fetch_cisa_kev),
]


def run_pipeline():
    print("=" * 60)
    print("🎯 IOC HUNTER — Starting IOC Fetch Pipeline")
    print(f"⏰ {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print("=" * 60)
    
    all_iocs = []
    feed_stats = {}
    
    for feed_name, fetcher in ALL_FEEDS:
        try:
            iocs = fetcher()
            feed_stats[feed_name] = len(iocs)
            all_iocs.extend(iocs)
        except Exception as e:
            print(f"  ❌ {feed_name} crashed: {e}")
            feed_stats[feed_name] = 0
    
    # --- Deduplicate by value ---
    seen = set()
    unique_iocs = []
    for ioc in all_iocs:
        val = (ioc.get("value") or "").strip()
        if val and val not in seen:
            seen.add(val)
            unique_iocs.append(ioc)
    
    # --- Sort by threat priority ---
    threat_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    unique_iocs.sort(key=lambda x: threat_order.get(x.get("threat", "info"), 4))
    
    # --- Stats ---
    total = len(unique_iocs)
    critical = sum(1 for i in unique_iocs if i["threat"] == "critical")
    high = sum(1 for i in unique_iocs if i["threat"] == "high")
    medium = sum(1 for i in unique_iocs if i["threat"] == "medium")
    low = sum(1 for i in unique_iocs if i["threat"] == "low")
    active_feeds = sum(1 for v in feed_stats.values() if v > 0)
    
    type_counts = {}
    for i in unique_iocs:
        t = i["type"]
        type_counts[t] = type_counts.get(t, 0) + 1
    
    print("\n" + "=" * 60)
    print("📊 RESULTS")
    print("=" * 60)
    print(f"Total unique IOCs: {total}")
    print(f"Critical: {critical} | High: {high} | Medium: {medium} | Low: {low}")
    print(f"Active feeds: {active_feeds}/{len(ALL_FEEDS)}")
    print(f"Type breakdown: {type_counts}")
    print()
    
    for name, count in feed_stats.items():
        status = "✅" if count > 0 else "⚠"
        print(f"  {status} {name}: {count} IOCs")
    
    # --- Build output JSON ---
    output = {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "stats": {
            "total": total,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "active_feeds": active_feeds,
            "total_feeds": len(ALL_FEEDS),
            "type_counts": type_counts
        },
        "feed_stats": feed_stats,
        "iocs": unique_iocs
    }
    
    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"\n💾 Saved {OUTPUT_JSON} ({total} IOCs)")
    
    # --- Generate HTML report ---
    generate_html_report(output)
    print(f"📄 Saved {OUTPUT_REPORT}")
    
    print("\n✅ Pipeline complete!")
    return output


def generate_html_report(data):
    """Generate a formatted HTML email report."""
    stats = data["stats"]
    feed_stats = data["feed_stats"]
    iocs = data["iocs"]
    scan_time = data["scan_time"]
    
    critical_iocs = [i for i in iocs if i["threat"] == "critical"][:25]
    high_iocs = [i for i in iocs if i["threat"] == "high"][:15]
    
    # Top tags
    tag_counts = {}
    for i in iocs:
        for t in (i.get("tags") or []):
            if t and len(t) > 1:
                tag_counts[t] = tag_counts.get(t, 0) + 1
    top_tags = sorted(tag_counts.items(), key=lambda x: x[1], reverse=True)[:8]
    
    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>IOC Hunter Report</title></head>
<body style="font-family:Segoe UI,Arial,sans-serif;background:#0a0e17;color:#e2e8f0;padding:30px;max-width:900px;margin:0 auto;">

<div style="background:linear-gradient(135deg,#151d2e,#111827);border:1px solid #1e2d4a;border-radius:12px;padding:24px;margin-bottom:20px;">
  <h1 style="margin:0;font-size:22px;color:#3b82f6;">🎯 IOC HUNTER — Daily Threat Intelligence Report</h1>
  <p style="margin:8px 0 0;color:#64748b;font-size:13px;">Scan Time: {scan_time} UTC</p>
</div>

<div style="background:#151d2e;border:1px solid #1e2d4a;border-radius:12px;padding:20px;margin-bottom:20px;">
  <h2 style="color:#06b6d4;font-size:16px;margin:0 0 14px;">📊 Executive Summary</h2>
  <table style="width:100%;border-collapse:collapse;">
    <tr>
      <td style="padding:8px 12px;text-align:center;border:1px solid #1e2d4a;">
        <div style="font-size:28px;font-weight:bold;color:#3b82f6;">{stats['total']}</div>
        <div style="font-size:11px;color:#64748b;">TOTAL IOCs</div>
      </td>
      <td style="padding:8px 12px;text-align:center;border:1px solid #1e2d4a;">
        <div style="font-size:28px;font-weight:bold;color:#ff1744;">{stats['critical']}</div>
        <div style="font-size:11px;color:#64748b;">CRITICAL</div>
      </td>
      <td style="padding:8px 12px;text-align:center;border:1px solid #1e2d4a;">
        <div style="font-size:28px;font-weight:bold;color:#ff6d00;">{stats['high']}</div>
        <div style="font-size:11px;color:#64748b;">HIGH</div>
      </td>
      <td style="padding:8px 12px;text-align:center;border:1px solid #1e2d4a;">
        <div style="font-size:28px;font-weight:bold;color:#ffd600;">{stats['medium']}</div>
        <div style="font-size:11px;color:#64748b;">MEDIUM</div>
      </td>
      <td style="padding:8px 12px;text-align:center;border:1px solid #1e2d4a;">
        <div style="font-size:28px;font-weight:bold;color:#00e676;">{stats['low']}</div>
        <div style="font-size:11px;color:#64748b;">LOW</div>
      </td>
      <td style="padding:8px 12px;text-align:center;border:1px solid #1e2d4a;">
        <div style="font-size:28px;font-weight:bold;color:#a855f7;">{stats['active_feeds']}</div>
        <div style="font-size:11px;color:#64748b;">FEEDS ACTIVE</div>
      </td>
    </tr>
  </table>
</div>

<div style="background:#151d2e;border:1px solid #1e2d4a;border-radius:12px;padding:20px;margin-bottom:20px;">
  <h2 style="color:#06b6d4;font-size:16px;margin:0 0 14px;">📡 Feed Performance</h2>
  <table style="width:100%;border-collapse:collapse;">
    <tr style="background:rgba(0,0,0,0.3);">
      <th style="padding:8px 12px;text-align:left;border:1px solid #1e2d4a;font-size:12px;color:#64748b;">Feed</th>
      <th style="padding:8px 12px;text-align:center;border:1px solid #1e2d4a;font-size:12px;color:#64748b;">IOCs</th>
      <th style="padding:8px 12px;text-align:center;border:1px solid #1e2d4a;font-size:12px;color:#64748b;">Status</th>
    </tr>"""
    
    for name, count in feed_stats.items():
        status = "✅ Active" if count > 0 else "⚠ Unavailable"
        html += f"""
    <tr>
      <td style="padding:6px 12px;border:1px solid #1e2d4a;font-size:13px;">{name}</td>
      <td style="padding:6px 12px;border:1px solid #1e2d4a;font-size:13px;text-align:center;">{count}</td>
      <td style="padding:6px 12px;border:1px solid #1e2d4a;font-size:13px;text-align:center;">{status}</td>
    </tr>"""
    
    html += """
  </table>
</div>"""

    # Top tags
    if top_tags:
        html += """
<div style="background:#151d2e;border:1px solid #1e2d4a;border-radius:12px;padding:20px;margin-bottom:20px;">
  <h2 style="color:#06b6d4;font-size:16px;margin:0 0 14px;">🏷 Top Threat Categories</h2>
  <p style="font-size:13px;color:#94a3b8;">"""
        html += " &nbsp;|&nbsp; ".join(f"<strong>{tag}</strong> ({count})" for tag, count in top_tags)
        html += "</p></div>"

    # Critical IOCs table
    if critical_iocs:
        html += """
<div style="background:#151d2e;border:1px solid #1e2d4a;border-radius:12px;padding:20px;margin-bottom:20px;">
  <h2 style="color:#ff1744;font-size:16px;margin:0 0 14px;">🔴 Critical IOCs</h2>
  <table style="width:100%;border-collapse:collapse;">
    <tr style="background:rgba(0,0,0,0.3);">
      <th style="padding:8px;text-align:left;border:1px solid #1e2d4a;font-size:11px;color:#64748b;">Type</th>
      <th style="padding:8px;text-align:left;border:1px solid #1e2d4a;font-size:11px;color:#64748b;">Indicator</th>
      <th style="padding:8px;text-align:left;border:1px solid #1e2d4a;font-size:11px;color:#64748b;">Source</th>
      <th style="padding:8px;text-align:left;border:1px solid #1e2d4a;font-size:11px;color:#64748b;">Tags</th>
    </tr>"""
        for ioc in critical_iocs:
            val = ioc["value"][:70] + ("…" if len(ioc["value"]) > 70 else "")
            tags = ", ".join((ioc.get("tags") or [])[:3])
            html += f"""
    <tr>
      <td style="padding:6px 8px;border:1px solid #1e2d4a;font-size:11px;text-transform:uppercase;color:#ff1744;">{ioc['type']}</td>
      <td style="padding:6px 8px;border:1px solid #1e2d4a;font-size:11px;font-family:monospace;word-break:break-all;">{val}</td>
      <td style="padding:6px 8px;border:1px solid #1e2d4a;font-size:11px;">{ioc['source']}</td>
      <td style="padding:6px 8px;border:1px solid #1e2d4a;font-size:11px;color:#94a3b8;">{tags}</td>
    </tr>"""
        html += """
  </table>
</div>"""

    # High IOCs table
    if high_iocs:
        html += """
<div style="background:#151d2e;border:1px solid #1e2d4a;border-radius:12px;padding:20px;margin-bottom:20px;">
  <h2 style="color:#ff6d00;font-size:16px;margin:0 0 14px;">🟠 High Priority IOCs (Top 15)</h2>
  <table style="width:100%;border-collapse:collapse;">
    <tr style="background:rgba(0,0,0,0.3);">
      <th style="padding:8px;text-align:left;border:1px solid #1e2d4a;font-size:11px;color:#64748b;">Type</th>
      <th style="padding:8px;text-align:left;border:1px solid #1e2d4a;font-size:11px;color:#64748b;">Indicator</th>
      <th style="padding:8px;text-align:left;border:1px solid #1e2d4a;font-size:11px;color:#64748b;">Source</th>
      <th style="padding:8px;text-align:left;border:1px solid #1e2d4a;font-size:11px;color:#64748b;">Tags</th>
    </tr>"""
        for ioc in high_iocs:
            val = ioc["value"][:70] + ("…" if len(ioc["value"]) > 70 else "")
            tags = ", ".join((ioc.get("tags") or [])[:3])
            html += f"""
    <tr>
      <td style="padding:6px 8px;border:1px solid #1e2d4a;font-size:11px;text-transform:uppercase;color:#ff6d00;">{ioc['type']}</td>
      <td style="padding:6px 8px;border:1px solid #1e2d4a;font-size:11px;font-family:monospace;word-break:break-all;">{val}</td>
      <td style="padding:6px 8px;border:1px solid #1e2d4a;font-size:11px;">{ioc['source']}</td>
      <td style="padding:6px 8px;border:1px solid #1e2d4a;font-size:11px;color:#94a3b8;">{tags}</td>
    </tr>"""
        html += """
  </table>
</div>"""

    # IOC type breakdown
    html += """
<div style="background:#151d2e;border:1px solid #1e2d4a;border-radius:12px;padding:20px;margin-bottom:20px;">
  <h2 style="color:#06b6d4;font-size:16px;margin:0 0 14px;">📋 IOC Type Breakdown</h2>
  <table style="width:100%;border-collapse:collapse;">
    <tr style="background:rgba(0,0,0,0.3);">
      <th style="padding:8px 12px;text-align:left;border:1px solid #1e2d4a;font-size:12px;color:#64748b;">Type</th>
      <th style="padding:8px 12px;text-align:center;border:1px solid #1e2d4a;font-size:12px;color:#64748b;">Count</th>
    </tr>"""
    for ioc_type in ["ip", "url", "hash", "domain", "cve", "email"]:
        count = stats["type_counts"].get(ioc_type, 0)
        if count > 0:
            html += f"""
    <tr>
      <td style="padding:6px 12px;border:1px solid #1e2d4a;font-size:13px;text-transform:uppercase;">{ioc_type}</td>
      <td style="padding:6px 12px;border:1px solid #1e2d4a;font-size:13px;text-align:center;">{count}</td>
    </tr>"""
    
    html += """
  </table>
</div>

<div style="text-align:center;padding:20px;color:#64748b;font-size:11px;">
  🎯 IOC HUNTER — Automated Threat Intelligence | Generated by GitHub Actions
</div>

</body>
</html>"""
    
    with open(OUTPUT_REPORT, "w", encoding="utf-8") as f:
        f.write(html)


# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    run_pipeline()
