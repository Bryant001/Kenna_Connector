#!/usr/bin/env python3
"""
reporting_api_to_kenna_connector_custom_tags.py
────────────────
WHAT THE SCRIPT DOES:
• Pull FINDINGS (Static / Dynamic / SCA / MPT) updated in the last 180 days for each app_id in APP_IDS.
• Save raw Veracode JSON and a Kenna Data-Importer v2 payload.
• Field Mappings based on - https://help.kennasecurity.com/hc/en-us/articles/360026413111-Data-Importer-JSON-Connector
• This version of the script adds custom tags to the assets and vulnerabilities based on Veracode data.

CURRENT STATE:
• This script is still IN-PROGRESS and mainly used for testing how we can ingest the Reporting API data into Kenna
• As of 7/30/3035 we are still testing with running the Reporting API on 1 or 2 app_ids. 
• Once we figure out how to ingest the data with one app profile, we should scale to do this for ALL App Profiles
"""

from __future__ import annotations
import json, os, sys, time, math, re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Set, Tuple

import requests
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC


# API Call and Credential Settings: 
API_KEY_ID     = "185336e8c554fc4ad2fa809f43e4e77b"    # Hard-coded crednetials in case customers want to quickly test the script with their account
API_KEY_SECRET = "8f24efb247a42e1f56200795a8284673656be85472c166fc9e76f73d3af16ad2fb3934ba57282876d1ea2c43311044946b8ac4da3e78031ef03016096161a48c"    # Leave **both** blank to use env vars or ~/.veracode/credentials file

# You can always test with App_ID 2457394, which is one of their retired App Profiles
APP_IDS     = [1811880]                                         # One or many numeric App IDs. It's the 2nd number in the app profile URL.
SCAN_TYPES  = ["Static Analysis", "Dynamic Analysis", "SCA"]    # MPT can be added optionally as "Manual Analysis"
WINDOW_DAYS = 180                                               # Set amount of days to look back for findings
BASE_URL    = "https://api.veracode.com"
# ─────────────────────────


# ───── Credential Resolution ─────
API_KEY_ID     = API_KEY_ID     or os.getenv("VERACODE_API_KEY_ID", "")
API_KEY_SECRET = API_KEY_SECRET or os.getenv("VERACODE_API_KEY_SECRET", "")

if API_KEY_ID and API_KEY_SECRET:
    auth = RequestsAuthPluginVeracodeHMAC(API_KEY_ID, API_KEY_SECRET)
else:
    # If no args, then the plugin reads ~/.veracode/credentials automatically
    auth = RequestsAuthPluginVeracodeHMAC()

REPORT_EP = f"{BASE_URL}/appsec/v1/analytics/report"


# ───── helper functions ─────
def hal_node(obj: Dict[str, Any], key: str):
    if key in obj: return obj[key]
    emb = obj.get("_embedded", {})
    if isinstance(emb, dict):
        if key in emb: return emb[key]
        rep = emb.get("report")
        if isinstance(rep, dict): return rep.get(key)
    return None

def hal_next(obj): return obj.get("_links", {}).get("next", {}).get("href")

def iso(ts: str | None) -> str | None:
    if not ts: return None
    ts = ts.split(".")[0].replace(" ", "T")
    return ts + "Z" if not ts.endswith("Z") else ts

def add_tag(asset: dict, tag: str) -> None:
    if tag and tag not in asset["tags"]:
        asset["tags"].append(tag)


# ───── collect findings ─────
start_utc = datetime.now(timezone.utc) - timedelta(days=WINDOW_DAYS)
rows, seen = [], set()

# Build Report for specified payload
for app_id in APP_IDS:
    print(f"\n=== app_id {app_id} ===")
    payload = {
        "report_type": "FINDINGS",
        "scan_type":   SCAN_TYPES,
        "app_id":      app_id,
        "last_updated_start_date": start_utc.strftime("%Y-%m-%d %H:%M:%S")
    }

    resp = requests.post(REPORT_EP, json=payload, auth=auth)
    print("POST", resp.status_code)
    if resp.status_code >= 400:
        try:  print(json.dumps(resp.json(), indent=2))
        except ValueError:  print(resp.text or "<non-JSON body>")
        continue

    rid = hal_node(resp.json(), "id") or resp.headers["Location"].split("/")[-1]
    status_url = f"{REPORT_EP}/{rid}"

    while True:
        time.sleep(10)
        if hal_node(requests.get(status_url, auth=auth).json(), "status").upper() == "COMPLETED":
            break

    nxt = status_url
    while nxt:
        page = requests.get(nxt, auth=auth).json()
        for row in (hal_node(page, "content") or hal_node(page, "findings") or []):
            fid = str(row.get("finding_id") or row.get("component_id")
                      or row.get("flaw_id")  or row.get("id"))
            key = f"{app_id}:{fid}"
            if key not in seen:
                seen.add(key)
                rows.append(row)
        nxt = hal_next(page)

print(f"\nTOTAL findings: {len(rows):,}")

# ───── Write Raw JSON ─────
stamp   = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
rawfile = f"findings_{stamp}.json"
with open(rawfile, "w", encoding="utf-8") as f:
    json.dump(rows, f, indent=2)
print("Raw findings →", rawfile)

# ───── Transform to Kenna Data Importer v2 ─────
assets: Dict[str, Dict[str, Any]] = {}
vdefs:  Dict[Tuple[str, str], Dict[str, Any]] = {}

for r in rows:
    aid = str(r["app_id"])
    asset = assets.setdefault(aid, {
        "external_id": aid,
        "application": r["app_name"],
        "tags": [f"BusinessUnit:{r.get('business_unit','UnknownBU')}"],
        "vulns": []
    })

    scan_type = f'Veracode {r["scan_type"]}'

    # Add Kenna-style tags on the asset
    bu = r.get("business_unit", "Unknown")
    bc = r.get("business_criticality") or r.get("business_criticality_rating") or r.get("business_criticality_desc")
    add_tag(asset, f"BusinessUnit: {bu}")
    add_tag(asset, f"veracode_app: {r['app_name']}")
    if bc: add_tag(asset, f"veracode_bc: {bc}")
    add_tag(asset, f"veracode_bu: {bu}")
    scan_label_map = {"SCA": "SCA", "Static Analysis": "STATIC", "Dynamic Analysis": "DAST", "Manual Analysis": "MPT"}
    add_tag(asset, f"veracode_scan_type: {scan_label_map.get(r['scan_type'], r['scan_type'])}")

    # Blank out CVE for Static findings
    if r["scan_type"] == "Static Analysis":
        cve_val = ""
    else:
        cve_val = r.get("cve_id") or ""

    # Build a human-readable vuln_def name
    srcclear_id = (
        r.get("srcclear_id")
        or r.get("sourceclear_id")
        or r.get("srcclr_id")
        or r.get("vulnerability_id")
        or r.get("srcclr_sid")
    )
    cwe_raw   = r.get("cwe_id")
    cwe_ident = f"CWE-{cwe_raw}" if cwe_raw else "CWE-Other"
    if r["scan_type"] == "SCA":
        vdef_name = cve_val or srcclear_id or cwe_ident
    else:
        vdef_name = cwe_ident

    # ----- build scanner_identifier in Kenna's preferred style -----
    if r["scan_type"] == "SCA":
        sid = cve_val or srcclear_id
        if not sid:
            sid = r.get("finding_id") or r.get("component_id") or r.get("id")
        scanner_id = f"veracode {sid}" if sid is not None else "veracode unknown"
    elif r["scan_type"] == "Static Analysis":
        sid = r.get("flaw_id") or r.get("finding_id") or r.get("id")
        scanner_id = f"veracode {sid}" if sid is not None else "veracode unknown"
    else:
        sid = r.get("finding_id") or r.get("id") or r.get("flaw_id")
        scanner_id = f"veracode {sid}" if sid is not None else "veracode unknown"

    if r["scan_type"] == "SCA" and r.get("nvd_cvss3_score"):
        try: score = int(math.ceil(float(r["nvd_cvss3_score"])))
        except ValueError: score = 0
    else:
        score = int(r.get("severity") or 0) * 2

    asset["vulns"].append({
        "scanner_identifier": scanner_id,
        "scanner_type":       scan_type,
        "vuln_def_name":      vdef_name,
        "scanner_score":      score,
        "status":             (r["status"] or "").lower(),
        "created_at":         iso(r.get("found_date")),
        "last_seen_at":       iso(r.get("last_found_date") or r.get("last_updated_date"))
        # TODO: make sure that description/solution is added to the vunls[].  
        # TODO: output vuln description and solution metadata
            # TODO: https://help.kennasecurity.com/hc/en-us/articles/360026413111-Data-Importer-JSON-Connector
            # TODO: https://help.kennasecurity.com/hc/en-us/articles/360026413111-Data-Importer-JSON-Connector#vuln_def2
            # TODO: add the solution to the "vuln_def"
    })

    # ---- build vuln_def ----
    vdef_key = (scan_type, vdef_name)
    if vdef_key not in vdefs:
        vdef_entry = {
            "scanner_type": scan_type,
            "name":         vdef_name,
            "description":  r.get("vulnerability_title") or r.get("description") or ""
            # TODO: should the above be contatonated?  
        }

        # Only include cve_identifiers for SCA findings and if SCA finding is SRCCLR remove cve_identifiers
        if r["scan_type"] == "SCA" and re.search(r"CVE-\d{4}-\d{4,}", cve_val):
            vdef_entry["cve_identifiers"] = cve_val

        # Include CWE for all NON-SCA findings (omit for SCA)
        if r["scan_type"] != "SCA" and cwe_ident:
            vdef_entry["cwe_identifiers"] = cwe_ident

        vdefs[vdef_key] = vdef_entry

kdi = {
    "skip_autoclose": False,
    "version": 2,
    "assets": list(assets.values()),
    "vuln_defs": list(vdefs.values())
}

# KDI (Kenna Data Importer) file created with timestamp. This should be uploaded to Kenna for ingestion.
kdi_file = f"kdi_payload_{stamp}.json"
with open(kdi_file, "w", encoding="utf-8") as f:
    json.dump(kdi, f, indent=2)

print(f"{kdi_file} written – upload this to Kenna Data-Importer.")
