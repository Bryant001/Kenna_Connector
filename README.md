# Veracode Reporting API → Kenna Connector (WORK IN PROGRESS)

**THIS SCRIPT IS SPECIFICALLY MADE FOR CORELOGIC/COTALITY** — but it can be adapted for other customers who use Kenna.

This script pulls findings from Veracode’s **Reporting API** (Static, Dynamic, SCA, and MPT) for specific `app_id`s and converts them into a **Kenna Data Importer (KDI v2)** payload for manual ingestion.

**Kenna Data Importer docs:**  
https://help.kennasecurity.com/hc/en-us/articles/360026413111-Data-Importer-JSON-Connector

It generates:

- The **raw JSON output** directly from Veracode’s Reporting API  
- A **KDI (Kenna Data Importer) payload** (`version: 2`) that can be uploaded via the Kenna UI

---

## 🔍 Use Cases

- Ingest Veracode findings into Kenna via the **custom Data Importer** connector  
- Provide a path to **scale ingestion across all app profiles** once mappings are validated (the stock Veracode connector that uses the Findings API can take many hours to run)

---

## 📦 Output

Running the script produces:

```
.
├── findings_<timestamp>.json         ← Raw Veracode Reporting API findings  
└── kdi_payload_<timestamp>.json      ← Kenna-ready JSON for manual upload
```

- Example outputs are available in the **Example Outputs** folder  
- Upload `kdi_payload_*.json` in **Kenna UI → Connectors → Data Importer**

---

## ⚠️ Current Status

> 🧪 **This is still IN-PROGRESS**  
> As of **August 5, 2025**, we are testing with **1–2 app profiles** at a time  
>  
> Once mappings are verified and Kenna ingests the data reliably, we can scale to:  
> - More scan types  
> - All app profiles in the Veracode account

---

## 🧩 Known Limitations

| Issue | Details |
|-------|---------|
| **Missing CWE for some SCA CVEs** | Reporting API may not return a `cwe_id` for every `cve_id`. Customer approved leaving `cwe_identifiers` omitted for SCA to keep ingestion clean. |

---

## 🛠 Prerequisites

- Python 3.9+  
- Install all dependencies using the provided `requirements.txt`:

```bash
pip install -r requirements.txt
```

- Authentication:  
  You can **hard-code** your Veracode API ID/Secret at the top of the script, or store them via environment variables or the local credentials file:

```bash
export VERACODE_API_KEY_ID=your_id
export VERACODE_API_KEY_SECRET=your_secret
```

> The credentials file should be stored in `~/.veracode/credentials` and automatically referenced if the variables are not set

---

## 🚀 How to Run

```bash
python reporting_api_to_kenna_connector.py
```

The script will:

1. Pull findings from the last **180 days**  
2. Run separately for each `app_id` in `APP_IDS`  
3. Save the raw Reporting API output  
4. Transform to a **KDI v2** payload  
5. Write timestamped `.json` files  

---

## 📋 Current Field Mapping Overview (as of 8-5-2025)

> Kenna validates the **(scanner_type, name)** pair in `vuln_defs`.  
> This script ensures every `(scanner_type, vuln_def_name)` used in `assets[*].vulns[*]` has a matching entry in `vuln_defs`.

| Kenna Field           | Value/Source (by scan type) |
|-----------------------|------------------------------|
| `scanner_identifier`  | **SCA:** `veracode <CVE>` (e.g., `veracode CVE-2025-24813`) or `veracode SRCCLR-SID-#####` if no CVE. **Static:** `veracode <flaw_id>`. **Dynamic/MPT:** `veracode <finding_id>`. |
| `scanner_type`        | `Veracode <scan type>` (e.g., `Veracode SCA`, `Veracode Static Analysis`, `Veracode Dynamic Analysis`) |
| `vuln_def_name`       | **SCA:** `<CVE>` (fallback to `SRCCLR-SID-#####`, else `CWE-###`). **Non-SCA:** `CWE-###`. |
| `scanner_score`       | **SCA:** `nvd_cvss3_score` rounded up to an integer. **SAST/DAST/MPT:** `(severity * 2)` for testing to fit 2–10. Need to validate with customer if this is what they want |
| `status`              | `status` |
| `created_at`          | `found_date` |
| `last_seen_at`        | `last_found_date` or `last_updated_date` |
| `vuln_defs[].cve_identifiers` | **Only for SCA** (set to `cve_id` when present) |
| `vuln_defs[].cwe_identifiers` | **Only for non-SCA** (set to `CWE-###`) |

---

## Once we confirm the initial ingestion works, then test further:

- Replace the manual `APP_IDS` list with a lookup from the **Applications API**, but start with a handful first and then scale  
- Add `"Manual Analysis"` (MPT) when needed   

---

## There's another script in this repo that runs the same way, but adds specific tags:

```bash
python reporting_api_to_kenna_connector_custom_tags.py
```
