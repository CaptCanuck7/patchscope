"""NVD API client for fetching CVE data and extracting patch references."""

import os
import re
import time
import requests
from dotenv import load_dotenv

load_dotenv()

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def _validate_cve_id(cve_id: str) -> str:
    """Validate and normalize a CVE identifier."""
    cve_id = cve_id.strip().upper()
    if not _CVE_PATTERN.match(cve_id):
        raise ValueError(f"Invalid CVE ID format: {cve_id!r}. Expected CVE-YYYY-NNNNN.")
    return cve_id


def fetch_cve_data(cve_id: str) -> dict:
    """Fetch raw CVE data from the NVD API.

    Args:
        cve_id: CVE identifier, e.g. CVE-2023-38545

    Returns:
        dict with keys: cve_id, description, severity, references (list of urls),
        and raw_data (full NVD response for the vulnerability).
    """
    cve_id = _validate_cve_id(cve_id)

    headers = {}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key
    else:
        # Respect unauthenticated rate limit (5 requests per 30s)
        time.sleep(6)

    resp = requests.get(NVD_API_BASE, params={"cveId": cve_id}, headers=headers, timeout=30)
    resp.raise_for_status()
    data = resp.json()

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        raise ValueError(f"CVE {cve_id} not found in NVD.")

    cve = vulns[0]["cve"]

    # Extract English description
    description = ""
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            description = desc["value"]
            break

    # Extract CVSS severity if available
    severity = None
    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metrics = cve.get("metrics", {}).get(metric_key, [])
        if metrics:
            severity = {
                "version": metric_key,
                "score": metrics[0].get("cvssData", {}).get("baseScore"),
                "severity": metrics[0].get("cvssData", {}).get("baseSeverity"),
            }
            break

    # Collect all references (deduplicate by URL)
    seen_urls = set()
    references = []
    for ref in cve.get("references", []):
        url = ref.get("url", "")
        if url and url not in seen_urls:
            seen_urls.add(url)
            references.append({"url": url, "tags": ref.get("tags", [])})

    return {
        "cve_id": cve_id,
        "description": description,
        "severity": severity,
        "references": references,
        "raw_data": cve,
    }


def extract_patch_urls(cve_id: str) -> dict:
    """Fetch CVE data and extract GitHub commit URLs that are tagged as patches.

    Args:
        cve_id: CVE identifier, e.g. CVE-2023-38545

    Returns:
        dict with keys: cve_id, description, severity, patch_urls (list of
        GitHub commit URLs), all_github_urls (any GitHub URLs in references).
    """
    cve_data = fetch_cve_data(cve_id)

    patch_urls = []
    all_github_urls = []

    for ref in cve_data["references"]:
        url = ref["url"]
        tags = ref["tags"]

        is_github_commit = "github.com" in url and "/commit/" in url

        if "github.com" in url:
            all_github_urls.append(url)

        if is_github_commit and "Patch" in tags:
            patch_urls.append(url)

    # Fallback: if no tagged patches, use any GitHub commit URL
    if not patch_urls:
        patch_urls = [u for u in all_github_urls if "/commit/" in u]

    return {
        "cve_id": cve_data["cve_id"],
        "description": cve_data["description"],
        "severity": cve_data["severity"],
        "patch_urls": patch_urls,
        "all_github_urls": all_github_urls,
    }
