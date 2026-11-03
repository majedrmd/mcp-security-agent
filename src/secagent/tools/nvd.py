import os
import re

import httpx

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")


def normalize_cve_id(cve_id: str) -> str | None:
    """Return the CVE id in upper case, or None if it is not a valid CVE id."""
    cve_id = cve_id.strip().upper()
    if CVE_PATTERN.match(cve_id):
        return cve_id
    return None


def parse_cve(item: dict) -> dict:
    """Turn one NVD 'vulnerabilities' entry into a small, flat dict."""
    cve = item["cve"]

    description = ""
    for d in cve.get("descriptions", []):
        if d["lang"] == "en":
            description = d["value"]
            break

    # Prefer the newest CVSS version available
    score = severity = vector = version = None
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            metric = metrics[key][0]
            data = metric["cvssData"]
            score = data["baseScore"]
            # v3 keeps severity in cvssData, v2 keeps it one level up
            severity = data.get("baseSeverity") or metric.get("baseSeverity")
            vector = data["vectorString"]
            version = data["version"]
            break

    cwes = set()
    for weakness in cve.get("weaknesses", []):
        for d in weakness["description"]:
            if d["value"].startswith("CWE-"):
                cwes.add(d["value"])

    references = [r["url"] for r in cve.get("references", [])][:5]

    return {
        "id": cve["id"],
        "published": cve.get("published", "")[:10],
        "description": description,
        "cvss_version": version,
        "cvss_score": score,
        "severity": severity,
        "vector": vector,
        "cwes": sorted(cwes),
        "references": references,
    }


async def lookup_cve(cve_id: str) -> dict:
    """Fetch one CVE from NVD. Returns a dict, with an 'error' key if it failed."""
    clean_id = normalize_cve_id(cve_id)
    if clean_id is None:
        return {"error": f"'{cve_id}' is not a valid CVE id. Expected format: CVE-2021-44228"}

    headers = {}
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(NVD_URL, params={"cveId": clean_id}, headers=headers)
    except httpx.TimeoutException:
        return {"error": "NVD did not answer within 10 seconds. Try again later."}
    except httpx.HTTPError as e:
        return {"error": f"Could not reach NVD: {e}"}

    if response.status_code in (403, 429):
        return {"error": "NVD rate limit reached. Wait 30 seconds and try again."}
    if response.status_code != 200:
        return {"error": f"NVD returned HTTP {response.status_code}"}

    vulnerabilities = response.json().get("vulnerabilities", [])
    if not vulnerabilities:
        return {"error": f"{clean_id} was not found in NVD."}

    return parse_cve(vulnerabilities[0])