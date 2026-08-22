"""
Optional LIVE data ingestion from the three public sources named in the
brief: NIST NVD, CISA KEV, FIRST EPSS.

This is intentionally kept separate from loader.py: the app must keep
working fully offline from the bundled CSV (per the brief's "no live API
dependency" requirement for the core demo). This module is the production
upgrade path -- a small on-disk cache (data/cache/*.json, TTL-based) so a
real deployment can refresh data periodically without hammering the public
APIs or hard-failing when they're unreachable/rate-limited.

Usage:
    from src.live_sources import refresh_live_dataset
    df, meta = refresh_live_dataset(keywords=["apache", "openssl", ...])

Design notes:
- NVD's public API rate-limits unauthenticated callers to ~5 req/30s, so
  keyword queries are paced and results are cached for CACHE_TTL_SECONDS.
- KEV and EPSS are bulk single-file downloads and are cached whole.
- Every network call is wrapped; any failure returns cached data if
  present, otherwise an empty frame with a clear `source_status` note --
  never a silent crash, and the caller always knows what happened.
"""

from __future__ import annotations
import json
import time
import logging
from pathlib import Path
from typing import Iterable

import pandas as pd
import requests

logger = logging.getLogger("vuln_triage.live_sources")

CACHE_DIR = Path(__file__).parent.parent / "data" / "cache"
CACHE_TTL_SECONDS = 6 * 60 * 60  # refresh at most every 6 hours

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
FIRST_EPSS_URL = "https://api.first.org/data/v1/epss"

REQUEST_TIMEOUT = 20
NVD_PAGE_DELAY = 6.5  # seconds between unauthenticated NVD requests (rate-limit safe)


def _cache_path(name: str) -> Path:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return CACHE_DIR / f"{name}.json"


def _read_cache(name: str) -> dict | None:
    path = _cache_path(name)
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text())
        age = time.time() - payload.get("_fetched_at", 0)
        payload["_fresh"] = age < CACHE_TTL_SECONDS
        payload["_age_seconds"] = age
        return payload
    except Exception:
        logger.warning("Cache file %s is corrupt; ignoring.", path)
        return None


def _write_cache(name: str, data: dict) -> None:
    data["_fetched_at"] = time.time()
    _cache_path(name).write_text(json.dumps(data))


def fetch_cisa_kev(force: bool = False) -> tuple[pd.DataFrame, str]:
    """Returns (dataframe of KEV CVE IDs, status message)."""
    cached = _read_cache("cisa_kev")
    if cached and not force and cached.get("_fresh"):
        return pd.DataFrame(cached["vulnerabilities"]), "cache"

    try:
        resp = requests.get(CISA_KEV_URL, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        payload = resp.json()
        vulns = payload.get("vulnerabilities", [])
        _write_cache("cisa_kev", {"vulnerabilities": vulns})
        return pd.DataFrame(vulns), "live"
    except Exception as e:
        logger.warning("CISA KEV fetch failed: %s", e)
        if cached:
            return pd.DataFrame(cached["vulnerabilities"]), "stale_cache"
        return pd.DataFrame(columns=["cveID"]), "unavailable"


def fetch_epss_bulk(force: bool = False) -> tuple[pd.DataFrame, str]:
    """Bulk EPSS scores for all scored CVEs (FIRST publishes a full CSV/JSON daily)."""
    cached = _read_cache("epss_bulk")
    if cached and not force and cached.get("_fresh"):
        return pd.DataFrame(cached["scores"]), "cache"

    try:
        resp = requests.get(FIRST_EPSS_URL, params={"envelope": "false"}, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        rows = resp.json().get("data", [])
        _write_cache("epss_bulk", {"scores": rows})
        return pd.DataFrame(rows), "live"
    except Exception as e:
        logger.warning("FIRST EPSS fetch failed: %s", e)
        if cached:
            return pd.DataFrame(cached["scores"]), "stale_cache"
        return pd.DataFrame(columns=["cve", "epss"]), "unavailable"


def fetch_nvd_by_keyword(keyword: str, results_per_page: int = 50) -> tuple[list[dict], str]:
    """One NVD keyword search (paced to respect the public rate limit)."""
    cache_key = f"nvd_{keyword.lower().replace(' ', '_')}"
    cached = _read_cache(cache_key)
    if cached and cached.get("_fresh"):
        return cached["items"], "cache"

    try:
        resp = requests.get(
            NVD_API_URL,
            params={"keywordSearch": keyword, "resultsPerPage": results_per_page},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        items = resp.json().get("vulnerabilities", [])
        _write_cache(cache_key, {"items": items})
        time.sleep(NVD_PAGE_DELAY)
        return items, "live"
    except Exception as e:
        logger.warning("NVD fetch failed for keyword=%r: %s", keyword, e)
        if cached:
            return cached["items"], "stale_cache"
        return [], "unavailable"


def _nvd_item_to_row(item: dict) -> dict | None:
    cve = item.get("cve", {})
    cve_id = cve.get("id")
    if not cve_id:
        return None
    metrics = cve.get("metrics", {})
    cvss = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            cvss = metrics[key][0]["cvssData"].get("baseScore")
            break
    descriptions = cve.get("descriptions", [])
    desc_en = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
    refs = cve.get("references", [])
    ref_url = refs[0]["url"] if refs else ""
    return {
        "cve_id": cve_id,
        "cvss_base_score": cvss,
        "published_date": cve.get("published", ""),
        "description": desc_en,
        "reference_url": ref_url,
    }


def refresh_live_dataset(
    keywords: Iterable[str],
    product_lookup: dict[str, str] | None = None,
) -> tuple[pd.DataFrame, dict]:
    """
    Build a vulnerabilities DataFrame in the same schema as loader.py's
    bundled CSV, sourced live from NVD + CISA KEV + FIRST EPSS, for the
    given list of product keywords (typically an org's critical_products).

    `product_lookup` optionally maps keyword -> display product_name to use
    in the output row (defaults to the keyword itself).

    Returns (dataframe, meta) where meta records per-source status so the
    caller can display honest provenance ("NVD: live", "KEV: stale_cache",
    ...) instead of pretending everything always succeeds.
    """
    product_lookup = product_lookup or {}
    meta = {"sources": {}, "keywords_queried": list(keywords)}

    kev_df, kev_status = fetch_cisa_kev()
    meta["sources"]["cisa_kev"] = kev_status
    kev_ids = set(kev_df["cveID"]) if "cveID" in kev_df.columns else set()

    epss_df, epss_status = fetch_epss_bulk()
    meta["sources"]["first_epss"] = epss_status
    epss_map = {}
    if not epss_df.empty and "cve" in epss_df.columns:
        epss_map = dict(zip(epss_df["cve"], pd.to_numeric(epss_df["epss"], errors="coerce")))

    all_rows = []
    nvd_statuses = []
    for kw in keywords:
        items, status = fetch_nvd_by_keyword(kw)
        nvd_statuses.append(status)
        product_name = product_lookup.get(kw, kw)
        for item in items:
            row = _nvd_item_to_row(item)
            if row is None:
                continue
            row["product_name"] = product_name
            row["cisa_kev"] = row["cve_id"] in kev_ids
            row["first_epss"] = epss_map.get(row["cve_id"])
            all_rows.append(row)

    meta["sources"]["nvd"] = "live" if "live" in nvd_statuses else (
        "cache" if "cache" in nvd_statuses else "unavailable"
    )

    if not all_rows:
        return pd.DataFrame(columns=[
            "cve_id", "product_name", "cvss_base_score", "cisa_kev", "first_epss",
            "published_date", "description", "reference_url",
        ]), meta

    df = pd.DataFrame(all_rows)
    df["data_quality"] = "ok"
    df.loc[df["cvss_base_score"].isna(), "data_quality"] = "missing_cvss"
    df.loc[df["first_epss"].isna(), "data_quality"] = "missing_epss"
    for col in ("vendor", "version_start", "version_end", "version_note", "source_snapshot_date"):
        df[col] = ""
    df = df.drop_duplicates(subset=["cve_id", "product_name"]).reset_index(drop=True)
    return df, meta
