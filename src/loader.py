"""
Load and validate the vulnerability dataset and organisation profiles.

Real schema (confirmed from the organiser-provided starter pack):

vulnerabilities.csv columns:
    cve_id, product_name, cvss_base_score, cisa_kev, first_epss

profiles.json (demo / built-in profiles) shape:
    {
      "organizations": [
        {
          "org_id", "name", "sector", "risk_appetite",
          "weight_modifiers": {"cvss_weight", "cisa_kev_weight", "first_epss_weight"},
          "critical_products": [str, ...]
        }, ...
      ]
    }

A user-supplied "custom" profile (built from the Streamlit form) uses the
same internal shape so the rest of the pipeline never has to know whether
a profile came from the demo file or the user.
"""

from __future__ import annotations
import json
import pandas as pd
from pathlib import Path

REQUIRED_VULN_COLUMNS = [
    "cve_id", "product_name", "cvss_base_score", "cisa_kev", "first_epss",
]

# Columns from the full production schema (Appendix A of the brief). All
# optional -- when present they unlock vendor-qualified and version-range
# matching (src/version_match.py); when absent the engine degrades
# gracefully to product-name-only matching, exactly as before.
OPTIONAL_VULN_COLUMNS = [
    "vendor", "version_start", "version_end", "version_note",
    "published_date", "reference_url", "source_snapshot_date", "description",
]

DEFAULT_WEIGHTS = {
    "cvss_weight": 0.34,
    "cisa_kev_weight": 0.33,
    "first_epss_weight": 0.33,
}


def load_vulnerabilities(path: str | Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    missing = [c for c in REQUIRED_VULN_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"vulnerabilities file is missing required columns: {missing}")

    df["cve_id"] = df["cve_id"].astype(str).str.strip()
    df["product_name"] = df["product_name"].astype(str).str.strip()
    df["cvss_base_score"] = pd.to_numeric(df["cvss_base_score"], errors="coerce")
    df["first_epss"] = pd.to_numeric(df["first_epss"], errors="coerce")

    # cisa_kev may arrive as bool, "True"/"False" strings, or 0/1
    df["cisa_kev"] = df["cisa_kev"].apply(_coerce_bool)

    # Ensure optional production-schema columns always exist (as empty
    # strings, never NaN-as-float) so downstream code never has to branch
    # on "does this column exist" -- only on "is it filled in".
    for col in OPTIONAL_VULN_COLUMNS:
        if col not in df.columns:
            df[col] = ""
        else:
            df[col] = df[col].fillna("").astype(str).str.strip()

    # Never silently drop rows with missing scores -> flag instead
    df["data_quality"] = "ok"
    df.loc[df["cvss_base_score"].isna(), "data_quality"] = "missing_cvss"
    df.loc[df["first_epss"].isna(), "data_quality"] = "missing_epss"

    return df.drop_duplicates(subset=["cve_id", "product_name"]).reset_index(drop=True)


def _coerce_bool(v) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return bool(v)
    return str(v).strip().lower() in {"true", "1", "yes"}


def load_demo_profiles(path: str | Path) -> list[dict]:
    with open(path) as f:
        raw = json.load(f)
    profiles = []
    for org in raw.get("organizations", []):
        profiles.append(normalize_profile(org))
    return profiles


def normalize_profile(org: dict) -> dict:
    """Ensure every profile (demo or user-built) has a consistent shape.

    Accepts either (or both) of:
      - critical_products: [str, ...]                     (simple schema)
      - technologies: [{vendor, product, version}, ...]    (Appendix A schema,
        unlocks vendor-qualified + version-range matching)
    plus optional context used to modulate priority even when the same
    technical flaw is shared across organisations:
      - exposure: "internet-facing" | "internal"
      - importance: "critical" | "high" | "normal"
    """
    weights = org.get("weight_modifiers") or DEFAULT_WEIGHTS
    technologies = []
    for t in org.get("technologies", []) or []:
        if isinstance(t, str):
            technologies.append({"vendor": "", "product": t.strip(), "version": ""})
        elif isinstance(t, dict) and str(t.get("product", "")).strip():
            technologies.append({
                "vendor": str(t.get("vendor", "")).strip(),
                "product": str(t.get("product", "")).strip(),
                "version": str(t.get("version", "")).strip(),
            })

    return {
        "org_id": org.get("org_id", org.get("name", "custom")),
        "name": org.get("name", "Unnamed Organisation"),
        "sector": org.get("sector", "Not specified"),
        "risk_appetite": org.get("risk_appetite", "Medium"),
        "weight_modifiers": {
            "cvss_weight": float(weights.get("cvss_weight", DEFAULT_WEIGHTS["cvss_weight"])),
            "cisa_kev_weight": float(weights.get("cisa_kev_weight", DEFAULT_WEIGHTS["cisa_kev_weight"])),
            "first_epss_weight": float(weights.get("first_epss_weight", DEFAULT_WEIGHTS["first_epss_weight"])),
        },
        "critical_products": [p.strip() for p in org.get("critical_products", []) if str(p).strip()],
        "technologies": technologies,
        "service": org.get("service", ""),
        "exposure": org.get("exposure", ""),
        "importance": org.get("importance", ""),
        "source": org.get("source", "demo"),
    }


def build_custom_profile(name: str, sector: str, risk_appetite: str,
                          critical_products: list[str],
                          cvss_weight: float, kev_weight: float, epss_weight: float,
                          exposure: str = "", importance: str = "", service: str = "") -> dict:
    total = cvss_weight + kev_weight + epss_weight
    if total <= 0:
        cvss_weight, kev_weight, epss_weight = DEFAULT_WEIGHTS.values()
        total = 1.0
    return normalize_profile({
        "org_id": f"custom-{name.strip().lower().replace(' ', '-')}" if name.strip() else "custom-org",
        "name": name.strip() or "My Organisation",
        "sector": sector.strip() or "Not specified",
        "risk_appetite": risk_appetite,
        "weight_modifiers": {
            "cvss_weight": cvss_weight / total,
            "cisa_kev_weight": kev_weight / total,
            "first_epss_weight": epss_weight / total,
        },
        "critical_products": critical_products,
        "exposure": exposure,
        "importance": importance,
        "service": service,
        "source": "custom",
    })
