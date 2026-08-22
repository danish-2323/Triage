"""
Turn a scored row into the plain-language fields required by the brief:
priority, plain title, matched context, why it matters, potential impact,
next step, confidence (+reason), source/traceability.

Every field is built from a fixed template referencing only fields present
in the row -- no free-text generation of facts. An optional LLM phrasing
layer (see llm_phraser.py) may restyle the *wording*, never the facts.
"""

from __future__ import annotations
import pandas as pd

NEXT_STEP_BY_PRIORITY = {
    "URGENT": "Patch immediately or restrict access to this product today.",
    "HIGH": "Schedule a patch this week and review the vendor advisory now.",
    "MEDIUM": "Review the vendor advisory and plan a patch in the next cycle.",
    "LOW": "Monitor; no immediate action required.",
}

CONFIDENCE_REASON = {
    "include": "Product name matched cleanly and all scoring data (CVSS, KEV, EPSS) was present.",
    "needs_verification": "Product matched, but some scoring data (CVSS or EPSS) was missing from the source record.",
}


def build_explanation(row: pd.Series, profile: dict) -> dict:
    priority = row["priority"]
    confidence = "High" if row["match_status"] == "include" else "Medium"

    plain_title = _plain_title(row, priority)
    why_bits = []
    if row.get("cisa_kev"):
        why_bits.append("it is confirmed as actively exploited (CISA KEV)")
    if row.get("first_epss") is not None and not pd.isna(row.get("first_epss")) and row["first_epss"] > 0.3:
        why_bits.append(f"there is a {row['first_epss']*100:.0f}% estimated chance of exploitation in the next 30 days (EPSS)")
    if row.get("cvss_base_score") is not None and not pd.isna(row.get("cvss_base_score")) and row["cvss_base_score"] >= 7:
        why_bits.append(f"its technical severity is high (CVSS {row['cvss_base_score']})")
    if not why_bits:
        why_bits.append("it affects a product this organisation marked as critical")

    why_it_matters = (
        f"This affects {row['matched_product']}, which {profile['name']} has flagged as a critical product. "
        + "In addition, " + "; and ".join(why_bits) + "."
    )

    return {
        "cve_id": row["cve_id"],
        "priority": priority,
        "score": row["score"],
        "plain_title": plain_title,
        "matched_context": f"Matched product: {row['matched_product']} (organisation: {profile['name']}, sector: {profile['sector']})",
        "why_it_matters": why_it_matters,
        "potential_impact": _potential_impact(row),
        "next_step": NEXT_STEP_BY_PRIORITY.get(priority, "Review and assess."),
        "confidence": confidence,
        "confidence_reason": CONFIDENCE_REASON[row["match_status"]],
        "factors": row["factors"],
        "source_name": "Organiser-provided vulnerability snapshot",
        "published_date": (row.get("published_date") or None) or None,
        "source_snapshot_date": (row.get("source_snapshot_date") or None) or None,
        "reference_url": (row.get("reference_url") or None) or None,
        "raw_row": row,
    }


def _plain_title(row: pd.Series, priority: str) -> str:
    kev = " actively exploited" if row.get("cisa_kev") else ""
    return f"{row['matched_product']} has a{kev} vulnerability rated {priority.title()}"


def _potential_impact(row: pd.Series) -> str:
    cvss = row.get("cvss_base_score")
    if pd.isna(cvss):
        return "Technical severity is unavailable in the source data; impact could not be automatically estimated."
    if cvss >= 9:
        return "Critical severity flaw; successful exploitation could lead to full compromise of this product."
    if cvss >= 7:
        return "High severity flaw; successful exploitation could seriously affect confidentiality, integrity, or availability."
    if cvss >= 4:
        return "Moderate severity flaw; limited but real risk if exploited."
    return "Low severity flaw; limited impact if exploited."


def no_match_message(profile: dict) -> str:
    return f"Nothing matched this profile in the supplied data for {profile['name']}."
