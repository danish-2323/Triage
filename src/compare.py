"""
Diff helpers for the "compare two profiles" view. Pure functions, no
Streamlit dependency, so they're easy to unit test independently of the UI.

Two things a judge is asked to check (brief, section 8, demo-time step 2):
  1. the top-5 actually changes between profiles
  2. which profile fields caused that difference

`profile_field_diff` answers (2). `top5_diff` answers (1) at item level --
which CVEs are unique to one profile's top-5, shared by both, and how their
rank/score moved.
"""

from __future__ import annotations
import pandas as pd


def _fmt(value) -> str:
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value) or "(none)"
    if value in (None, ""):
        return "(not set)"
    return str(value)


def profile_field_diff(profile_a: dict, profile_b: dict) -> list[dict]:
    """Field-by-field comparison of the inputs that drive matching/ranking.
    Returns only fields that plausibly affect output, each flagged with
    whether it actually differs between the two profiles."""
    fields = [
        ("Sector", profile_a.get("sector"), profile_b.get("sector")),
        ("Exposure", profile_a.get("exposure"), profile_b.get("exposure")),
        ("Service importance", profile_a.get("importance"), profile_b.get("importance")),
        ("Business service", profile_a.get("service"), profile_b.get("service")),
        ("Risk appetite", profile_a.get("risk_appetite"), profile_b.get("risk_appetite")),
        ("Critical products", profile_a.get("critical_products", []), profile_b.get("critical_products", [])),
    ]
    wa, wb = profile_a.get("weight_modifiers", {}), profile_b.get("weight_modifiers", {})
    for key, label in [("cvss_weight", "CVSS weight"), ("cisa_kev_weight", "KEV weight"),
                        ("first_epss_weight", "EPSS weight")]:
        fields.append((label, wa.get(key), wb.get(key)))

    out = []
    for label, va, vb in fields:
        out.append({
            "field": label,
            "a": _fmt(va),
            "b": _fmt(vb),
            "differs": va != vb,
        })
    return out


def top5_diff(top5_a: pd.DataFrame, top5_b: pd.DataFrame) -> list[dict]:
    """Per-CVE comparison across the two ranked top-5 lists: rank and score
    in each (None if it didn't make that profile's top-5), and a plain-
    language movement label."""
    def index_map(df):
        return {row["cve_id"] + "|" + row["product_name"]: (i + 1, row["score"])
                for i, row in df.reset_index(drop=True).iterrows()} if not df.empty else {}

    ia, ib = index_map(top5_a), index_map(top5_b)
    all_keys = list(dict.fromkeys(list(ia.keys()) + list(ib.keys())))

    rows = []
    for key in all_keys:
        cve_id, product = key.split("|", 1)
        rank_a, score_a = ia.get(key, (None, None))
        rank_b, score_b = ib.get(key, (None, None))
        if rank_a and rank_b:
            movement = "same item, both lists" if rank_a == rank_b else "re-ranked"
        elif rank_a and not rank_b:
            movement = "dropped out for profile B"
        else:
            movement = "new for profile B"
        rows.append({
            "cve_id": cve_id, "product_name": product,
            "rank_a": rank_a, "score_a": score_a,
            "rank_b": rank_b, "score_b": score_b,
            "movement": movement,
        })
    return rows
