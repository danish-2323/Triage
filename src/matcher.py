"""
Match a vulnerability dataset against one organisation profile.

Four honest outcomes (Figure 3 of the brief):
  - "include"            : product matches AND (no version data to check,
                            OR installed version confirmed inside the
                            affected range)
  - "needs_verification" : product matches but a version, CVSS or EPSS
                            value is missing/unsafe to compare -- never
                            guessed, never silently dropped
  - "not_affected"        : product matches this org, but the org's
                            installed version is outside the affected
                            range -- an honest exclude with evidence,
                            distinct from "we don't use this product"
  - "exclude"             : product is not used by this organisation at all

Nothing is ever silently dropped -> excluded rows are returned too, each
with a short human-readable reason, so the UI can show "what we ignored".

Backward compatible: if a profile only has `critical_products` (no
`technologies` with versions) and the dataset has no version columns
filled in, behaviour is identical to the original product-name-only
matcher.
"""

from __future__ import annotations
import pandas as pd
from .aliases import names_match
from .version_match import compare_version, VersionOutcome


def _find_technology_match(product_name: str, profile: dict):
    """Return the matching technology entry (dict with vendor/product/version)
    for this vulnerability row, or None. Prefers `technologies` (which may
    carry version info); falls back to plain `critical_products` strings."""
    for tech in profile.get("technologies", []):
        if names_match(product_name, tech["product"]):
            return tech
    for cp in profile.get("critical_products", []):
        if names_match(product_name, cp):
            return {"vendor": "", "product": cp, "version": ""}
    return None


def match_profile(vulnerabilities: pd.DataFrame, profile: dict) -> pd.DataFrame:
    df = vulnerabilities.copy()

    def status_and_reason(row):
        tech = _find_technology_match(row["product_name"], profile)

        if tech is None:
            return pd.Series({
                "match_status": "exclude",
                "matched_product": None,
                "exclude_reason": f'"{row["product_name"]}" is not used by {profile["name"]}',
                "version_outcome": None,
            })

        version_start = row.get("version_start") or None
        version_end = row.get("version_end") or None
        version_note = row.get("version_note") or None
        installed_version = tech.get("version") or None

        has_range_data = bool(version_start or version_end or version_note)
        if has_range_data:
            outcome = compare_version(installed_version, version_start, version_end, version_note)
            if outcome == VersionOutcome.NOT_AFFECTED:
                return pd.Series({
                    "match_status": "not_affected",
                    "matched_product": tech["product"],
                    "exclude_reason": (
                        f'{profile["name"]}\'s installed version ({installed_version}) of '
                        f'{tech["product"]} is outside the affected range '
                        f'({version_start or "unbounded"}\u2013{version_end or "unbounded"}).'
                    ),
                    "version_outcome": outcome.value,
                })
            if outcome == VersionOutcome.NEEDS_VERIFICATION:
                return pd.Series({
                    "match_status": "needs_verification",
                    "matched_product": tech["product"],
                    "exclude_reason": None,
                    "version_outcome": outcome.value,
                })

        if row.get("data_quality", "ok") != "ok":
            return pd.Series({
                "match_status": "needs_verification",
                "matched_product": tech["product"],
                "exclude_reason": None,
                "version_outcome": "affected" if has_range_data else None,
            })

        return pd.Series({
            "match_status": "include",
            "matched_product": tech["product"],
            "exclude_reason": None,
            "version_outcome": "affected" if has_range_data else None,
        })

    result = df.join(df.apply(status_and_reason, axis=1))
    return result


def split_candidates(matched_df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Returns (candidates, excluded). "not_affected" and "exclude" both go
    to the excluded bucket -- both are honest, evidenced non-matches, just
    for different reasons."""
    candidates = matched_df[matched_df["match_status"].isin(["include", "needs_verification"])].copy()
    excluded = matched_df[matched_df["match_status"].isin(["exclude", "not_affected"])].copy()
    return candidates, excluded
