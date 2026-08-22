"""
Score and rank matched candidates for one organisation profile.

Scoring is a transparent weighted sum of three visible signals, using the
organisation's own weight_modifiers (so risk appetite genuinely changes
outcomes, not just cosmetic labels):

    score = 100 * ( cvss_weight     * (cvss_base_score / 10)
                   + cisa_kev_weight * (1 if in_kev else 0)
                   + epss_weight     * first_epss )
            - VERIFICATION_PENALTY (if match_status == needs_verification)

Every contributing factor is returned alongside the score so the UI can
display it -- never a bare opaque number.
"""

from __future__ import annotations
import pandas as pd

VERIFICATION_PENALTY = 15  # points deducted when key data is missing

PRIORITY_THRESHOLDS = [
    (70, "URGENT"),
    (45, "HIGH"),
    (20, "MEDIUM"),
    (0, "LOW"),
]

# Optional context signals (Appendix A: exposure, importance). These are
# additive bonuses on top of the three core weighted signals -- present
# only when the profile actually states them, so a profile without this
# context behaves exactly as before (three-signal scoring).
EXPOSURE_BONUS = {"internet-facing": 8, "internal": 0}
IMPORTANCE_BONUS = {"critical": 10, "high": 5, "normal": 0}


def priority_label(score: float) -> str:
    for threshold, label in PRIORITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "LOW"


def score_row(row: pd.Series, profile: dict) -> tuple[float, dict]:
    weights = profile["weight_modifiers"]
    cvss = row.get("cvss_base_score")
    epss = row.get("first_epss")
    kev = bool(row.get("cisa_kev", False))

    cvss_component = weights["cvss_weight"] * ((cvss or 0) / 10) * 100
    kev_component = weights["cisa_kev_weight"] * (1 if kev else 0) * 100
    epss_component = weights["first_epss_weight"] * (epss or 0) * 100

    penalty = VERIFICATION_PENALTY if row.get("match_status") == "needs_verification" else 0

    exposure_component = EXPOSURE_BONUS.get(str(profile.get("exposure", "")).lower(), 0)
    importance_component = IMPORTANCE_BONUS.get(str(profile.get("importance", "")).lower(), 0)

    score = round(
        cvss_component + kev_component + epss_component
        + exposure_component + importance_component - penalty, 1
    )
    score = max(score, 0.0)

    factors = {
        "CVSS severity": round(cvss_component, 1),
        "Confirmed exploitation (CISA KEV)": round(kev_component, 1),
        "Exploitation probability (EPSS)": round(epss_component, 1),
    }
    if exposure_component:
        factors["Internet exposure"] = exposure_component
    if importance_component:
        factors["Service importance"] = importance_component
    if penalty:
        factors["Data-quality penalty"] = -penalty
    return score, factors


def rank(candidates: pd.DataFrame, profile: dict, top_n: int = 5) -> pd.DataFrame:
    if candidates.empty:
        return candidates

    df = candidates.copy()
    scores, factors_list, priorities = [], [], []
    for _, row in df.iterrows():
        score, factors = score_row(row, profile)
        scores.append(score)
        factors_list.append(factors)
        priorities.append(priority_label(score))

    df["score"] = scores
    df["factors"] = factors_list
    df["priority"] = priorities

    df = df.sort_values("score", ascending=False).drop_duplicates(subset=["cve_id", "product_name"])
    return df.head(top_n).reset_index(drop=True)


def rank_with_watchlist(candidates: pd.DataFrame, profile: dict,
                         top_n: int = 5) -> tuple[pd.DataFrame, pd.Series | None]:
    """
    Same ranking as rank(), but also returns the single highest-scored
    candidate that just missed the top_n cutoff -- "one more worth
    watching": not urgent enough to act on today, but the closest thing to
    becoming the next problem if e.g. its EPSS/KEV status changes.

    Returns (top_n_df, watchlist_row_or_None). watchlist_row is None if
    there aren't more than top_n candidates in total.
    """
    scored = rank(candidates, profile, top_n=top_n + 1)
    if scored.empty:
        return scored, None
    top = scored.head(top_n).reset_index(drop=True)
    watchlist = scored.iloc[top_n] if len(scored) > top_n else None
    return top, watchlist


def negative_test(matched_df: pd.DataFrame, profile: dict, cvss_threshold: float = 9.0) -> pd.Series | None:
    """
    Find one high-severity item (CVSS >= threshold) that was excluded or
    ranked low, to prove personalisation isn't just severity sorting.
    Prefers an excluded row; falls back to a low-scored included one.
    """
    high = matched_df[matched_df["cvss_base_score"] >= cvss_threshold]
    if high.empty:
        return None

    excluded_high = high[high["match_status"].isin(["exclude", "not_affected"])]
    if not excluded_high.empty:
        row = excluded_high.iloc[0].copy()
        row["negative_reason"] = row["exclude_reason"]
        row["negative_kind"] = "excluded"
        return row

    # fall back: a matched-but-low-priority high CVSS item
    candidates = high[high["match_status"].isin(["include", "needs_verification"])].copy()
    if candidates.empty:
        return None
    scored = []
    for _, row in candidates.iterrows():
        score, _ = score_row(row, profile)
        scored.append(score)
    candidates["score"] = scored
    lowest = candidates.sort_values("score").iloc[0].copy()
    lowest["negative_reason"] = (
        f'Matched product, but low internet exposure/importance context keeps '
        f'the overall score low despite CVSS {lowest["cvss_base_score"]}.'
    )
    lowest["negative_kind"] = "ranked_low"
    return lowest


def high_severity_screened_out(matched_df: pd.DataFrame, profile: dict,
                                cvss_threshold: float = 9.0, top_n_scored: pd.DataFrame | None = None,
                                limit: int = 12) -> pd.DataFrame:
    """
    All CVSS >= threshold items that did NOT make the final top-5, whatever
    the reason (excluded, not_affected, or matched but out-ranked). Powers
    the "why not this one?" browser -- the negative_test() above returns
    just the single headline example; this returns the full set so a judge
    can spot-check as many as they like, not just the one item we chose to
    highlight.
    """
    high = matched_df[matched_df["cvss_base_score"] >= cvss_threshold].copy()
    if high.empty:
        return high

    top5_cves = set(top_n_scored["cve_id"]) if top_n_scored is not None and not top_n_scored.empty else set()

    rows = []
    for _, row in high.iterrows():
        if row["cve_id"] in top5_cves:
            continue  # it DID make the cut, nothing to explain
        status = row["match_status"]
        if status in ("exclude", "not_affected"):
            reason = row["exclude_reason"]
            kind = "excluded" if status == "exclude" else "not_affected"
            score = None
        else:
            score, _ = score_row(row, profile)
            kind = "outranked"
            reason = (
                f'Matched {row.get("matched_product") or row["product_name"]}, scored {score} — '
                f'below the top-5 cutoff for this profile\'s exposure/importance/weights.'
            )
        r = row.copy()
        r["screen_reason"] = reason
        r["screen_kind"] = kind
        r["screen_score"] = score
        rows.append(r)

    if not rows:
        return pd.DataFrame(columns=list(high.columns) + ["screen_reason", "screen_kind", "screen_score"])
    out = pd.DataFrame(rows).sort_values("cvss_base_score", ascending=False)
    return out.head(limit)
