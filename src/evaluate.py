"""
Evaluate the ranking engine's weighting logic against data/gold_set.csv --
a small practitioner-ranked sample with one rank column per demo profile
(e.g. practitioner_rank_bank, practitioner_rank_startup).

IMPORTANT: gold_set.csv is a standalone illustrative sample -- its CVE IDs
are deliberately NOT the same rows as data/vulnerabilities.csv (verified:
zero overlap). Per the brief it exists as "an optional sanity check for
your weights", so this harness scores the gold rows directly with each
profile's own weight_modifiers/exposure/importance and compares the
resulting order to the practitioner's stated rank -- it does not run the
matching pipeline (there is nothing to match; gold rows already carry
product_name).

Reports, per profile:
  - Spearman rank correlation between engine score-order and practitioner
    rank order across the whole gold sample
  - Top-3 agreement: does the engine's #1-3 by score line up with the
    practitioner's #1-3?

Run:
    python -m src.evaluate
"""

from __future__ import annotations
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.loader import load_demo_profiles
from src.ranker import score_row

DATA_DIR = Path(__file__).parent.parent / "data"

GOLD_COLUMN_TO_PROFILE = {
    "practitioner_rank_bank": "Bank",
    "practitioner_rank_startup": "Startup",
}


def spearman(a: list[float], b: list[float]) -> float | None:
    """Lightweight Spearman rank correlation (no scipy dependency)."""
    if len(a) < 2 or len(a) != len(b):
        return None
    ra = pd.Series(a).rank()
    rb = pd.Series(b).rank()
    n = len(a)
    d2 = ((ra - rb) ** 2).sum()
    return 1 - (6 * d2) / (n * (n**2 - 1))


def evaluate() -> dict:
    gold = pd.read_csv(DATA_DIR / "gold_set.csv")
    profiles = load_demo_profiles(DATA_DIR / "profiles.json")

    report = {}
    for gold_col, name_substr in GOLD_COLUMN_TO_PROFILE.items():
        if gold_col not in gold.columns:
            continue
        profile = next((p for p in profiles if name_substr in p["name"]), None)
        if profile is None:
            continue

        ranked_gold = gold.dropna(subset=[gold_col]).copy()
        ranked_gold["match_status"] = "include"  # gold rows are assumed fully matched
        ranked_gold["engine_score"] = ranked_gold.apply(lambda r: score_row(r, profile)[0], axis=1)
        ranked_gold = ranked_gold.sort_values("engine_score", ascending=False)

        corr = spearman(
            list(ranked_gold["engine_score"]),
            [-x for x in ranked_gold[gold_col]],  # lower practitioner rank number = higher priority
        )

        engine_top3 = set(ranked_gold["cve_id"].head(3))
        gold_top3 = set(ranked_gold.sort_values(gold_col)["cve_id"].head(3))

        report[profile["name"]] = {
            "spearman_rank_correlation": round(corr, 2) if corr is not None else None,
            "top3_overlap": sorted(engine_top3 & gold_top3),
            "engine_order": list(ranked_gold["cve_id"]),
            "practitioner_order": list(ranked_gold.sort_values(gold_col)["cve_id"]),
        }
    return report


if __name__ == "__main__":
    import json
    result = evaluate()
    print(json.dumps(result, indent=2))
    for name, r in result.items():
        print(f"\n{name}: spearman={r['spearman_rank_correlation']}  top3_overlap={r['top3_overlap']}")
