"""
Builds the aggregate numbers and (optional) AI-written executive summary
for a whole-run report, sitting on top of an already-computed triage
result. Nothing here re-derives facts -- it only aggregates numbers the
matching/ranking/explaining pipeline already produced, same "explainable
or it does not count" contract as the rest of the app.

Two outputs:
  - `build_report_stats(actions, negative_test, excluded_count)` -- pure,
    deterministic aggregation (priority counts, average score, per-signal
    contribution totals) for the charts. No AI involved, always available.
  - `write_executive_summary(...)` -- OPTIONAL, short AI-phrased paragraph
    over those same stats, via a small/fast Featherless model. Given only
    the aggregated numbers already computed -- never the raw dataset --
    with a strict "don't invent" system prompt and a deterministic
    template fallback if the model is unavailable or fails.
"""

from __future__ import annotations
import os
import json
import time
import requests

from src.llm_phraser import call_llm, is_available as _ai_available, _looks_like_garbage

# Same reasoning as company_lookup.py: this is a short structured-to-prose
# task, not creative writing, so a fast model is enough and keeps report
# generation from being the slow step in a live demo. Groq is default for
# the same reason it's llm_phraser's default: low-latency inference, so
# report generation isn't stuck waiting out Featherless timeouts first.
REPORT_MODEL = "groq:llama-3.1-8b-instant"

# Tried in order after REPORT_MODEL if it fails -- same reasoning as
# llm_phraser.FALLBACK_MODELS: one overloaded/deprecated model shouldn't
# knock the whole summary back to the template. A second fast Groq model
# is tried before the slower Featherless ones.
REPORT_FALLBACK_MODELS = [
    "groq:llama-3.3-70b-versatile",
    "featherless-ai/Qwerky-72B",
    "meta-llama/Meta-Llama-3.1-8B-Instruct",
    "mistralai/Mistral-7B-Instruct-v0.3",
    "Qwen/Qwen2.5-72B-Instruct",
    "google/gemma-2-9b-it",
]

SYSTEM_PROMPT = (
    "You write short executive summaries for a cybersecurity vulnerability "
    "triage report, for a non-technical business reader (e.g. a clinic "
    "director or small-business owner, not an engineer). "
    "You will be given ONLY pre-computed statistics about the organisation's "
    "top-5 vulnerability list -- priority counts, average score, the single "
    "highest-priority item, the negative-test example, and (if present) one "
    "watchlist item that just missed the top 5. "
    "Write 3-6 sentences: state how many items need attention and at what "
    "urgency, name the single most urgent item and why, mention the "
    "negative-test example as proof this is not just a severity table, and "
    "if a watchlist item is present, note it briefly as one to keep an eye "
    "on even though it isn't urgent today, then "
    "close with a one-sentence call to action. "
    "Rules: use ONLY the numbers and names given to you -- never invent a "
    "CVE ID, product, score, date, or vendor that isn't in the input. Never "
    "say the organisation is secure or safe. Return plain text only, no "
    "markdown, no headings, no bullet points."
)


def build_report_stats(actions: list[dict], negative_test: dict | None, excluded_count: int,
                        candidate_count: int, watchlist_item: dict | None = None) -> dict:
    """Pure aggregation over an already-computed triage result. No AI, no
    network call, always succeeds -- this is what powers the charts even
    if AI phrasing is off or unavailable."""
    priority_counts = {"URGENT": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    factor_totals: dict[str, float] = {}
    scores = []

    for a in actions:
        priority_counts[a["priority"]] = priority_counts.get(a["priority"], 0) + 1
        scores.append(a["score"])
        for factor_name, points in (a.get("factors") or {}).items():
            factor_totals[factor_name] = factor_totals.get(factor_name, 0.0) + points

    n = len(actions) or 1
    factor_averages = {k: round(v / n, 1) for k, v in factor_totals.items()}
    avg_score = round(sum(scores) / n, 1) if scores else 0.0
    top_item = actions[0] if actions else None

    return {
        "priority_counts": priority_counts,
        "factor_averages": factor_averages,
        "average_score": avg_score,
        "total_in_report": len(actions),
        "excluded_count": excluded_count,
        "candidate_count": candidate_count,
        "top_item": {
            "cve_id": top_item["cve_id"],
            "plain_title": top_item["plain_title"],
            "priority": top_item["priority"],
            "score": top_item["score"],
        } if top_item else None,
        "negative_test": negative_test,
        # The highest-scored candidate that just missed the top-5 cut --
        # "one more worth watching" rather than acted on today. None if
        # there were 5 or fewer candidates in total.
        "watchlist_item": {
            "cve_id": watchlist_item["cve_id"],
            "plain_title": watchlist_item["plain_title"],
            "priority": watchlist_item["priority"],
            "score": watchlist_item["score"],
            "why_watch": watchlist_item.get("why_watch"),
        } if watchlist_item else None,
    }


def _fallback_summary(stats: dict, profile_name: str) -> str:
    pc = stats["priority_counts"]
    parts = [
        f"{stats['total_in_report']} item(s) were prioritised for {profile_name} out of "
        f"{stats['candidate_count']} matched product(s) ({stats['excluded_count']} excluded as not applicable)."
    ]
    urgent_high = pc.get("URGENT", 0) + pc.get("HIGH", 0)
    if urgent_high:
        parts.append(f"{urgent_high} of these are URGENT or HIGH priority and warrant attention this week.")
    if stats["top_item"]:
        t = stats["top_item"]
        parts.append(f"The top item is {t['cve_id']} ({t['plain_title']}), priority {t['priority']}, "
                     f"score {t['score']}/100.")
    if stats["negative_test"]:
        nt = stats["negative_test"]
        parts.append(f"For comparison, {nt['cve_id']} (CVSS {nt['cvss_base_score']}) was correctly kept out of "
                     f"the top 5 -- proof this list is not just sorted by severity.")
    if stats.get("watchlist_item"):
        w = stats["watchlist_item"]
        parts.append(f"One item just outside the top 5 is worth watching: {w['cve_id']} ({w['plain_title']}), "
                     f"score {w['score']}/100 -- not urgent enough to act on today, but close enough that it "
                     f"could become a problem if its exploitation risk rises.")
    parts.append("This report reflects what matched the supplied data; it does not certify the organisation is secure.")
    return " ".join(parts)


def _model_chain(requested: str | None) -> list[str]:
    ordered = [requested] if requested else []
    ordered += [REPORT_MODEL] + REPORT_FALLBACK_MODELS
    seen: set[str] = set()
    chain = []
    for m in ordered:
        if m and m not in seen:
            seen.add(m)
            chain.append(m)
    return chain


def write_executive_summary(stats: dict, profile_name: str, model: str = REPORT_MODEL,
                             timeout: int = 8, total_budget: float = 25.0) -> dict:
    """Returns {"text": str, "used_ai": bool, "error": str|None, "attempts": list}.
    Never raises.

    Tries the requested/default model, then REPORT_FALLBACK_MODELS in order,
    before giving up and returning the deterministic template summary --
    same fallback-chain contract as llm_phraser.phrase(), including the
    overall `total_budget` that bounds the whole call regardless of how
    many models are tried, so an unresponsive/unknown model can't make
    report generation hang indefinitely.
    """
    fallback = _fallback_summary(stats, profile_name)

    if not _ai_available():
        return {"text": fallback, "used_ai": False,
                 "error": "No AI provider configured (set FEATHERLESS_API_KEY and/or GROQ_API_KEY)", "attempts": []}

    user_msg = (
        f"Organisation: {profile_name}\n"
        f"Stats (JSON): {json.dumps(stats, default=str)}"
    )

    attempts: list[dict] = []
    budget_start = time.monotonic()
    for candidate_model in _model_chain(model):
        elapsed = time.monotonic() - budget_start
        if elapsed >= total_budget:
            attempts.append({"model": candidate_model, "ok": False,
                              "error": "skipped: time budget exhausted", "latency_ms": 0})
            break

        started = time.monotonic()
        text, error = call_llm(
            SYSTEM_PROMPT, user_msg, candidate_model, timeout=min(timeout, total_budget - elapsed),
            max_tokens=260, temperature=0.2,
        )
        latency_ms = round((time.monotonic() - started) * 1000)
        if text:
            garbage_reason = _looks_like_garbage(text)
            if garbage_reason is None:
                attempts.append({"model": candidate_model, "ok": True, "latency_ms": latency_ms})
                return {"text": text, "used_ai": True, "error": None, "model": candidate_model, "attempts": attempts}
            attempts.append({"model": candidate_model, "ok": False, "error": garbage_reason, "latency_ms": latency_ms})
            continue
        attempts.append({"model": candidate_model, "ok": False, "error": error, "latency_ms": latency_ms})

    summary_error = "; ".join(f"{a['model']}: {a['error']}" for a in attempts)
    return {"text": fallback, "used_ai": False, "error": summary_error[:300], "attempts": attempts}
