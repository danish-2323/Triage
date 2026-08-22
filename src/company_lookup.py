"""
OPTIONAL autofill helper. Given just a company name (+ optional sector
hint), asks a Featherless-hosted model to GUESS a starting profile: likely
technologies, sector, exposure and importance. This is a convenience for
filling in the "Your own company" form faster -- it is never treated as
ground truth and never feeds the triage engine directly.

Design contract (same spirit as llm_phraser.py):
  - Output populates form FIELDS only, never a ranked result or an
    explanation. The existing matching/ranking/explaining pipeline is
    completely untouched by this module.
  - Every guessed field is returned alongside a source-honesty flag so the
    UI can visibly mark it "AI-suggested -- verify before use" rather than
    presenting it as fact.
  - The user must review and can edit or delete any field before
    submitting the form that actually drives the triage.
  - If the API key is missing, the call fails, times out, or the model
    returns unparseable output, callers get an empty/failed result and the
    UI falls back to the plain manual form -- never a crash, never a
    silent invented profile.
  - This does not scan, probe, or reconnoiter any real system. It only
    asks a language model what it already knows about a named company's
    likely public technology stack, which is explicitly allowed under the
    brief ("no live ingestion pipelines / external reconnaissance" refers
    to probing real infrastructure, not describing one in prose).
"""

from __future__ import annotations
import os
import json
import re
import time
import requests

from src.llm_phraser import call_llm, is_available as _ai_available

# Autofill only needs to extract a short JSON object, not write prose, so
# a fast model is enough. Groq is the default here for the same reason as
# llm_phraser/report: it's low-latency, so autofill isn't stuck waiting
# out slow/timed-out Featherless attempts first.
AUTOFILL_MODEL = "groq:llama-3.1-8b-instant"

# Tried in order if AUTOFILL_MODEL fails for any reason other than a
# missing key (bad/retired model id, that model overloaded, etc.) -- same
# fallback-chain contract as llm_phraser.phrase() / report.write_executive_summary().
# A second fast Groq model is tried before the slower Featherless ones.
AUTOFILL_FALLBACK_MODELS = [
    "groq:llama-3.3-70b-versatile",
    "featherless-ai/Qwerky-72B",
    "meta-llama/Meta-Llama-3.1-8B-Instruct",
    "mistralai/Mistral-7B-Instruct-v0.3",
    "Qwen/Qwen2.5-72B-Instruct",
    "google/gemma-2-9b-it",
    "groq:llama-3.1-8b-instant",
]

SYSTEM_PROMPT = (
    "You are helping pre-fill a cybersecurity triage tool's intake form. "
    "Given a company name (and optional sector hint), suggest a plausible "
    "starting profile based on publicly known information about that kind "
    "of organisation. This is a best-effort GUESS the user will review and "
    "edit -- never claim certainty. "
    "Return ONLY a single JSON object, no markdown fences, no prose, with "
    "exactly these keys: "
    '{"sector": string, "exposure": "internet-facing" or "internal", '
    '"importance": "critical", "high", or "normal", '
    '"service": short string naming their main customer-facing service, '
    '"technologies": array of up to 8 short strings, each a specific '
    'vendor/product name likely in their stack (e.g. "nginx", "wordpress", '
    '"microsoft exchange"), lowercase, no version numbers}. '
    "If you do not recognise the company or are not confident, still "
    "return your best generic guess for that sector -- never leave a "
    "field blank, and never invent a specific unpublicized breach, "
    "vendor contract, or internal system name presented as fact."
)


class LookupStatus:
    def __init__(self, profile: dict | None, used_ai: bool, error: str | None = None):
        self.profile = profile
        self.used_ai = used_ai
        self.error = error

    @property
    def ok(self) -> bool:
        return self.used_ai and self.profile is not None


def is_available() -> bool:
    return _ai_available()


def _extract_json(text: str) -> dict | None:
    text = text.strip()
    text = re.sub(r"^```(json)?|```$", "", text, flags=re.MULTILINE).strip()
    try:
        return json.loads(text)
    except Exception:
        match = re.search(r"\{.*\}", text, flags=re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except Exception:
                return None
    return None


def _model_chain(requested: str | None) -> list[str]:
    ordered = [requested] if requested else []
    ordered += [AUTOFILL_MODEL] + AUTOFILL_FALLBACK_MODELS
    seen: set[str] = set()
    chain = []
    for m in ordered:
        if m and m not in seen:
            seen.add(m)
            chain.append(m)
    return chain


def suggest_profile(company_name: str, sector_hint: str = "", model: str = AUTOFILL_MODEL,
                     timeout: int = 10, total_budget: float = 20.0, _retry: bool = True) -> LookupStatus:
    """Best-effort profile guess for the intake form. Never raises.

    Tries the requested/default model, then AUTOFILL_FALLBACK_MODELS in
    order, before giving up -- one bad/overloaded/deprecated model no
    longer takes autofill straight to "unavailable". On top of that, a
    per-model timeout still gets one retry (Featherless can be slow to
    spin up a model on the first call of a session).

    `total_budget` bounds the WHOLE call (all models + retries combined),
    same contract as llm_phraser.phrase() / report.write_executive_summary()
    -- previously this loop had no overall cap, so a timeout on every model
    in the chain (each retried once) could take minutes. With Groq's low-
    latency default now tried first, most calls return well under that.
    """
    company_name = (company_name or "").strip()
    if not company_name:
        return LookupStatus(None, used_ai=False, error="No company name given")

    if not _ai_available():
        return LookupStatus(None, used_ai=False,
                             error="No AI provider configured (set FEATHERLESS_API_KEY and/or GROQ_API_KEY)")

    user_msg = f"Company name: {company_name}"
    if sector_hint.strip():
        user_msg += f"\nSector hint: {sector_hint.strip()}"

    errors: list[str] = []
    budget_start = time.monotonic()
    for candidate_model in _model_chain(model):
        elapsed = time.monotonic() - budget_start
        if elapsed >= total_budget:
            errors.append(f"{candidate_model}: skipped: time budget exhausted")
            break

        per_call_timeout = min(timeout, max(total_budget - elapsed, 1))
        text, error = call_llm(
            SYSTEM_PROMPT, user_msg, candidate_model, timeout=per_call_timeout,
            max_tokens=300, temperature=0.3,
        )
        elapsed = time.monotonic() - budget_start
        if error and "timed out" in error and _retry and elapsed < total_budget:
            # one retry per model, same reasoning as before: first call of a
            # session can be slow while the provider spins the model up
            per_call_timeout = min(timeout, max(total_budget - elapsed, 1))
            text, error = call_llm(
                SYSTEM_PROMPT, user_msg, candidate_model, timeout=per_call_timeout,
                max_tokens=300, temperature=0.3,
            )

        if text:
            parsed = _extract_json(text)
            if not parsed:
                errors.append(f"{candidate_model}: model returned unparseable output")
                continue

            profile = {
                "sector": str(parsed.get("sector", "")).strip(),
                "exposure": parsed.get("exposure") if parsed.get("exposure") in
                            ("internet-facing", "internal") else "internet-facing",
                "importance": parsed.get("importance") if parsed.get("importance") in
                              ("critical", "high", "normal") else "high",
                "service": str(parsed.get("service", "")).strip(),
                "technologies": [str(t).strip().lower() for t in parsed.get("technologies", [])
                                  if str(t).strip()][:8],
            }
            return LookupStatus(profile, used_ai=True)

        errors.append(f"{candidate_model}: {error}")

    return LookupStatus(None, used_ai=False, error="; ".join(errors)[:300])
