"""
OPTIONAL phrasing layer. Turns the structured explanation dict into a
single smooth paragraph using a hosted model -- restyling wording only,
never adding facts. The app works fully offline without this module;
every call site must fall back to the deterministic template text if
this is disabled or fails for any reason.

Two providers are supported, so one provider being slow/rate-limited
doesn't take phrasing straight to the template:
  - Featherless (default) -- model ids used as-is, e.g. "Qwen/Qwen2.5-72B-Instruct".
  - Groq -- model ids prefixed "groq:", e.g. "groq:llama-3.1-8b-instant".
Each provider needs its own API key (FEATHERLESS_API_KEY / GROQ_API_KEY);
either, both, or neither may be configured. A model chain can freely mix
ids from both providers -- call_llm() resolves the right endpoint/key per
model, and a missing key for one provider just skips its models rather
than failing the whole chain.

Design contract (kept deliberately strict, per the brief's "explainable
or it does not count" rule):
  - The model is given ONLY the fields already computed by explainer.py.
  - It is instructed never to introduce a number, date, version, vendor
    name or recommendation that isn't already in the input.
  - If the call fails, times out, returns empty text, or no provider key is
    configured, callers silently get the deterministic template back --
    the UI never breaks and never shows a raw error to an end user.
"""

from __future__ import annotations
import os
import re
import time
from collections import Counter
import requests

FEATHERLESS_URL = "https://api.featherless.ai/v1/chat/completions"
FEATHERLESS_MODELS_URL = "https://api.featherless.ai/v1/models"
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

# Model ids prefixed with this are routed to Groq instead of Featherless.
# e.g. "groq:allam-2-7b" -> Groq, model "allam-2-7b".
GROQ_PREFIX = "groq:"

DEFAULT_MODEL = "groq:allam-2-7b"

# A small curated shortlist shown in the UI's model picker. Groq is listed
# first and is the default -- it's a low-latency inference service and
# responds in roughly a second, versus several seconds (or a timeout) for
# some Featherless-hosted models. Any model your plan has access to will
# work -- this list just gives fast, sensible defaults without an extra
# network round trip. The /models API endpoint will merge this with a live
# catalog fetch when possible.
SUGGESTED_MODELS = [
    {"id": "groq:allam-2-7b", "label": "Groq · Allam 2 7B (default)"},
    {"id": "groq:openai/gpt-oss-20b", "label": "Groq · GPT OSS 20B"},
    {"id": "featherless-ai/Qwerky-72B", "label": "Qwerky 72B"},
    {"id": "meta-llama/Meta-Llama-3.1-8B-Instruct", "label": "Llama 3.1 8B Instruct"},
    {"id": "mistralai/Mistral-7B-Instruct-v0.3", "label": "Mistral 7B Instruct"},
    {"id": "Qwen/Qwen2.5-72B-Instruct", "label": "Qwen 2.5 72B Instruct (higher quality)"},
    {"id": "google/gemma-2-9b-it", "label": "Gemma 2 9B Instruct"},
]

SYSTEM_PROMPT = (
    "You are a plain-language rewriting assistant for a cybersecurity triage tool. "
    "Rephrase the given fields into one smooth, plain-language paragraph (3-4 sentences max) "
    "for a non-technical reader such as a clinic or small-business IT lead. "
    "Rules: do not add any fact, number, date, version, vendor name, exploit detail, or "
    "recommendation that is not already present in the input. Do not soften or remove the "
    "recommended next step. Do not claim the organisation is secure. If you are unsure of a "
    "fact, use the input text verbatim instead of guessing. Return only the paragraph, no "
    "preamble, no markdown, no headings."
)


# If the requested/default model fails (rate-limited, deprecated, cold,
# whatever) we don't want one bad model to knock phrasing back to the
# template straight away. These are tried in order, after the caller's
# requested model, before giving up and returning the deterministic text.
# A second fast Groq model comes first so a bad/rate-limited default
# doesn't immediately fall through to the slower Featherless models --
# those are last since they're the ones most likely to time out.
FALLBACK_MODELS = [
    "groq:openai/gpt-oss-20b",
    "featherless-ai/Qwerky-72B",
    "meta-llama/Meta-Llama-3.1-8B-Instruct",
    "mistralai/Mistral-7B-Instruct-v0.3",
    "Qwen/Qwen2.5-72B-Instruct",
    "google/gemma-2-9b-it",
]


class PhraserStatus:
    """Small result wrapper so API layers can report *why* AI phrasing was
    skipped (missing key, network error, timeout) instead of guessing."""

    def __init__(self, text: str, used_ai: bool, model: str | None = None, error: str | None = None,
                 attempts: list[dict] | None = None):
        self.text = text
        self.used_ai = used_ai
        self.model = model
        self.error = error
        # One entry per model tried this call, e.g.
        # [{"model": "...", "ok": False, "error": "timed out after 15s"}, ...]
        # Empty when no AI attempt was made at all (no key configured).
        self.attempts = attempts or []

    def to_dict(self) -> dict:
        return {
            "text": self.text, "used_ai": self.used_ai, "model": self.model,
            "error": self.error, "attempts": self.attempts,
        }


def _model_chain(requested: str | None) -> list[str]:
    """Requested model first (if any), then the curated fallbacks, de-duped,
    order preserved."""
    ordered = [requested] if requested else []
    ordered += [DEFAULT_MODEL] + FALLBACK_MODELS
    seen: set[str] = set()
    chain = []
    for m in ordered:
        if m and m not in seen:
            seen.add(m)
            chain.append(m)
    return chain


def _resolve_provider(model: str) -> tuple[str, str, str]:
    """Maps a model id to (api_url, api_key_env_name, actual_model_id).
    "groq:"-prefixed ids route to Groq; everything else goes to Featherless
    unchanged, so existing (unprefixed) model ids keep working exactly as
    before."""
    if model.startswith(GROQ_PREFIX):
        return GROQ_URL, "GROQ_API_KEY", model[len(GROQ_PREFIX):]
    return FEATHERLESS_URL, "FEATHERLESS_API_KEY", model


def _post_chat_completion(url: str, api_key: str, model: str, messages: list,
                           timeout: int, max_tokens: int, temperature: float) -> tuple[str | None, str | None]:
    """Raw POST to an OpenAI-compatible chat/completions endpoint (both
    Featherless and Groq use this shape). Returns (text, None) on success
    or (None, error_message) on any failure. Never raises."""
    try:
        resp = requests.post(
            url,
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"model": model, "messages": messages, "max_tokens": max_tokens, "temperature": temperature},
            timeout=timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        text = _remove_reasoning(data["choices"][0]["message"]["content"])
        if not text:
            return None, "empty response after removing model reasoning"
        return text, None
    except requests.exceptions.Timeout:
        return None, f"timed out after {timeout}s"
    except requests.exceptions.HTTPError as e:
        status = e.response.status_code if e.response is not None else "?"
        return None, f"HTTP {status}"
    except Exception as e:  # noqa: BLE001 - deliberately broad: never break triage over phrasing
        return None, f"{type(e).__name__}: {e}"[:200]


def _remove_reasoning(text: str) -> str:
    """Remove private reasoning that some hosted models include in content."""
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.IGNORECASE | re.DOTALL)
    if re.match(r"^\s*<think\b", text, flags=re.IGNORECASE):
        return ""
    return text.strip()


def call_featherless(system_prompt: str, user_content, model: str, timeout: int,
                      max_tokens: int, temperature: float, api_key: str) -> tuple[str | None, str | None]:
    """Featherless-only call, kept for backward compatibility with any
    caller that already resolves its own FEATHERLESS_API_KEY. New code
    should prefer call_llm(), which also supports Groq."""
    messages = [
        {"role": "system", "content": system_prompt},
        user_content if isinstance(user_content, dict) else {"role": "user", "content": user_content},
    ]
    return _post_chat_completion(FEATHERLESS_URL, api_key, model, messages, timeout, max_tokens, temperature)


def call_llm(system_prompt: str, user_content, model: str, timeout: int,
             max_tokens: int, temperature: float) -> tuple[str | None, str | None]:
    """One attempt against one model, auto-routing to Featherless or Groq
    based on the model id (see _resolve_provider) and pulling that
    provider's API key from the environment. Returns (text, None) on
    success or (None, error_message) on any failure, including a missing
    key for that specific provider -- never raises. Shared by the
    per-item phraser below, report.py's executive-summary writer, and
    company_lookup.py's autofill, so fallback-chain behaviour (and Groq
    support) is identical everywhere AI phrasing is used."""
    url, key_env, actual_model = _resolve_provider(model)
    api_key = os.environ.get(key_env)
    if not api_key:
        return None, f"{key_env} not configured"
    messages = [
        {"role": "system", "content": system_prompt},
        user_content if isinstance(user_content, dict) else {"role": "user", "content": user_content},
    ]
    return _post_chat_completion(url, api_key, actual_model, messages, timeout, max_tokens, temperature)


def _looks_like_garbage(text: str) -> str | None:
    """
    Returns a short reason string if `text` looks like corrupted model
    output rather than a real answer, else None. Catches two failure
    modes seen with some Featherless-hosted models when the chat template
    isn't applied/stopped correctly:
      - leftover template control tokens ("[INST]", "<|im_end|>", etc.)
        leaking into the visible text
      - degenerate repetition (the model gets stuck looping one token/word,
        e.g. "tttt batter match/INST]tttt batter match/INST]...")
    This is a sanity gate, not a content check -- it never reads the
    *meaning* of the text, only whether it's structurally broken.
    """
    if not text:
        return "empty"

    markers = ["[INST]", "[/INST]", "<<SYS>>", "<</SYS>>", "<s>", "</s>",
               "<|im_start|>", "<|im_end|>", "<|endoftext|>"]
    for m in markers:
        if m in text:
            return f"leftover chat-template marker '{m}' in output"

    words = re.findall(r"\w+", text.lower())
    if len(words) >= 15:
        most_common_word, most_common_count = Counter(words).most_common(1)[0]
        if most_common_count / len(words) > 0.15:
            return f"degenerate repetition of '{most_common_word}' ({most_common_count}/{len(words)} words)"

    return None


def is_available() -> bool:
    """True if at least one provider's key is configured (Featherless
    and/or Groq) -- callers only need one to get AI phrasing."""
    return bool(os.environ.get("FEATHERLESS_API_KEY")) or bool(os.environ.get("GROQ_API_KEY"))


def list_models(timeout: int = 6) -> list[dict]:
    """Best-effort live model list. Fetches Featherless's catalog (if that
    key is set) and Groq's (if that key is set, ids prefixed "groq:" to
    match the routing convention), merges them with the curated
    SUGGESTED_MODELS, and falls back to SUGGESTED_MODELS alone if neither
    key is set or both calls fail."""
    featherless_key = os.environ.get("FEATHERLESS_API_KEY")
    groq_key = os.environ.get("GROQ_API_KEY")
    if not featherless_key and not groq_key:
        return SUGGESTED_MODELS

    live_ids: list[str] = []

    if featherless_key:
        try:
            resp = requests.get(
                FEATHERLESS_MODELS_URL,
                headers={"Authorization": f"Bearer {featherless_key}"},
                timeout=timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            live_ids += [m.get("id") for m in data.get("data", []) if m.get("id")]
        except Exception:
            pass  # fall through -- curated Featherless entries still show up below

    if groq_key:
        try:
            resp = requests.get(
                "https://api.groq.com/openai/v1/models",
                headers={"Authorization": f"Bearer {groq_key}"},
                timeout=timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            live_ids += [f"{GROQ_PREFIX}{m.get('id')}" for m in data.get("data", []) if m.get("id")]
        except Exception:
            pass  # fall through -- curated Groq entry still shows up below

    if not live_ids:
        return SUGGESTED_MODELS

    favourites = [m for m in SUGGESTED_MODELS if m["id"] in live_ids]
    rest = [{"id": i, "label": i} for i in live_ids if i not in {m["id"] for m in favourites}]
    return (favourites + rest)[:40]


def _fallback_text(explanation: dict) -> str:
    return (
        f"{explanation['why_it_matters']} {explanation['potential_impact']} "
        f"Recommended action: {explanation['next_step']}"
    )


def phrase(explanation: dict, model: str = DEFAULT_MODEL, timeout: int = 8,
           total_budget: float = 20.0) -> PhraserStatus:
    """
    Returns a PhraserStatus wrapping either an AI-phrased paragraph or the
    deterministic fallback text (with a reason) if AI phrasing is
    unavailable or fails for any reason. Never raises.

    Fallback chain, in order:
      1. The caller's requested model (or DEFAULT_MODEL if none given).
      2. DEFAULT_MODEL, if that wasn't already the one just tried.
      3. Each model in FALLBACK_MODELS, in order.
      4. The deterministic template text -- always succeeds, no network call.
    One bad/overloaded/deprecated model no longer takes phrasing straight
    back to the template; every step tried is recorded in `.attempts` so
    the UI can show exactly what happened if the caller wants to.

    `total_budget` bounds the WHOLE call (all models combined), not just
    one attempt. api.py calls phrase() once per action card (up to 5 per
    request), so an unbounded chain of N models x `timeout` seconds each
    could turn one slow/unknown model choice into several minutes of
    "Running..." -- this budget stops trying further fallbacks once the
    time is used up, so the request always returns in bounded time.
    """
    fallback = _fallback_text(explanation)

    if not is_available():
        return PhraserStatus(fallback, used_ai=False,
                              error="No AI provider configured (set FEATHERLESS_API_KEY and/or GROQ_API_KEY)")

    user_content = (
        f"Plain title: {explanation['plain_title']}\n"
        f"Why it matters: {explanation['why_it_matters']}\n"
        f"Potential impact: {explanation['potential_impact']}\n"
        f"Next step: {explanation['next_step']}\n"
        f"Confidence: {explanation['confidence']} ({explanation['confidence_reason']})"
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
            SYSTEM_PROMPT, user_content, candidate_model, timeout=min(timeout, total_budget - elapsed),
            max_tokens=220, temperature=0.2,
        )
        latency_ms = round((time.monotonic() - started) * 1000)
        if text:
            garbage_reason = _looks_like_garbage(text)
            if garbage_reason is None:
                attempts.append({"model": candidate_model, "ok": True, "latency_ms": latency_ms})
                return PhraserStatus(text, used_ai=True, model=candidate_model, attempts=attempts)
            attempts.append({"model": candidate_model, "ok": False, "error": garbage_reason, "latency_ms": latency_ms})
            continue
        attempts.append({"model": candidate_model, "ok": False, "error": error, "latency_ms": latency_ms})

    summary_error = "; ".join(f"{a['model']}: {a['error']}" for a in attempts)
    return PhraserStatus(fallback, used_ai=False, error=summary_error[:300], attempts=attempts)
