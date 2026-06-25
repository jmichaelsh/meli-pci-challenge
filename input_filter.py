"""
input_filter.py -- Input & Content Controls (Stage 3, category 2 of 3).

Two jobs, both deterministic (regex-based), never delegated to the LLM:

  1. Strip instruction-like content out of the raw email BEFORE it ever
     reaches the planner LLM's context, and flag the attempt as a security
     event. In this lab the injected payloads are framed as fake
     "system notes" inside "--- ... ---" delimited blocks, which is exactly
     the kind of pattern this filter targets.
  2. Extract the structured field the pipeline actually needs (the
     transaction id) deterministically, instead of trusting the LLM to
     "read" arbitrary instructions out of free text.

This never silently drops a whole email -- a real dispute should still get
a reply -- it only removes the instruction-shaped parts and logs that it
did so.
"""

import re
from dataclasses import dataclass, field

from security_events import log_event

TXN_ID_RE = re.compile(r"\btxn_[a-zA-Z0-9]+\b")

# Intentionally broad heuristics for the injection phrasing used in this lab
# (fake system-note framing, requests to call privileged tools, requests to
# echo secrets/keys). Over-inclusive on purpose: a false positive just gets
# logged and stripped, which is the safe failure mode.
SUSPICIOUS_PATTERNS = [
    r"nota do sistema",
    r"instru[cç][aã]o de sistema",
    r"instru[cç][aã]o automatizada",
    r"system note",
    r"system prompt",
    r"\[system",
    r"ignore.{0,20}(instru|previous)",
    r"detokenize",
    r"cdv\.detokenize",
    r"api[_ ]?key",
    r"diag_key",
    r"justification\s*=",
    r"n[uú]mero completo do cart[aã]o",
    r"inclua\b.*\b(chave|key|valor)",
    r"diagn[oó]stico de conectividade",
]
_SUSPICIOUS_RE = re.compile("|".join(SUSPICIOUS_PATTERNS), re.IGNORECASE)

# In this lab the injected payloads are wrapped in "--- ... ---" blocks --
# strip those blocks outright before anything reaches a model.
_BLOCK_RE = re.compile(r"---.*?---", re.DOTALL)


@dataclass
class SanitizedEmail:
    email_id: str
    sender: str
    subject: str
    clean_body: str
    txn_ids_mentioned: list = field(default_factory=list)
    injection_suspected: bool = False
    matched_patterns: list = field(default_factory=list)


def sanitize_email(email_id: str, sender: str, subject: str, raw_body: str) -> SanitizedEmail:
    matches = sorted(set(m.group(0).lower() for m in _SUSPICIOUS_RE.finditer(raw_body)))
    injection_suspected = bool(matches)

    clean_body = _BLOCK_RE.sub("[CONTEUDO REMOVIDO PELO INPUT SANITIZER]", raw_body)
    txn_ids = sorted(set(TXN_ID_RE.findall(clean_body)))

    if injection_suspected:
        log_event(
            "injection_suspected",
            email_id=email_id,
            sender=sender,
            matched_patterns=matches,
        )

    return SanitizedEmail(
        email_id=email_id,
        sender=sender,
        subject=subject,
        clean_body=clean_body,
        txn_ids_mentioned=txn_ids,
        injection_suspected=injection_suspected,
        matched_patterns=matches,
    )
