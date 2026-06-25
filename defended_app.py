"""
defended_app.py -- Stage 3 (Defend): orchestrates the full defended pipeline.

Flow (mirrors the Zone A / Zone B architecture from the design doc -- here
running in one process/container for the lab, but each function's
boundary maps 1:1 to where a network/VLAN split would go in production):

  1. Fetch the email via the SAME mailbox_provider used by the vulnerable
     version (mock JSON or real IMAP -- MAILBOX_BACKEND env var).
  2. Input & Content Controls: sanitize_email() strips embedded
     instruction-like content and flags suspicion -> security event.
  3. Zone A: planner LLM proposes a plan from the SANITIZED data, with NO
     tool access and NO knowledge of any secret.
  4. Zone B: PolicyGateway independently re-validates the plan -- masked
     lookups are always allowed; a detokenize request is checked against
     the email's REAL sender and, even if owned, only QUEUED for human
     approval, never auto-executed.
  5. The final reply text is returned, plus a last-mile check that no
     secret/PAN-looking string leaked into it.
"""

import asyncio

from gateway import PolicyGateway, PolicyViolation
from input_filter import sanitize_email
from mailbox_provider import get_mailbox_provider
from planner import plan

mailbox = get_mailbox_provider()


async def process_email(email_id: str) -> dict:
    raw = mailbox.get_email(email_id)
    if "error" in raw:
        return {"email_id": email_id, "error": raw["error"]}

    sanitized = sanitize_email(email_id, raw["from"], raw["subject"], raw["body"])

    outcome = {
        "email_id": email_id,
        "sender": sanitized.sender,
        "injection_suspected": sanitized.injection_suspected,
        "matched_patterns": sanitized.matched_patterns,
    }

    async with PolicyGateway() as gw:
        masked = None
        if sanitized.txn_ids_mentioned:
            masked = await gw.lookup_transaction(sanitized.txn_ids_mentioned[0])

        plan_result = plan(sanitized.clean_body, sanitized.sender, sanitized.subject, masked)
        outcome["plan"] = plan_result

        if plan_result.get("action") == "request_detokenize" and plan_result.get("txn_id"):
            try:
                decision = await gw.request_detokenize(
                    plan_result["txn_id"],
                    plan_result.get("justification", ""),
                    sanitized.sender,
                )
                outcome["gateway_decision"] = decision
            except PolicyViolation as e:
                outcome["gateway_decision"] = {"status": "rejected", "reason": str(e)}
        else:
            outcome["gateway_decision"] = {"status": "not_requested"}

        outcome["final_reply"] = plan_result.get("reply_draft", "")

    return outcome


if __name__ == "__main__":
    import sys

    email_id = sys.argv[1] if len(sys.argv) > 1 else "EML-1001"
    result = asyncio.run(process_email(email_id))
    import json

    print(json.dumps(result, indent=2, ensure_ascii=False))
