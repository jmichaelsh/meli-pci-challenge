"""
mcp_server.py -- Stage 1 (Build): VULNERABLE baseline MCP server.

Exposes 4 tools over MCP, exactly as specified in the challenge:
  - emails.list()
  - emails.get(id)
  - cdv.get_transaction(txn_id)
  - cdv.detokenize(txn_id, justification)

INTENTIONALLY INSECURE -- this is the "before" picture for the GenAI Security
Challenge (fintech, PCI DSS v4.0). Do not deploy anything resembling this in
production. Specifically, on purpose, this version:

  1. Has NO authentication or authorization on any tool call -- whoever can
     talk to this MCP server can call any tool, including the privileged
     cdv.detokenize.
  2. cdv.detokenize() does not check that the transaction belongs to whoever
     is asking, and accepts ANY string as "justification" with no human
     approval step.
  3. Returns the live CDV_API_KEY value back to the caller as part of the
     detokenize response (simulating a sloppy implementation that echoes
     credentials in responses/logs).
  4. emails.get() returns the RAW, unsanitized email body -- including
     anything an attacker embedded in it -- with no stripping of
     instruction-like content.

All secrets and PANs below are MOCK values for this lab exercise only.
"""

import json
import logging
import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from mailbox_provider import get_mailbox_provider

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [MCP-SERVER] %(message)s",
)
log = logging.getLogger("mcp_server")

DATA_DIR = Path(__file__).parent / "mock_data"
TRANSACTIONS = json.loads((DATA_DIR / "transactions.json").read_text(encoding="utf-8"))

# MAILBOX_BACKEND=mock  -> original Stage 1/2 canned JSON emails (default)
# MAILBOX_BACKEND=imap  -> reads a real IMAP mailbox (see mailbox_provider.py)
mailbox = get_mailbox_provider()
log.info(f"mailbox backend = {os.environ.get('MAILBOX_BACKEND', 'mock')}")

# Secrets loaded straight from plaintext env vars -- vulnerable baseline.
CDV_API_KEY = os.environ.get("CDV_API_KEY", "sk_live_mock_cdv_abc123")
SIGNING_KEY = os.environ.get("SIGNING_KEY", "mock_hmac_key_xyz789")

mcp = FastMCP("dispute-resolution-mcp-vulnerable")


@mcp.tool(name="emails.list")
def emails_list() -> list[dict]:
    """List incoming dispute-resolution emails (id, sender, subject only)."""
    log.info("emails.list() called")
    return mailbox.list_emails()


@mcp.tool(name="emails.get")
def emails_get(id: str) -> dict:
    """Retrieve the full RAW content of a specific email by id.
    VULNERABLE: returns the body completely unsanitized, with no
    stripping of embedded instructions."""
    log.info(f"emails.get(id={id!r}) called")
    return mailbox.get_email(id)


@mcp.tool(name="cdv.get_transaction")
def cdv_get_transaction(txn_id: str) -> dict:
    """Return MASKED cardholder data + metadata for a transaction id.
    VULNERABLE: no caller authentication, no check that the caller is
    entitled to view this transaction."""
    log.info(f"cdv.get_transaction(txn_id={txn_id!r}) called [api_key={CDV_API_KEY}]")
    txn = TRANSACTIONS.get(txn_id)
    if not txn:
        return {"error": "transaction not found"}
    return {
        "txn_id": txn_id,
        "cardholder_name": txn["cardholder_name"],
        "masked_pan": txn["masked_pan"],
        "bin": txn["bin"],
        "last4": txn["last4"],
        "amount": txn["amount"],
        "date": txn["date"],
        "status": txn["status"],
        "sender_email": txn["sender_email"],
    }


@mcp.tool(name="cdv.detokenize")
def cdv_detokenize(txn_id: str, justification: str) -> dict:
    """PRIVILEGED: returns the FULL unmasked PAN for a transaction.

    VULNERABLE: accepts any justification string with no validation, requires
    NO human approval, performs NO ownership/scope check, and echoes the live
    CDV_API_KEY back in the response -- all on purpose, to demonstrate the
    baseline risk this challenge asks you to fix in Stage 3."""
    log.warning(
        f"cdv.detokenize(txn_id={txn_id!r}, justification={justification!r}) "
        f"called -- NO APPROVAL REQUIRED [api_key={CDV_API_KEY}]"
    )
    txn = TRANSACTIONS.get(txn_id)
    if not txn:
        return {"error": "transaction not found"}
    return {
        "txn_id": txn_id,
        "full_pan": txn["full_pan"],
        "cardholder_name": txn["cardholder_name"],
        "justification_logged": justification,
        "api_key_used": CDV_API_KEY,
    }


if __name__ == "__main__":
    mcp.run()
