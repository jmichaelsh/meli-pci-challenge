"""
gateway.py -- Tool & Policy Controls (Stage 3, category 1 of 3).

This module is the ONLY thing in the defended pipeline that ever talks to
the real MCP/CDV tools. The planner LLM (planner.py) never receives a tool
binding at all -- it can only PROPOSE an action as structured JSON. Every
proposal is independently re-validated here, deterministically, before
anything privileged happens:

  - lookup_transaction(txn_id)      -> always allowed, MASKED data only.
  - request_detokenize(...)          -> hard ownership check against the
                                         REAL email sender (never a sender
                                         claim parsed out of the body),
                                         then queued for human approval --
                                         never auto-executed, even for a
                                         legitimate owner.
  - release_after_approval(...)      -> the only path that can ever return
                                         a full PAN, and only after
                                         human_approval.approve() has been
                                         called out-of-band.

In production this module's process boundary IS the network/VLAN boundary
in the architecture: it is the only component with reachability into the
CDE segment and the only holder of CDV_API_KEY.
"""

import json
import os
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

import human_approval
from security_events import log_event

_SERVER_SCRIPT = os.path.join(os.path.dirname(__file__), "mcp_server.py")


class PolicyViolation(Exception):
    """Raised when a proposed action fails a deterministic policy check.
    This is the backstop: even if the planner LLM is fully fooled by a
    prompt injection and proposes a malicious action, this exception is
    what actually stops it from ever reaching the CDV vault."""


def _parse(mcp_result) -> dict:
    return json.loads(mcp_result.content[0].text)


class PolicyGateway:
    def __init__(self):
        self._stdio_cm = None
        self._session_cm = None
        self._session: ClientSession | None = None

    async def __aenter__(self) -> "PolicyGateway":
        params = StdioServerParameters(command=sys.executable, args=[_SERVER_SCRIPT])
        self._stdio_cm = stdio_client(params)
        read, write = await self._stdio_cm.__aenter__()
        self._session_cm = ClientSession(read, write)
        self._session = await self._session_cm.__aenter__()
        await self._session.initialize()
        return self

    async def __aexit__(self, *exc):
        await self._session_cm.__aexit__(*exc)
        await self._stdio_cm.__aexit__(*exc)

    async def lookup_transaction(self, txn_id: str) -> dict:
        """Always allowed: MASKED data only. This is the only
        transaction-related call the planner is permitted to trigger."""
        result = await self._session.call_tool("cdv.get_transaction", {"txn_id": txn_id})
        return _parse(result)

    async def request_detokenize(self, txn_id: str, justification: str, true_sender: str) -> dict:
        """Privileged path. Enforces, in order:
          1. Ownership/scope check against `true_sender` -- the verified
             `From` header captured by the input sanitizer, NEVER a sender
             claim extracted from the email body by an LLM.
          2. Human approval: queued, never auto-executed.
        Raises PolicyViolation if the ownership check fails.
        """
        txn = await self.lookup_transaction(txn_id)
        if "error" in txn:
            return {"status": "rejected", "reason": "transaction not found"}

        owner = txn.get("sender_email")
        if owner != true_sender:
            log_event(
                "detokenize_rejected_ownership_mismatch",
                txn_id=txn_id,
                true_sender=true_sender,
                txn_owner=owner,
                justification=justification,
            )
            raise PolicyViolation(
                f"txn_id={txn_id} belongs to {owner!r}, not requester {true_sender!r}"
            )

        request_id = human_approval.submit_request(txn_id, justification, true_sender)
        log_event(
            "detokenize_queued_for_approval",
            request_id=request_id,
            txn_id=txn_id,
            requester=true_sender,
            justification=justification,
        )
        return {"status": "pending_human_approval", "request_id": request_id}

    async def release_after_approval(self, request_id: str) -> dict:
        """Only path that can ever return a full PAN. Call only after
        human_approval.approve(request_id) has happened out-of-band
        (e.g. via approve_pending.py, simulating an analyst)."""
        status = human_approval.get_status(request_id)
        if status != "approved":
            return {"status": f"still_{status}"}

        data = human_approval.get_request(request_id)
        result = await self._session.call_tool(
            "cdv.detokenize",
            {"txn_id": data["txn_id"], "justification": data["justification"]},
        )
        log_event("detokenize_released", request_id=request_id, txn_id=data["txn_id"])
        return _parse(result)
