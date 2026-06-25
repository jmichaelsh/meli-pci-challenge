"""
human_approval.py -- mocks the human-in-the-loop approval gate for
cdv.detokenize.

In production this would be a queue an authorized fraud/support analyst
reviews in a dashboard, with its own authentication and audit trail (PCI
DSS Req 8). Here it's a simple JSON file so the demo -- and your interview
-- can show the full lifecycle of a request: submitted -> pending ->
approved/denied -> (only then) released.

cdv.detokenize is NEVER auto-approved by this pipeline, even for a request
that already passed the ownership check in gateway.py.
"""

import json
import time
import uuid
from pathlib import Path

STORE_PATH = Path(__file__).parent / "logs" / "approval_queue.json"
STORE_PATH.parent.mkdir(exist_ok=True)


def _load() -> dict:
    if STORE_PATH.exists():
        return json.loads(STORE_PATH.read_text(encoding="utf-8"))
    return {}


def _save(data: dict) -> None:
    STORE_PATH.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def submit_request(txn_id: str, justification: str, requester_email: str) -> str:
    data = _load()
    request_id = str(uuid.uuid4())[:8]
    data[request_id] = {
        "txn_id": txn_id,
        "justification": justification,
        "requester_email": requester_email,
        "status": "pending",
        "created_at": time.time(),
    }
    _save(data)
    return request_id


def get_request(request_id: str) -> dict | None:
    return _load().get(request_id)


def get_status(request_id: str) -> str:
    return _load().get(request_id, {}).get("status", "not_found")


def list_pending() -> dict:
    return {rid: r for rid, r in _load().items() if r["status"] == "pending"}


def approve(request_id: str, approver: str = "analyst") -> None:
    data = _load()
    if request_id in data:
        data[request_id]["status"] = "approved"
        data[request_id]["approved_by"] = approver
        data[request_id]["approved_at"] = time.time()
        _save(data)


def deny(request_id: str, approver: str = "analyst") -> None:
    data = _load()
    if request_id in data:
        data[request_id]["status"] = "denied"
        data[request_id]["approved_by"] = approver
        data[request_id]["approved_at"] = time.time()
        _save(data)
