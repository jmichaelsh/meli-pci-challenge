"""
security_events.py -- lightweight structured security-event logger.

Writes one JSON object per line to logs/security_events.jsonl. In production
this file (or stdout) would be tailed by a Wazuh agent / Filebeat and shipped
to the SIEM; here it gives a durable, structured trail of every detection
and policy decision, independent of whatever the LLM ends up saying in its
final text. This is the "Detection" half of "Reasoning Separation &
Detection".
"""

import json
import time
from pathlib import Path

LOG_DIR = Path(__file__).parent / "logs"
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "security_events.jsonl"


def log_event(event_type: str, **fields) -> dict:
    record = {"ts": time.time(), "event": event_type, **fields}
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
    print(f"  [SECURITY EVENT] {event_type} :: { {k: v for k, v in fields.items()} }")
    return record
