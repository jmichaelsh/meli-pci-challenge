"""
approve_pending.py -- simulates the human analyst in the human-in-the-loop
approval gate.

In a real deployment this would be a small internal dashboard with its own
authentication; here it's a CLI so you can show the full lifecycle live in
an interview:

    python approve_pending.py list
    python approve_pending.py approve <request_id>
    python approve_pending.py deny <request_id>
"""

import sys

import human_approval


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return

    cmd = sys.argv[1]

    if cmd == "list":
        pending = human_approval.list_pending()
        if not pending:
            print("No pending requests.")
        for rid, r in pending.items():
            print(f"{rid}  txn={r['txn_id']}  requester={r['requester_email']}  "
                  f"justification={r['justification']!r}")

    elif cmd == "approve" and len(sys.argv) >= 3:
        human_approval.approve(sys.argv[2])
        print(f"Approved {sys.argv[2]}")

    elif cmd == "deny" and len(sys.argv) >= 3:
        human_approval.deny(sys.argv[2])
        print(f"Denied {sys.argv[2]}")

    else:
        print(__doc__)


if __name__ == "__main__":
    main()
