"""
mailbox_provider.py -- pluggable backends for the "mailbox" MCP tool.

Two implementations:
  - MockMailboxProvider: reads from mock_data/emails.json. This is the
    original, fully offline Stage 1/2 baseline -- no network involved.
  - ImapMailboxProvider: connects to a REAL IMAP mailbox and reads real
    messages. This is the more elaborate version: the agent genuinely
    reads an inbox instead of canned JSON, while the Cardholder Data
    Vault stays mocked (we never want to touch real PCI data either way).

Selected via the MAILBOX_BACKEND env var ("mock" | "imap"), default "mock".
This keeps the original demo working unchanged while adding the new mode.
"""

import email
import imaplib
import json
import os
import re
from email.header import decode_header
from email.message import Message
from pathlib import Path

def _resolve_data_dir() -> Path:
    """The repo currently keeps emails.json/transactions.json at the project
    root, not under mock_data/ -- support both layouts so this doesn't break
    depending on how files were uploaded/committed."""
    here = Path(__file__).parent
    for candidate in (here / "mock_data", here):
        if (candidate / "emails.json").exists():
            return candidate
    return here


DATA_DIR = _resolve_data_dir()


class MailboxProvider:
    def list_emails(self) -> list[dict]:
        raise NotImplementedError

    def get_email(self, id: str) -> dict:
        raise NotImplementedError


class MockMailboxProvider(MailboxProvider):
    """Original Stage 1 backend: canned JSON, no network involved."""

    def __init__(self):
        self._emails = json.loads((DATA_DIR / "emails.json").read_text(encoding="utf-8"))

    def list_emails(self):
        return [{"id": e["id"], "from": e["from"], "subject": e["subject"]} for e in self._emails]

    def get_email(self, id: str):
        for e in self._emails:
            if e["id"] == id:
                return e
        return {"error": "not found"}


class ImapMailboxProvider(MailboxProvider):
    """Reads a real dispute-resolution mailbox over IMAP.

    VULNERABLE BASELINE NOTE: like the mock version, this returns the RAW
    decoded body with no sanitization -- that's the point of the baseline,
    the defense comes in Stage 3.
    """

    def __init__(self):
        self.host = os.environ["IMAP_HOST"]
        self.port = int(os.environ.get("IMAP_PORT", "993"))
        self.user = os.environ["IMAP_USER"]
        self.password = os.environ["IMAP_PASS"]
        self.folder = os.environ.get("IMAP_FOLDER", "INBOX")
        self.use_ssl = os.environ.get("IMAP_USE_SSL", "true").lower() == "true"
        self.list_limit = int(os.environ.get("IMAP_LIST_LIMIT", "50"))

    def _connect(self) -> imaplib.IMAP4:
        conn = (
            imaplib.IMAP4_SSL(self.host, self.port)
            if self.use_ssl
            else imaplib.IMAP4(self.host, self.port)
        )
        conn.login(self.user, self.password)
        conn.select(self.folder)
        return conn

    @staticmethod
    def _decode(value: str | None) -> str:
        if not value:
            return ""
        parts = decode_header(value)
        return "".join(
            (t.decode(enc or "utf-8", errors="replace") if isinstance(t, bytes) else t)
            for t, enc in parts
        )

    @staticmethod
    def _strip_html(html: str) -> str:
        text = re.sub(r"<(script|style)[^>]*>.*?</\1>", "", html, flags=re.S | re.I)
        text = re.sub(r"<[^>]+>", " ", text)
        return re.sub(r"\s+", " ", text).strip()

    @classmethod
    def _extract_body(cls, msg: Message) -> str:
        """Pull the best available text body out of a (possibly multipart) message."""
        if msg.is_multipart():
            for part in msg.walk():
                disp = str(part.get("Content-Disposition") or "")
                if part.get_content_type() == "text/plain" and "attachment" not in disp:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        return payload.decode(charset, errors="replace")
            for part in msg.walk():
                if part.get_content_type() == "text/html":
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        return cls._strip_html(payload.decode(charset, errors="replace"))
            return ""
        payload = msg.get_payload(decode=True)
        if not payload:
            return ""
        charset = msg.get_content_charset() or "utf-8"
        text = payload.decode(charset, errors="replace")
        if msg.get_content_type() == "text/html":
            text = cls._strip_html(text)
        return text

    def list_emails(self):
        conn = self._connect()
        try:
            _, data = conn.search(None, "ALL")
            uids = data[0].split()[-self.list_limit :]
            out = []
            for uid in uids:
                _, msg_data = conn.fetch(uid, "(RFC822.HEADER)")
                if not msg_data or msg_data[0] is None:
                    continue
                msg = email.message_from_bytes(msg_data[0][1])
                out.append(
                    {
                        "id": uid.decode(),
                        "from": self._decode(msg.get("From")),
                        "subject": self._decode(msg.get("Subject")),
                    }
                )
            return out
        finally:
            conn.logout()

    def get_email(self, id: str):
        conn = self._connect()
        try:
            _, msg_data = conn.fetch(id.encode(), "(RFC822)")
            if not msg_data or msg_data[0] is None:
                return {"error": "not found"}
            msg = email.message_from_bytes(msg_data[0][1])
            return {
                "id": id,
                "from": self._decode(msg.get("From")),
                "subject": self._decode(msg.get("Subject")),
                "body": self._extract_body(msg),
            }
        finally:
            conn.logout()


def get_mailbox_provider() -> MailboxProvider:
    backend = os.environ.get("MAILBOX_BACKEND", "mock").lower()
    if backend == "imap":
        return ImapMailboxProvider()
    return MockMailboxProvider()
