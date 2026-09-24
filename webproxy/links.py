"""Client links for WEB proxy (tproxy-server README.md section 6, BASE_PATH.md)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import urllib.parse

_SECRET_RE = re.compile(r"^[0-9a-f]{32}$")
_SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
MAX_BASE_PATH = 128
MARKER = b"\x70"


def validate_secret(secret_hex: str) -> bytes:
    if not _SECRET_RE.match(secret_hex):
        raise ValueError("secret must be 32 lowercase hex characters")
    return bytes.fromhex(secret_hex)


def validate_base_path(base_path: str) -> str:
    if base_path == "":
        return base_path
    if len(base_path) > MAX_BASE_PATH:
        raise ValueError("base path is too long")
    for segment in base_path.split("/"):
        if not _SEGMENT_RE.match(segment):
            raise ValueError("invalid base path segment")
    return base_path


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def marked_secret(secret_hex: str) -> str:
    """Unpadded base64url of 0x70 || secret, used in links under a base path."""
    return _b64url(MARKER + validate_secret(secret_hex))


def client_server(domain: str, base_path: str) -> str:
    validate_base_path(base_path)
    return domain + "/" + base_path if base_path else domain


def client_secret(secret_hex: str, base_path: str) -> str:
    """The secret as typed by hand or put in a link."""
    validate_base_path(base_path)
    if base_path:
        return marked_secret(secret_hex)
    validate_secret(secret_hex)
    return secret_hex


def build(domain: str, base_path: str, secret_hex: str) -> str:
    server = urllib.parse.quote(client_server(domain, base_path), safe="")
    return "https://t.me/webproxy?server=%s&secret=%s" % (server, client_secret(secret_hex, base_path))


def capability(domain: str, base_path: str, secret: bytes) -> str:
    """Bridge capability; mirrors tproxy-server config.DeriveCapability (self-check only)."""
    validate_base_path(base_path)
    if base_path:
        context = "tdesktop-web-proxy-bridge-v2\n" + domain + "\n" + base_path
    else:
        context = "tdesktop-web-proxy-bridge-v1\n" + domain
    return _b64url(hmac.new(secret, context.encode("utf-8"), hashlib.sha256).digest())
