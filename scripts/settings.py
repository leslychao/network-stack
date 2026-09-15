"""The DEPLOY_ENV contract. Values are data, never executable shell code."""

import base64
import binascii
import ipaddress
import os
from pathlib import Path
import re
import uuid


class StackError(Exception):
    """Safe, value-free message suitable for CI logs."""


SSH_FIELDS = {"SSH_HOST", "SSH_USER", "SSH_PRIVATE_KEY_B64", "SSH_KNOWN_HOSTS_B64"}
APP_FIELDS = {
    "PANEL_HOST", "INITIAL_PANEL_USERNAME", "INITIAL_PANEL_PASSWORD",
    "INITIAL_VLESS_UUID", "INITIAL_REALITY_PRIVATE_KEY", "INITIAL_REALITY_PUBLIC_KEY",
    "INITIAL_REALITY_SHORT_ID", "MTG_SECRET",
}


def parse_env(text):
    result = {}
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if not sep or not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            raise StackError(f"Invalid .env entry at line {number}")
        if key in result:
            raise StackError(f"Duplicate .env key at line {number}")
        if value.startswith("'"):
            chars, index = [], 1
            while index < len(value):
                char = value[index]
                if char == "'":
                    tail = value[index + 1:].strip()
                    if tail and not tail.startswith("#"):
                        raise StackError(f"Invalid quoted value at line {number}")
                    break
                if char == "\\" and index + 1 < len(value) and value[index + 1] in "\\'":
                    index += 1
                    char = value[index]
                chars.append(char)
                index += 1
            else:
                raise StackError(f"Unclosed quote at line {number}")
            value = "".join(chars)
        elif value.startswith('"'):
            raise StackError(f"Use single quotes for literal values at line {number}")
        if any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise StackError(f"Control character at line {number}")
        result[key] = value
    return result


def dump_env(values):
    return "".join(f"{key}='" + value.replace("\\", "\\\\").replace("'", "\\'") + "'\n"
                   for key, value in sorted(values.items()))


def domain(value):
    return len(value) <= 253 and bool(re.fullmatch(
        r"(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,63}", value))


def decode64(value, field):
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise StackError(f"Invalid Base64 in {field}") from None


def panel_host(value):
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return domain(value)


def validate(values, ssh=False):
    required = APP_FIELDS | (SSH_FIELDS if ssh else set())
    unknown = values.keys() - APP_FIELDS - SSH_FIELDS
    if unknown:
        raise StackError("Unknown .env key; see .env.example")
    for key in sorted(required):
        if not values.get(key):
            raise StackError(f"Missing required setting: {key}")
    if not panel_host(values["PANEL_HOST"]):
        raise StackError("PANEL_HOST must be an IPv4 address or DNS hostname without scheme or port")
    if not re.fullmatch(r"[A-Za-z0-9_.@-]{3,64}", values["INITIAL_PANEL_USERNAME"]):
        raise StackError("INITIAL_PANEL_USERNAME must have 3-64 safe ASCII characters")
    if not 16 <= len(values["INITIAL_PANEL_PASSWORD"].encode()) <= 72:
        raise StackError("INITIAL_PANEL_PASSWORD must have 16-72 UTF-8 bytes")
    try:
        if str(uuid.UUID(values["INITIAL_VLESS_UUID"])) != values["INITIAL_VLESS_UUID"].lower():
            raise ValueError
    except ValueError:
        raise StackError("Invalid INITIAL_VLESS_UUID") from None
    for key in ("INITIAL_REALITY_PRIVATE_KEY", "INITIAL_REALITY_PUBLIC_KEY"):
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", values[key]):
            raise StackError(f"Invalid {key}: expected a 32-byte URL-safe Base64 key")
        decoded = base64.urlsafe_b64decode(values[key] + "=")
        if base64.urlsafe_b64encode(decoded).decode().rstrip("=") != values[key]:
            raise StackError(f"Noncanonical {key}")
    if not re.fullmatch(r"[0-9a-f]{16}", values["INITIAL_REALITY_SHORT_ID"]):
        raise StackError("INITIAL_REALITY_SHORT_ID must contain 16 lowercase hex digits")
    secret = values["MTG_SECRET"]
    try:
        data = bytes.fromhex(secret)
        front = data[17:].decode("ascii")
        if not re.fullmatch(r"ee[0-9a-f]+", secret) or len(data) < 20 or not domain(front):
            raise ValueError
    except (ValueError, UnicodeError):
        raise StackError("MTG_SECRET must be a hex FakeTLS secret containing a hostname") from None
    if ssh:
        try:
            ipaddress.ip_address(values["SSH_HOST"])
        except ValueError:
            if not domain(values["SSH_HOST"]):
                raise StackError("SSH_HOST must be an IP address or DNS hostname") from None
        if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", values["SSH_USER"]):
            raise StackError("Invalid SSH_USER")
        key = decode64(values["SSH_PRIVATE_KEY_B64"], "SSH_PRIVATE_KEY_B64")
        if not key.startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----\n"):
            raise StackError("Expected an unencrypted OpenSSH private key with LF newlines")
        known = decode64(values["SSH_KNOWN_HOSTS_B64"], "SSH_KNOWN_HOSTS_B64")
        if not known.strip() or b"\x00" in known:
            raise StackError("Invalid SSH_KNOWN_HOSTS_B64")
    return values


def read_env(path, ssh=False):
    return validate(parse_env(Path(path).read_text(encoding="utf-8-sig")), ssh)


def private_write(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with open(path, "wb", opener=lambda p, flags: os.open(p, flags, 0o600)) as stream:
        stream.write(data.encode() if isinstance(data, str) else data)
    path.chmod(0o600)


def mask(values):
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return
    for value in values:
        if value:
            value = value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
            print(f"::add-mask::{value}", flush=True)
