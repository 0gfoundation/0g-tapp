#!/usr/bin/env python3
"""
Ethereum signature utility for TAPP service authentication.

tapp-server >= 0.9.0 accepts only body-bound signatures: the signed message is

    <MethodName>:0x<sha256 of the protobuf-encoded request>:<unix timestamp>

and the request carries the header `x-signature-version: 2`. The server hashes
the request bytes it actually received, so the signature covers the content —
a request altered in flight no longer verifies.

Usage:
    sign_message.py <method_name> <private_key> [request.json | -]

The request is the same JSON handed to grpcurl (`-` reads it from stdin;
omitted means an empty request). It is encoded with the message definitions in
../proto/tapp_service.proto (override with TAPP_PROTO) — the same encoding
grpcurl puts on the wire.

Example:
    printf '%s' "$request_json" | python3 sign_message.py StopApp 0xabc123... -

Output format:
    signature,timestamp,address
"""

import base64
import hashlib
import json
import os
import re
import sys
import time

from eth_account import Account
from eth_account.messages import encode_defunct


# ─── Minimal protobuf encoder ────────────────────────────────────────────────
#
# Request messages use only string, bytes, bool, int32/int64/uint32/uint64 and
# repeated strings / messages. Encoded the way every protobuf implementation
# does it for proto3: fields in field-number order, default values omitted,
# repeated elements always emitted.

VARINT_TYPES = {"bool", "int32", "int64", "uint32", "uint64"}
LEN_TYPES = {"string", "bytes"}


def load_messages(proto_path):
    text = open(proto_path).read()
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"//[^\n]*", "", text)
    messages = {}
    for name, body in re.findall(r"message\s+(\w+)\s*\{([^{}]*)\}", text):
        fields = {}
        for rep, ftype, fname, num in re.findall(
            r"(repeated\s+)?(map<[^>]*>|\w[\w.]*)\s+(\w+)\s*=\s*(\d+)\s*;", body
        ):
            fields[fname] = (int(num), ftype.strip(), bool(rep))
        messages[name] = fields
    return messages


def varint(n):
    if n < 0:
        n += 1 << 64  # negative int32/int64: ten-byte two's complement
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def snake(key):
    return re.sub(r"([A-Z])", lambda m: "_" + m.group(1).lower(), key)


def encode(messages, type_name, obj):
    fields = messages.get(type_name)
    if fields is None:
        raise ValueError(f"unknown message type {type_name}")
    values = {}
    for key, value in (obj or {}).items():
        name = key if key in fields else snake(key)
        if name not in fields:
            raise ValueError(f"{type_name} has no field {key!r}")
        values[name] = value

    out = bytearray()
    for name, (num, ftype, repeated) in sorted(fields.items(), key=lambda f: f[1][0]):
        value = values.get(name)
        if value is None:
            continue
        items = value if repeated else [value]
        for item in items:
            out += encode_field(messages, num, ftype, item, omit_default=not repeated)
    return bytes(out)


def encode_field(messages, num, ftype, value, omit_default):
    if ftype in VARINT_TYPES:
        if ftype == "bool":
            n = 1 if value in (True, "true") else 0
        else:
            n = int(value)  # JSON carries 64-bit integers as strings
        if omit_default and n == 0:
            return b""
        return varint(num << 3 | 0) + varint(n)
    if ftype == "string":
        data = value.encode()
    elif ftype == "bytes":
        # proto3 JSON accepts standard or URL-safe base64, padded or not
        std = value.replace("-", "+").replace("_", "/")
        data = base64.b64decode(std + "=" * (-len(std) % 4))
    elif ftype in messages:
        data = encode(messages, ftype, value)
        omit_default = False  # a present sub-message is emitted even when empty
    else:
        raise ValueError(f"unsupported field type {ftype}")
    if omit_default and not data:
        return b""
    return varint(num << 3 | 2) + varint(len(data)) + data


# ─── Signing ─────────────────────────────────────────────────────────────────


def main():
    if len(sys.argv) not in (3, 4):
        print(__doc__, file=sys.stderr)
        sys.exit(1)

    method_name = sys.argv[1]
    private_key = sys.argv[2]
    if len(sys.argv) == 4:
        raw = sys.stdin.read() if sys.argv[3] == "-" else open(sys.argv[3]).read()
        request = json.loads(raw) if raw.strip() else {}
    else:
        request = {}

    if private_key.startswith("0x") or private_key.startswith("0X"):
        private_key = private_key[2:]
    try:
        account = Account.from_key("0x" + private_key)
    except Exception as e:
        print(f"Error: Invalid private key - {e}", file=sys.stderr)
        sys.exit(1)

    proto_path = os.environ.get(
        "TAPP_PROTO",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "proto", "tapp_service.proto"),
    )
    try:
        body = encode(load_messages(proto_path), f"{method_name}Request", request)
    except Exception as e:
        print(f"Error: cannot encode the {method_name} request - {e}", file=sys.stderr)
        sys.exit(1)

    timestamp = int(time.time())
    message = f"{method_name}:0x{hashlib.sha256(body).hexdigest()}:{timestamp}"

    try:
        signed = account.sign_message(encode_defunct(text=message))
    except Exception as e:
        print(f"Error: Failed to sign message - {e}", file=sys.stderr)
        sys.exit(1)

    # Output: signature,timestamp,address
    sig = signed.signature.hex()
    print(f"{sig if sig.startswith('0x') else '0x' + sig},{timestamp},{account.address}")


if __name__ == "__main__":
    main()
