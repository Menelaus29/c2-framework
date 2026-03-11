# Protocol Specification — C2 Simulation Framework

## Overview

All agent-to-server communication uses a single binary envelope format carried over
HTTPS POST to `/beacon`. Every envelope is AES-256-GCM encrypted before framing.
Padding is applied to plaintext before encryption to obscure payload length. TLS
provides transport-layer confidentiality; AES-256-GCM provides end-to-end
application-layer confidentiality and integrity independent of the TLS layer.

---

## Section 1: Cryptographic Specification

| Property | Value | Notes |
|---|---|---|
| Cipher | AES-256-GCM (AEAD) | |
| Key size | 256 bits (32 bytes) | |
| Nonce size | 96 bits (12 bytes) | |
| Tag size | 128 bits (16 bytes) | GCM standard; enforced by minimum body size check in `unpack()` |
| Additional data | None | |
| KDF | HKDF-SHA256 | |
| KDF input key | `PRE_SHARED_KEY` — 32-byte lab PSK | Rotated each lab session; never transmitted |
| KDF salt | `b'c2-lab-fixed-salt-v1'` | Fixed — see `crypto.py` `get_session_key()` if updating |
| KDF info | `b'c2-framework-v1'` | Fixed — see `crypto.py` `HKDF_INFO` if updating |
| KDF output | 32-byte session key | Derived independently by both agent and server — no key exchange on wire |
| Nonce generation | `os.urandom(12)` per message | |
| Nonce position in body | First 12 bytes, prepended before ciphertext | Split at fixed offset `body[:12]` on receipt |

The session key is derived once per process start using HKDF with a fixed salt.
Both agent and server derive the identical key independently from the shared PSK —
no key exchange occurs over the wire.

---

## Section 2: Padding Specification

Padding is applied to plaintext **before** encryption to obscure the length of the
original payload.

### Padding byte layout (pre-encryption plaintext)

```
┌──────────────────┬─────────────────────────┬─────────────────────────┐
│  pad_len : 2B    │  pad_bytes : pad_len B   │  plaintext : N B        │
│  big-endian u16  │  os.urandom(pad_len)     │  JSON-encoded payload   │
└──────────────────┴─────────────────────────┴─────────────────────────┘
```

- The 2-byte prefix encodes the **pad length only**, not the plaintext length.
- `strip_padding()` reads the prefix, skips `2 + pad_len` bytes, and returns
  everything after — no plaintext length field is needed.
- Pad bytes are `os.urandom(pad_len)` — cryptographically random, discarded on receipt.
- `pad_len` is drawn from `random.randint(padding_min, padding_max)` per the active
  evasion profile.

### Padding by evasion profile

| Profile | `padding_min` | `padding_max` | Pad bytes added | Prefix |
|---|---|---|---|---|
| baseline | 0 | 0 | 0 (always) | `\x00\x00` |
| low | 0 | 64 | 0–64 random | `\x00\x00`–`\x00\x40` |
| medium | 0 | 128 | 0–128 random | `\x00\x00`–`\x00\x80` |
| high | 64 | 256 | 64–256 random | `\x00\x40`–`\x01\x00` |

The baseline profile always produces `\x00\x00` as the prefix and adds no random
bytes — the padded plaintext is exactly 2 bytes longer than the original JSON.

---

## Section 3: Binary Envelope Layout

Struct format string: `'!HBI'` (big-endian, unsigned 16-bit + unsigned 8-bit + unsigned 32-bit = **7-byte header**).

```
 Byte offset
 0        1        2        3        4        5        6
┌────────┬────────┬────────┬────────┬────────┬────────┬────────┐
│ magic          │ ver    │ body_length (4 bytes, big-endian)  │
│ 0xC2   0xC2    │ 0x01   │                                    │
└────────┴────────┴────────┴────────┴────────┴────────┴────────┘
 ◄── 2 bytes ───► ◄─ 1B ─► ◄──────────── 4 bytes ────────────►

 7        8  ...  18       19  ...  (7 + body_length - 1)
┌────────┬────────────────┬────────────────────────────────────┐
│        nonce (12 bytes) │  ciphertext + GCM tag              │
│        os.urandom(12)   │  len = body_length - 12            │
└────────┴────────────────┴────────────────────────────────────┘
 ◄─────────── 12 bytes ──► ◄──── variable ────────────────────►
```

### Field reference

| Field | Offset | Size | Type | Value |
|---|---|---|---|---|
| `magic` | 0 | 2 B | `uint16` big-endian | `0xC2C2` — identifies C2 envelope |
| `version` | 2 | 1 B | `uint8` | `0x01` — current protocol version |
| `body_length` | 3 | 4 B | `uint32` big-endian | byte count of everything after the header |
| `nonce` | 7 | 12 B | raw bytes | `os.urandom(12)` — unique per message |
| `ciphertext` | 19 | variable | raw bytes | AES-256-GCM encrypted padded plaintext |
| `tag` | last 16 B of body | 16 B | raw bytes | GCM authentication tag |

### Minimum valid envelope size

`7 (header) + 12 (nonce) + 16 (tag) = 35 bytes`.

---

## Section 4: Message Type Schemas

Every message — agent-sent and server-sent — shares the same outer envelope
structure produced by `_base_payload()`. The `payload` field carries the
message-specific content.

### Outer envelope (all messages)

```json
{
  "msg_type":   "<string>",
  "session_id": "<uuid-hex | null>",
  "timestamp":  1741824000,
  "nonce":      "a3f1c2d4e5b6078910abcdef12345678",
  "payload":    {}
}
```

| Field | Type | Notes |
|---|---|---|
| `msg_type` | string | One of the six constants below |
| `session_id` | string \| null | `null` on `CHECKIN` (no session yet); UUID hex string for all others |
| `timestamp` | integer | Unix epoch seconds — `int(time.time())` |
| `nonce` | string | `uuid.uuid4().hex` — 32-char hex string; stored by server for replay detection |
| `payload` | object | Message-specific fields; empty `{}` for messages with no inner content |

### Message type constants

| Constant | Value | Direction | Implemented |
|---|---|---|---|
| `MSG_CHECKIN` | `'CHECKIN'` | Agent → Server, Server → Agent | ✅ |
| `MSG_TASK_PULL` | `'TASK_PULL'` | Agent → Server, Server → Agent | ✅ |
| `MSG_TASK_DISPATCH` | `'TASK_DISPATCH'` | Server → Agent only | ✅ |
| `MSG_TASK_RESULT` | `'TASK_RESULT'` | Agent → Server, Server → Agent | ✅ |
| `MSG_HEARTBEAT` | `'HEARTBEAT'` | Server → Agent only (handler exists; agent does not send) | ✅ |
| `MSG_TERMINATE` | `'TERMINATE'` | Server → Agent only | ✅ |

---

### CHECKIN

Sent by the agent on startup to register with the server. Server responds with the
same `msg_type` and the assigned `session_id`.

**Agent → Server**

```json
{
  "msg_type":   "CHECKIN",
  "session_id": null,
  "timestamp":  1741824000,
  "nonce":      "a3f1c2d4e5b6078910abcdef12345678",
  "payload": {
    "hostname":   "VICTIM-PC",
    "username":   "jdoe",
    "os":         "Windows 10",
    "agent_ver":  "1.0.0",
    "jitter_pct": 20
  }
}
```

**Server → Agent**

```json
{
  "msg_type":   "CHECKIN",
  "session_id": "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1",
  "timestamp":  1741824001,
  "nonce":      "b4e2c1d3f5a6079811bcdef012345679",
  "payload": {
    "session_id": "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1",
    "status":     "ok"
  }
}
```

---

### TASK_PULL

Sent by the agent on every beacon cycle to request the next pending task.
Server responds with either a `TASK_DISPATCH`, `TASK_PULL` (no task), or
`TERMINATE` (session killed).

**Agent → Server**

```json
{
  "msg_type":   "TASK_PULL",
  "session_id": "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1",
  "timestamp":  1741824030,
  "nonce":      "c5f3d2e4a6b7089912cdef0123456780",
  "payload": {
    "session_id": "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1"
  }
}
```

**Server → Agent — no task pending**

```json
{
  "msg_type":   "TASK_PULL",
  "session_id": "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1",
  "timestamp":  1741824030,
  "nonce":      "d6a4e3f5b7c8091013def0124567891a",
  "payload": {
    "status": "no_task"
  }
}
```

---

### TASK_DISPATCH

Sent by the server in response to a `TASK_PULL` when a task is pending.
Never sent by the agent. The agent's executor runs `command` with `args`
and a `timeout_s` deadline.

**Server → Agent**

```json
{
  "msg_type":   "TASK_DISPATCH",
  "session_id": "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1",
  "timestamp":  1741824060,
  "nonce":      "e7b5f4a6c8d909201 4ef01235678902b",
  "payload": {
    "task_id":   "f1e2d3c4-b5a6-7890-1234-567890abcdef",
    "command":   "ipconfig",
    "args":      [],
    "timeout_s": 30
  }
}
```

---

### TASK_RESULT

Sent by the agent after executing a dispatched task. Server acknowledges with
the same `msg_type`.

**Agent → Server**

```json
{
  "msg_type":   "TASK_RESULT",
  "session_id": "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1",
  "timestamp":  1741824062,
  "nonce":      "f8c6e5b7d9a01012 15f0123456789013c",
  "payload": {
    "task_id":     "f1e2d3c4-b5a6-7890-1234-567890abcdef",
    "stdout":      "Windows IP Configuration\r\n\r\nEthernet adapter...",
    "stderr":      "",
    "exit_code":   0,
    "duration_ms": 142
  }
}
```

**Server → Agent**

```json
{
  "msg_type":   "TASK_RESULT",
  "session_id": "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1",
  "timestamp":  1741824062,
  "nonce":      "a9d7f6c8e0b1112316012345678904d",
  "payload": {
    "status":  "received",
    "task_id": "f1e2d3c4-b5a6-7890-1234-567890abcdef"
  }
}
```

---

### HEARTBEAT

The server updates `last_seen` and acknowledges. The agent beacon loop does not
currently send heartbeats — this message type is reserved for future use or manual
testing via the operator interface.

**Server → Agent**

```json
{
  "msg_type":   "HEARTBEAT",
  "session_id": "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1",
  "timestamp":  1741824090,
  "nonce":      "b0e8a7d9f1c2123417012345678905e",
  "payload": {
    "status": "ok"
  }
}
```

---

### TERMINATE

Sent by the server in place of a `TASK_PULL` response when the session has been
deactivated by the operator. The agent calls `sys.exit(0)` on receipt.
Never sent by the agent.

**Server → Agent**

```json
{
  "msg_type":   "TERMINATE",
  "session_id": "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1",
  "timestamp":  1741824120,
  "nonce":      "c1f9b8e0a2d3134518023456789016f",
  "payload": {
    "reason": "session killed by operator"
  }
}
```

---

## Section 5: Integrity Invariants

These are the conditions under which the server rejects a request.

### HTTP-layer rejections (Nginx — before FastAPI)

| Condition | Nginx response |
|---|---|
| Method is not `POST` on `/beacon` | `deny all` (connection closed) |
| `User-Agent` does not contain `Mozilla` | `404 Not Found` |
| `Content-Type` is not `application/octet-stream` | `404 Not Found` |
| Path is not `/beacon` | `200` (fake website) or `404` |

### Application-layer rejections (FastAPI)

| Condition | HTTP status | Response body |
|---|---|---|
| Payload exceeds 262,144 bytes | `413` | `{"error": "payload too large"}` |
| Header shorter than 7 bytes | `400` | `{"error": "bad request"}` |
| `magic` ≠ `0xC2C2` | `400` | `{"error": "bad request"}` |
| `version` ≠ `0x01` | `400` | `{"error": "bad request"}` |
| `body_length` exceeds actual bytes | `400` | `{"error": "bad request"}` |
| Body shorter than 28 bytes (nonce + tag minimum) | `400` | `{"error": "bad request"}` |
| GCM authentication tag mismatch | `400` | `{"error": "bad request"}` |
| Decrypted bytes are not valid UTF-8 JSON | `400` | `{"error": "bad request"}` |
| `nonce` field missing or empty string | `400` | `{"error": "bad request"}` |
| Nonce seen within last 24 hours | `409` | `{"error": "replay detected"}` |
| `msg_type` not recognised | `400` | `{"error": "bad request"}` |
| Unhandled exception in dispatch | `500` | `{"error": "internal error"}` |
| Response pack failure | `500` | `{"error": "internal error"}` |

### Nonce replay window

Nonces are stored in the SQLite `nonces` table with a `received_at` float timestamp.
A nonce is rejected if `received_at > (now - 86400)` — a **sliding 24-hour window**.
The table is pruned on every write: rows older than 24 hours are deleted immediately after each successful insert. Nonces are 32-character lowercase hex strings.

### Why 409 for replay, not 400

The server returns `409 Conflict` specifically for replay detection rather than the
generic `400 Bad Request`. This allows the operator to distinguish a replay attack
from a malformed envelope in server logs — both look like `bad request` to the sender,
but the server-side log entry for `409` includes the offending nonce value.

---

## Section 6: Worked Example — CHECKIN at Every Stage

This example traces a single CHECKIN message from plaintext JSON through every
transformation to the final transmitted hex. A **synthetic 32-byte key** is used
(`c2c2c2...c2` repeated). The timestamp, nonce, and encryption nonce are fixed for
reproducibility. The active profile is **baseline** (`padding_min=0`, `padding_max=0`).

---

### Stage 1 — Plaintext JSON (213 bytes)

Serialised with `json.dumps().encode('utf-8')`, compact separators, no whitespace:

```json
{"msg_type":"CHECKIN","session_id":null,"timestamp":1741824000,"nonce":"a3f1c2d4e5b6078910abcdef12345678","payload":{"hostname":"VICTIM-PC","username":"jdoe","os":"Windows 10","agent_ver":"1.0.0","jitter_pct":20}}
```

---

### Stage 2 — After padding (215 bytes, baseline profile)

`pad(plaintext, 0, 0)` prepends a 2-byte big-endian prefix encoding `pad_len = 0`:

```
00 00  7b 22 6d 73 67 5f 74 79 70 65 22 3a 22 43 48
       └── plaintext starts here ({"msg_type":"CH...)
```

- Bytes 0–1: `00 00` — pad_len = 0, no random bytes added
- Bytes 2–214: original 213-byte JSON plaintext

---

### Stage 3 — After AES-256-GCM encryption (231 bytes of ciphertext+tag)

A 12-byte random nonce is generated and `AESGCM(key).encrypt(nonce, padded, None)` is called.

Using fixed example nonce `000102030405060708090a0b`:

```
nonce (12 bytes):
  00 01 02 03 04 05 06 07 08 09 0a 0b

ciphertext (215 bytes, first 16 shown):
  d4 2e c7 e9 ea ee 65 5a 0e ab 3c 0d ad 4a ad fb ...

GCM tag (last 16 bytes of ciphertext_with_tag):
  95 d9 96 17 75 a8 5e 7a 36 42 1c 1b 3b cd 6f 21
```

The 215-byte padded plaintext becomes 231 bytes: 215 bytes ciphertext + 16-byte tag.

---

### Stage 4 — After framing (250 bytes)

The 7-byte header is prepended. Body = nonce (12B) + ciphertext+tag (231B) = 243 bytes.

```
Header (7 bytes):
  c2 c2        ← magic 0xC2C2
  01           ← version 0x01
  00 00 00 f3  ← body_length = 243 (0xF3)

Body (first 32 bytes shown):
  00 01 02 03 04 05 06 07 08 09 0a 0b  ← nonce (12 bytes)
  d4 2e c7 e9 ea ee 65 5a 0e ab 3c 0d  ← ciphertext starts
  ad 4a ad fb ad bd c6 d2
```

---

### Stage 5 — On the wire (hex, first 64 bytes)

This is what appears in the HTTP POST body after TLS decryption at Nginx.
FastAPI receives this exact byte sequence.

```
c2c201000000f3000102030405060708
090a0bd42ec7e9eaee655a0eab3c0dad
4aadfbadbdc6d2c64c779873533bf0b8
a12fad902640c6177a57a73149d3d4ce
... (250 bytes total)
```

---

### Stage summary

| Stage | Size | What changed |
|---|---|---|
| 1. Plaintext JSON | 213 B | Raw serialised dict |
| 2. Padded (baseline) | 215 B | +2 bytes: `\x00\x00` prefix prepended |
| 3. AES-256-GCM | 231 B | +16 bytes: GCM authentication tag appended by AESGCM |
| 4. Framed envelope | 250 B | +7 bytes: magic + version + body_length header prepended; nonce (12B) prepended to body |
| 5. TLS record | >250 B | Entire HTTP POST additionally wrapped by TLS 1.2/1.3; exact overhead depends on cipher suite and record fragmentation |

---

## Appendix: `unpack()` Processing Order

The following is the exact sequence of checks `unpack()` performs on a received
raw byte buffer. Any failure at any step raises an exception and the server returns
`400` (or `409` for replay, which is checked outside `unpack()` in `beacon()`).

```
raw bytes received
      │
      ▼
1. len(raw) >= 7?                      ProtocolError if not — too short for header
      │
      ▼
2. struct.unpack('!HBI', raw[:7])      ProtocolError if struct fails
      │
      ▼
3. magic == 0xC2C2?                    ProtocolError if not
      │
      ▼
4. version == 0x01?                    ProtocolError if not
      │
      ▼
5. len(raw) >= 7 + body_length?        ProtocolError if not — frame truncated
      │
      ▼
6. len(body) >= 28?                    ProtocolError if not — nonce+tag minimum
      │
      ▼
7. split body: nonce=body[:12],        fixed offset split
   ciphertext_with_tag=body[12:]
      │
      ▼
8. AESGCM.decrypt(nonce, ct, None)     CryptoError if tag mismatch or wrong key
      │
      ▼
9. strip_padding(plaintext)            ValueError→ProtocolError if prefix malformed
      │
      ▼
10. json.loads(plaintext.decode())     ProtocolError if not valid UTF-8 JSON
      │
      ▼
11. isinstance(result, dict)?          ProtocolError if JSON is not an object
      │
      ▼
    return dict
```