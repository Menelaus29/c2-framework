import struct
import pytest
import random

from common.message_format import (
    pack, unpack,
    build_checkin, build_task_pull, build_task_result,
    _base_payload,
    MAGIC, PROTOCOL_VERSION, HEADER_FORMAT, HEADER_SIZE,
    MSG_CHECKIN, MSG_TASK_PULL, MSG_TASK_RESULT, MSG_HEARTBEAT,
)
from common.crypto import get_session_key
from common.utils import CryptoError, ProtocolError


# fixtures
@pytest.fixture(scope="module")
def key():
    # session key shared across all tests in this module
    return get_session_key()


@pytest.fixture
def checkin_payload():
    # realistic CHECKIN payload
    return build_checkin(
        hostname='VICTIM-PC',
        username='jdoe',
        os_info='Windows 10 22H2',
        agent_ver='1.0.0',
        jitter_pct=20,
    )


@pytest.fixture
def task_pull_payload():
    # realistic TASK_PULL payload
    return build_task_pull(session_id='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee')


@pytest.fixture
def task_result_payload():
    # realistic TASK_RESULT payload
    return build_task_result(
        session_id='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
        task_id='11111111-2222-3333-4444-555555555555',
        stdout='VICTIM-PC\\jdoe',
        stderr='',
        exit_code=0,
        duration_ms=142,
    )


@pytest.fixture
def heartbeat_payload():
    # realistic HEARTBEAT payload
    return _base_payload(MSG_HEARTBEAT, session_id='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee')


@pytest.fixture
def packed_checkin(checkin_payload, key):
    # pre-packed CHECKIN frame for use in tamper/truncation tests
    return pack(checkin_payload, key)


# round-trip tests — all four message types
class TestRoundTrip:

    def test_checkin_round_trip(self, checkin_payload, key):
        # pack then unpack returns identical dict for CHECKIN
        raw       = pack(checkin_payload, key)
        recovered = unpack(raw, key)

        assert recovered['msg_type']              == MSG_CHECKIN
        assert recovered['payload']['hostname']   == 'VICTIM-PC'
        assert recovered['payload']['username']   == 'jdoe'
        assert recovered['payload']['os']         == 'Windows 10 22H2'
        assert recovered['payload']['agent_ver']  == '1.0.0'
        assert recovered['payload']['jitter_pct'] == 20

    def test_task_pull_round_trip(self, task_pull_payload, key):
        # pack then unpack returns identical dict for TASK_PULL
        raw       = pack(task_pull_payload, key)
        recovered = unpack(raw, key)

        assert recovered['msg_type'] == MSG_TASK_PULL
        assert recovered['payload']['session_id'] == 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'

    def test_task_result_round_trip(self, task_result_payload, key):
        # pack then unpack returns identical dict for TASK_RESULT
        raw       = pack(task_result_payload, key)
        recovered = unpack(raw, key)

        assert recovered['msg_type']              == MSG_TASK_RESULT
        assert recovered['payload']['stdout']     == 'VICTIM-PC\\jdoe'
        assert recovered['payload']['stderr']     == ''
        assert recovered['payload']['exit_code']  == 0
        assert recovered['payload']['duration_ms']== 142

    def test_heartbeat_round_trip(self, heartbeat_payload, key):
        # pack then unpack returns identical dict for HEARTBEAT
        raw       = pack(heartbeat_payload, key)
        recovered = unpack(raw, key)

        assert recovered['msg_type'] == MSG_HEARTBEAT

    def test_round_trip_preserves_session_id(self, task_pull_payload, key):
        # session_id survives the full pack/unpack cycle unchanged
        raw       = pack(task_pull_payload, key)
        recovered = unpack(raw, key)

        assert recovered['session_id'] == task_pull_payload['session_id']

    def test_round_trip_preserves_timestamp(self, checkin_payload, key):
        # timestamp field survives pack/unpack unchanged
        raw       = pack(checkin_payload, key)
        recovered = unpack(raw, key)

        assert recovered['timestamp'] == checkin_payload['timestamp']

    def test_round_trip_preserves_nonce(self, checkin_payload, key):
        # Per-message replay-protection nonce survives pack/unpack
        raw       = pack(checkin_payload, key)
        recovered = unpack(raw, key)

        assert recovered['nonce'] == checkin_payload['nonce']

    def test_packed_output_is_bytes(self, checkin_payload, key):
        # pack() must return bytes, not str or bytearray
        raw = pack(checkin_payload, key)
        assert isinstance(raw, bytes)

    def test_unpacked_output_is_dict(self, checkin_payload, key):
        # unpack() must return a dict
        raw       = pack(checkin_payload, key)
        recovered = unpack(raw, key)
        assert isinstance(recovered, dict)

    def test_packed_frame_starts_with_correct_magic(self, checkin_payload, key):
        # first two bytes of every packed frame must be MAGIC (0xC2C2)
        raw             = pack(checkin_payload, key)
        magic, _, _     = struct.unpack(HEADER_FORMAT, raw[:HEADER_SIZE])
        assert magic == MAGIC

    def test_packed_frame_has_correct_version(self, checkin_payload, key):
        # version byte in header must equal PROTOCOL_VERSION
        raw             = pack(checkin_payload, key)
        _, version, _   = struct.unpack(HEADER_FORMAT, raw[:HEADER_SIZE])
        assert version == PROTOCOL_VERSION

    def test_round_trip_large_payload(self, key):
        # round-trip works for a payload with large stdout (64KB)
        large_output = 'A' * 65536
        payload  = build_task_result(
            session_id='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
            task_id='11111111-2222-3333-4444-555555555555',
            stdout=large_output,
            stderr='',
            exit_code=0,
            duration_ms=3000,
        )
        raw       = pack(payload, key)
        recovered = unpack(raw, key)

        assert recovered['payload']['stdout'] == large_output

    def test_round_trip_unicode_in_payload(self, key):
        # Round-trip preserves unicode characters in string fields.
        payload = build_task_result(
            session_id='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
            task_id='11111111-2222-3333-4444-555555555555',
            stdout='héllo wörld — 八重神子 — Ω',
            stderr='',
            exit_code=0,
            duration_ms=10,
        )
        raw       = pack(payload, key)
        recovered = unpack(raw, key)

        assert recovered['payload']['stdout'] == 'héllo wörld — 八重神子 — Ω'

    def test_round_trip_special_chars_in_payload(self, key):
        # round-trip preserves backslashes, quotes, and newlines
        payload = build_task_result(
            session_id='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
            task_id='11111111-2222-3333-4444-555555555555',
            stdout='C:\\Users\\jdoe\nline2\t"quoted"',
            stderr='',
            exit_code=0,
            duration_ms=10,
        )
        raw       = pack(payload, key)
        recovered = unpack(raw, key)

        assert recovered['payload']['stdout'] == 'C:\\Users\\jdoe\nline2\t"quoted"'


# wrong magic bytes
class TestWrongMagic:

    def test_zeroed_magic_raises_protocol_error(self, packed_checkin, key):
        # magic bytes set to 0x0000 must raise ProtocolError
        corrupt = b'\x00\x00' + packed_checkin[2:]
        with pytest.raises(ProtocolError, match="magic"):
            unpack(corrupt, key)

    def test_inverted_magic_raises_protocol_error(self, packed_checkin, key):
        # bit-flipped magic bytes must raise ProtocolError
        corrupt = b'\x3D\x3D' + packed_checkin[2:]
        with pytest.raises(ProtocolError, match="magic"):
            unpack(corrupt, key)

    def test_ff_magic_raises_protocol_error(self, packed_checkin, key):
        # magic bytes set to 0xFFFF must raise ProtocolError
        corrupt = b'\xFF\xFF' + packed_checkin[2:]
        with pytest.raises(ProtocolError, match="magic"):
            unpack(corrupt, key)

    def test_wrong_magic_does_not_raise_crypto_error(self, packed_checkin, key):
        # wrong magic must be caught before decryption — no CryptoError
        corrupt = b'\x00\x00' + packed_checkin[2:]
        with pytest.raises(ProtocolError):
            unpack(corrupt, key)

    def test_random_bytes_raises_protocol_error(self, key):
        # completely random bytes as input must raise ProtocolError
        import os
        garbage = os.urandom(64)
        # May raise ProtocolError (bad magic) or CryptoError (bad tag).
        # Both are acceptable — garbage must never return a payload dict.
        with pytest.raises((ProtocolError, CryptoError)):
            unpack(garbage, key)


# truncated input
class TestTruncatedInput:

    def test_empty_bytes_raises_protocol_error(self, key):
        # empty input must raise ProtocolError
        with pytest.raises(ProtocolError):
            unpack(b'', key)

    def test_one_byte_raises_protocol_error(self, key):
        # single byte is too short for header — must raise ProtocolError
        with pytest.raises(ProtocolError):
            unpack(b'\xC2', key)

    def test_six_bytes_raises_protocol_error(self, key):
        # six bytes is one short of the 7-byte header — must raise ProtocolError
        with pytest.raises(ProtocolError):
            unpack(b'\xC2\xC2\x01\x00\x00\x00', key)

    def test_header_only_raises_protocol_error(self, packed_checkin, key):
        # frame with header but no body must raise ProtocolError
        header_only = packed_checkin[:HEADER_SIZE]
        with pytest.raises(ProtocolError):
            unpack(header_only, key)

    def test_half_frame_raises_protocol_error(self, packed_checkin, key):
        # frame truncated to half its length must raise ProtocolError
        half = packed_checkin[:len(packed_checkin) // 2]
        with pytest.raises(ProtocolError):
            unpack(half, key)

    def test_frame_missing_last_byte_raises_error(self, packed_checkin, key):
        # frame with one byte removed from the end must raise an error
        short = packed_checkin[:-1]
        with pytest.raises((ProtocolError, CryptoError)):
            unpack(short, key)

    def test_four_bytes_raises_protocol_error(self, key):
        # four bytes — can unpack two header fields but not all three
        with pytest.raises(ProtocolError):
            unpack(b'\xC2\xC2\x01\x00', key)


# tampered body — must raise CryptoError
class TestTamperedBody:

    def test_flip_first_body_byte_raises_crypto_error(self, packed_checkin, key):
        # flipping first byte of body (nonce) must raise CryptoError
        pos     = HEADER_SIZE
        tampered = packed_checkin[:pos] + bytes([packed_checkin[pos] ^ 0xFF]) + packed_checkin[pos + 1:]
        with pytest.raises(CryptoError):
            unpack(tampered, key)

    def test_flip_last_body_byte_raises_crypto_error(self, packed_checkin, key):
        # flipping last byte of body (GCM tag area) must raise CryptoError
        tampered = packed_checkin[:-1] + bytes([packed_checkin[-1] ^ 0xFF])
        with pytest.raises(CryptoError):
            unpack(tampered, key)

    def test_flip_middle_body_byte_raises_crypto_error(self, packed_checkin, key):
        # flipping a byte in the middle of the ciphertext must raise CryptoError
        mid      = (HEADER_SIZE + len(packed_checkin)) // 2
        tampered = packed_checkin[:mid] + bytes([packed_checkin[mid] ^ 0xFF]) + packed_checkin[mid + 1:]
        with pytest.raises(CryptoError):
            unpack(tampered, key)

    def test_zeroed_body_raises_crypto_error(self, packed_checkin, key):
        # replacing entire body with zeros must raise CryptoError
        body_len = len(packed_checkin) - HEADER_SIZE
        tampered = packed_checkin[:HEADER_SIZE] + b'\x00' * body_len
        with pytest.raises(CryptoError):
            unpack(tampered, key)

    def test_tamper_does_not_return_payload(self, packed_checkin, key):
        # a tampered frame must never silently return a payload dict
        tampered = packed_checkin[:-1] + bytes([packed_checkin[-1] ^ 0xFF])
        result = None
        try:
            result = unpack(tampered, key)
        except (ProtocolError, CryptoError):
            pass
        assert result is None, "tampered frame must never return a payload"

    def test_wrong_key_raises_crypto_error(self, packed_checkin):
        # decrypting with a different key must raise CryptoError
        from common.crypto import derive_key
        wrong_key = derive_key(b'Z' * 32, b'wrong-salt')
        with pytest.raises(CryptoError):
            unpack(packed_checkin, wrong_key)


# pack input validation
class TestPackValidation:

    def test_empty_dict_raises_protocol_error(self, key):
        # pack() must reject an empty dict
        with pytest.raises(ProtocolError):
            pack({}, key)

    def test_non_dict_raises_protocol_error(self, key):
        # pack() must reject non-dict input
        with pytest.raises(ProtocolError):
            pack("not a dict", key)  # type: ignore

    def test_non_serialisable_raises_protocol_error(self, key):
        # pack() must raise ProtocolError for non-JSON-serialisable values
        with pytest.raises(ProtocolError):
            pack({'msg_type': 'CHECKIN', 'data': object()}, key)

# evasion layer — padding integration tests
class TestPaddingIntegration:

    def test_pad_strip_round_trip_50_random_payloads(self):
        # pad then strip_padding returns original plaintext for 50 random payloads
        import os
        from evasion.padding_strat import pad, strip_padding

        for _ in range(50):
            original = os.urandom(random.randint(1, 512))
            padded   = pad(original, 0, 128)
            assert strip_padding(padded) == original, \
                "FAIL: strip_padding did not recover original plaintext"

    def test_pad_zero_limits_prepends_only_header(self):
        # with padding_min=0, padding_max=0: padded contains only 2-byte header + original
        import struct
        from evasion.padding_strat import pad, strip_padding

        original = b'hello world'
        padded   = pad(original, 0, 0)
        assert padded == struct.pack('>H', 0) + original, \
            "FAIL: zero-limit pad should prepend only 2-byte zero header"
        assert strip_padding(padded) == original, \
            "FAIL: strip_padding should recover original for zero-limit pad"

    def test_pad_nonzero_limits_increases_length(self):
        # with padding_min=64, padding_max=128: padded is always longer than original
        from evasion.padding_strat import pad

        original = b'hello world'
        for _ in range(20):
            padded = pad(original, 64, 128)
            # 2-byte header + 64-128 pad bytes + original
            assert len(padded) >= 2 + 64 + len(original), \
                f"FAIL: padded length {len(padded)} not greater than original {len(original)}"
            assert len(padded) <= 2 + 128 + len(original), \
                f"FAIL: padded length {len(padded)} exceeds max expected"

    def test_pack_unpack_round_trip_with_medium_profile(self, key):
        # pack/unpack round-trips correctly with padding active (medium profile)
        from transport.traffic_profile import load_profile

        profile = load_profile('medium')
        assert profile.padding_min == 0
        assert profile.padding_max == 128

        payload   = build_checkin('VICTIM-PC', 'jdoe', 'Windows 10', '1.0.0', 20)
        raw       = pack(payload, key)
        recovered = unpack(raw, key)

        assert recovered['msg_type']              == MSG_CHECKIN
        assert recovered['payload']['hostname']   == 'VICTIM-PC'
        assert recovered['payload']['username']   == 'jdoe'
        assert recovered['payload']['agent_ver']  == '1.0.0'