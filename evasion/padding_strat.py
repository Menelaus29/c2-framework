import os
import random
import struct

HEADER_SIZE = 2  # 2-byte uint16 big-endian length prefix


def pad(plaintext: bytes, min_bytes: int, max_bytes: int) -> bytes:
    # Prepend a 2-byte length prefix and random pad bytes to plaintext.
    if min_bytes > max_bytes:
        raise ValueError(
            f"invalid padding range: min_bytes ({min_bytes}) > max_bytes ({max_bytes})"
        )

    pad_len   = random.randint(min_bytes, max_bytes) if max_bytes > 0 else 0
    pad_bytes = os.urandom(pad_len)

    # length prefix lets strip_padding know exactly how many bytes to skip
    return struct.pack('>H', pad_len) + pad_bytes + plaintext


def strip_padding(padded: bytes) -> bytes:
    # Remove the padding prepended by pad() and return the original plaintext.
    if len(padded) < HEADER_SIZE:
        raise ValueError(
            f'strip_padding: input too short to contain length prefix '
            f'(got {len(padded)} bytes, need at least {HEADER_SIZE})'
        )

    pad_len = struct.unpack('>H', padded[:HEADER_SIZE])[0]

    expected_min = HEADER_SIZE + pad_len
    if len(padded) < expected_min:
        raise ValueError(
            f'strip_padding: input too short — '
            f'header claims {pad_len} pad bytes but only '
            f'{len(padded) - HEADER_SIZE} bytes follow the header'
        )

    return padded[HEADER_SIZE + pad_len:]


# Self-test
if __name__ == '__main__':
    print("Running padding_strategy self-test...")

    # Test 1 — baseline: zero padding adds only the 2-byte header
    original = b'hello world'
    result   = pad(original, 0, 0)
    assert result == struct.pack('>H', 0) + original, \
        "FAIL: baseline should prepend 2-byte zero header only"
    assert strip_padding(result) == original, \
        "FAIL: baseline round-trip failed"
    print("  [OK] baseline (0,0) prepends 2-byte zero header, strip recovers original")

    # Test 2 — pad then strip returns original plaintext
    for min_b, max_b in [(0, 64), (64, 128), (64, 256), (1, 1), (128, 128)]:
        padded    = pad(original, min_b, max_b)
        recovered = strip_padding(padded)
        assert recovered == original, \
            f"FAIL: round-trip failed for min={min_b} max={max_b}"
    print("  [OK] pad→strip round-trip correct for all ranges")

    # Test 3 — padded length is within expected range
    for _ in range(50):
        padded = pad(original, 10, 100)
        # total = 2 (header) + pad_len (10-100) + len(original)
        assert HEADER_SIZE + 10 + len(original) <= len(padded) <= HEADER_SIZE + 100 + len(original), \
            "FAIL: padded length outside expected range"
    print("  [OK] padded length always within expected range")

    # Test 4 — pad_len=1 (min==max==1) always adds exactly 1 byte
    padded = pad(original, 1, 1)
    assert len(padded) == HEADER_SIZE + 1 + len(original), \
        "FAIL: min==max==1 should add exactly 1 pad byte"
    assert strip_padding(padded) == original, \
        "FAIL: strip failed for min==max==1"
    print("  [OK] min==max==1 adds exactly 1 pad byte")

    # Test 5 — two pads of same plaintext produce different output (random pad)

    # Generate multiple padded samples
    samples = [pad(original, 32, 32) for _ in range(10)]

    # Check if they are all identical
    all_same = all(s == samples[0] for s in samples)

    assert not all_same, "FAIL: padding should be random, not deterministic"
    print("  [OK] padding content is random")

    # Test 6 — strip_padding raises ValueError on too-short input
    try:
        strip_padding(b'\x00')
        print("  FAIL: should raise ValueError on 1-byte input")
    except ValueError:
        print("  [OK] strip_padding raises ValueError on too-short input")

    # Test 7 — strip_padding raises ValueError when claimed pad_len exceeds data
    import struct as _struct
    bad = _struct.pack('>H', 200) + b'\x00' * 10  # claims 200 pad bytes, only 10 present
    try:
        strip_padding(bad)
        print("  FAIL: should raise ValueError on truncated padded data")
    except ValueError:
        print("  [OK] strip_padding raises ValueError on truncated data")

    print("\nAll padding_strategy self-tests passed.")