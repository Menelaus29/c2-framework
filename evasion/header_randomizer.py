import random
from common import config

# Browser User-Agent strings
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
]

ACCEPT_LANGUAGES = [
    'en-US,en;q=0.9',
    'en-GB,en;q=0.9',
    'fr-FR,fr;q=0.9,en;q=0.8',
    'de-DE,de;q=0.9,en;q=0.8',
    'ja-JP,ja;q=0.9,en;q=0.8',
    'zh-CN,zh;q=0.9,en;q=0.8',
    'pt-BR,pt;q=0.9,en;q=0.8',
]

ACCEPT_ENCODINGS = [
    'gzip, deflate, br',
    'gzip, deflate',
    'br, gzip',
]

_CHROME_UA       = USER_AGENTS[0]   # fixed UA for level 0 and 1 fallback
_DEFAULT_LANG    = ACCEPT_LANGUAGES[0]  # en-US default for levels 0 and 1


def get_headers(level: int) -> dict:
    # Return HTTP headers for a beacon request at the given randomisation level.
    if level not in (0, 1, 2, 3):
        raise ValueError(f'invalid header randomisation level: {level}')

    if level == 0:
        ua       = _CHROME_UA
        language = _DEFAULT_LANG
        encoding = ACCEPT_ENCODINGS[0]
        optional = _build_optional(ua, language, encoding)

    elif level == 1:
        ua       = random.choice(USER_AGENTS)
        language = _DEFAULT_LANG
        encoding = ACCEPT_ENCODINGS[0]
        optional = _build_optional(ua, language, encoding)

    elif level == 2:
        ua       = random.choice(USER_AGENTS)
        language = random.choice(ACCEPT_LANGUAGES)
        encoding = ACCEPT_ENCODINGS[0]
        optional = _build_optional(ua, language, encoding)

    else:
        # Level 3 — randomise UA, language, encoding, and shuffle optional header order
        ua       = random.choice(USER_AGENTS)
        language = random.choice(ACCEPT_LANGUAGES)
        encoding = random.choice(ACCEPT_ENCODINGS)
        optional = _build_optional(ua, language, encoding)
        random.shuffle(optional)

    # Host and Content-Type are always fixed and never shuffled
    host = config.SERVER_HOST
    port = config.SERVER_PORT

    # Include port if non-standard
    if port not in (80, 443):
        host = f"{host}:{port}"

    headers = {
        'Host':         host,
        'Content-Type': 'application/octet-stream',
    }
    headers.update(dict(optional))
    return headers


def _build_optional(ua: str, language: str, encoding: str) -> list[tuple[str, str]]:
    # Return optional headers as an ordered list of (name, value) tuples.
    return [
        ('User-Agent',       ua),
        ('Accept-Language',  language),
        ('Accept-Encoding',  encoding),
        ('Accept',           '*/*'),
        ('Connection',       'keep-alive'),
    ]


# Self-test
if __name__ == '__main__':
    print("Running header_randomizer self-test...")

    # Test 1 — all levels return required fixed headers
    for level in range(4):
        headers = get_headers(level)
        assert 'Host'         in headers, f"FAIL: Host missing at level {level}"
        assert 'Content-Type' in headers, f"FAIL: Content-Type missing at level {level}"
        assert headers['Content-Type'] == 'application/octet-stream', \
            f"FAIL: wrong Content-Type at level {level}"

        expected_host = config.SERVER_HOST
        if config.SERVER_PORT not in (80, 443):
            expected_host = f"{config.SERVER_HOST}:{config.SERVER_PORT}"

        assert headers['Host'] == expected_host, \
            f"FAIL: wrong Host at level {level}"
        print(f"  [OK] level {level} contains required fixed headers")

    # Test 2 — level 0 always returns Chrome UA
    for _ in range(10):
        headers = get_headers(0)
        assert headers['User-Agent'] == _CHROME_UA, \
            "FAIL: level 0 should always use Chrome UA"
    print("  [OK] level 0 always uses Chrome UA")

    # Test 3 — level 1 uses random UA but fixed language
    uas_seen = set()
    for _ in range(50):
        headers = get_headers(1)
        uas_seen.add(headers['User-Agent'])
        assert headers['Accept-Language'] == _DEFAULT_LANG, \
            "FAIL: level 1 should use fixed language"
    assert len(uas_seen) > 1, "FAIL: level 1 should rotate UA"
    print("  [OK] level 1 rotates UA, keeps fixed language")

    # Test 4 — level 2 randomises both UA and language
    langs_seen = set()
    for _ in range(100):
        headers = get_headers(2)
        langs_seen.add(headers['Accept-Language'])
    assert len(langs_seen) > 1, "FAIL: level 2 should rotate language"
    print("  [OK] level 2 rotates UA and language")

    # Test 5 — level 3 randomises encoding
    encodings_seen = set()
    for _ in range(100):
        headers = get_headers(3)
        encodings_seen.add(headers['Accept-Encoding'])
    assert len(encodings_seen) > 1, "FAIL: level 3 should rotate encoding"
    print("  [OK] level 3 rotates encoding")

    # Test 6 — Host and Content-Type are always first two keys at all levels
    for level in range(4):
        for _ in range(10):
            headers = get_headers(level)
            keys = list(headers.keys())
            assert keys[0] == 'Host',         \
                f"FAIL: Host must be first key at level {level}"
            assert keys[1] == 'Content-Type', \
                f"FAIL: Content-Type must be second key at level {level}"
    print("  [OK] Host and Content-Type always appear first")

    # Test 7 — level 3 produces different header orders across calls
    orders_seen = set()
    for _ in range(50):
        headers  = get_headers(3)
        # exclude the fixed first two keys, capture order of optional headers
        optional_keys = tuple(list(headers.keys())[2:])
        orders_seen.add(optional_keys)
    assert len(orders_seen) > 1, "FAIL: level 3 should shuffle optional header order"
    print("  [OK] level 3 shuffles optional header order")

    print("\nAll header_randomizer self-tests passed.")