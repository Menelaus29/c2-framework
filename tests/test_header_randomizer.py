import pytest
from unittest.mock import patch
import common.config as config
from evasion.header_randomizer import (
    get_headers,
    USER_AGENTS,
    ACCEPT_LANGUAGES,
    ACCEPT_ENCODINGS,
    _CHROME_UA,
    _DEFAULT_LANG,
)


@pytest.fixture(autouse=True)
def patch_config(monkeypatch):
    # Pin config values so tests are independent of whatever is in config.py
    monkeypatch.setattr(config, 'SERVER_HOST', 'c2.lab.internal')
    monkeypatch.setattr(config, 'SERVER_PORT', 443)


class TestGetHeadersReturnStructure:

    def test_returns_dict(self):
        result = get_headers(0)
        assert isinstance(result, dict)

    def test_all_values_are_strings(self):
        for level in range(4):
            headers = get_headers(level)
            for k, v in headers.items():
                assert isinstance(v, str), (
                    f"Level {level}: value for '{k}' is {type(v)}, expected str"
                )

    def test_invalid_level_raises_value_error(self):
        with pytest.raises(ValueError):
            get_headers(-1)

    def test_invalid_level_4_raises_value_error(self):
        with pytest.raises(ValueError):
            get_headers(4)

    def test_invalid_level_99_raises_value_error(self):
        with pytest.raises(ValueError):
            get_headers(99)


class TestFixedHeaders:
    # Host and Content-Type must always be present and always be the first two keys

    @pytest.mark.parametrize("level", [0, 1, 2, 3])
    def test_host_present_at_all_levels(self, level):
        assert 'Host' in get_headers(level)

    @pytest.mark.parametrize("level", [0, 1, 2, 3])
    def test_content_type_present_at_all_levels(self, level):
        assert 'Content-Type' in get_headers(level)

    @pytest.mark.parametrize("level", [0, 1, 2, 3])
    def test_content_type_value_is_octet_stream(self, level):
        assert get_headers(level)['Content-Type'] == 'application/octet-stream'

    @pytest.mark.parametrize("level", [0, 1, 2, 3])
    def test_host_is_first_key(self, level):
        keys = list(get_headers(level).keys())
        assert keys[0] == 'Host', (
            f"Level {level}: Host must be first key, got '{keys[0]}'"
        )

    @pytest.mark.parametrize("level", [0, 1, 2, 3])
    def test_content_type_is_second_key(self, level):
        keys = list(get_headers(level).keys())
        assert keys[1] == 'Content-Type', (
            f"Level {level}: Content-Type must be second key, got '{keys[1]}'"
        )

    def test_host_standard_port_no_suffix(self, monkeypatch):
        # Port 443 — host must NOT have :443 appended
        monkeypatch.setattr(config, 'SERVER_PORT', 443)
        monkeypatch.setattr(config, 'SERVER_HOST', 'c2.lab.internal')
        assert get_headers(0)['Host'] == 'c2.lab.internal'

    def test_host_port_80_no_suffix(self, monkeypatch):
        # Port 80 — host must NOT have :80 appended
        monkeypatch.setattr(config, 'SERVER_PORT', 80)
        monkeypatch.setattr(config, 'SERVER_HOST', 'c2.lab.internal')
        assert get_headers(0)['Host'] == 'c2.lab.internal'

    def test_host_nonstandard_port_appended(self, monkeypatch):
        # Non-standard port — host MUST have :PORT appended
        monkeypatch.setattr(config, 'SERVER_PORT', 8443)
        monkeypatch.setattr(config, 'SERVER_HOST', 'c2.lab.internal')
        assert get_headers(0)['Host'] == 'c2.lab.internal:8443'

    def test_host_nonstandard_port_8080_appended(self, monkeypatch):
        monkeypatch.setattr(config, 'SERVER_PORT', 8080)
        monkeypatch.setattr(config, 'SERVER_HOST', '192.168.100.10')
        assert get_headers(0)['Host'] == '192.168.100.10:8080'


class TestLevel0Determinism:
    # Level 0 is the baseline — everything must be fixed, no randomness ever

    def test_ua_is_always_chrome(self):
        for _ in range(20):
            assert get_headers(0)['User-Agent'] == _CHROME_UA

    def test_language_is_always_default(self):
        for _ in range(20):
            assert get_headers(0)['Accept-Language'] == _DEFAULT_LANG

    def test_encoding_is_always_first(self):
        for _ in range(20):
            assert get_headers(0)['Accept-Encoding'] == ACCEPT_ENCODINGS[0]

    def test_optional_key_order_never_changes(self):
        # Level 0 must never shuffle — same order every time
        first_order = tuple(list(get_headers(0).keys())[2:])
        for _ in range(20):
            order = tuple(list(get_headers(0).keys())[2:])
            assert order == first_order, (
                "Level 0 optional header order changed between calls"
            )


class TestLevel1Behaviour:
    # Level 1: UA rotates, language and encoding stay fixed

    def test_language_is_always_default(self):
        for _ in range(30):
            assert get_headers(1)['Accept-Language'] == _DEFAULT_LANG

    def test_encoding_is_always_first(self):
        for _ in range(30):
            assert get_headers(1)['Accept-Encoding'] == ACCEPT_ENCODINGS[0]

    def test_ua_rotates_across_calls(self):
        uas_seen = {get_headers(1)['User-Agent'] for _ in range(50)}
        assert len(uas_seen) > 1, (
            "Level 1 UA never changed across 50 calls — rotation not working"
        )

    def test_ua_values_come_from_pool(self):
        for _ in range(30):
            ua = get_headers(1)['User-Agent']
            assert ua in USER_AGENTS, f"UA '{ua}' is not in the USER_AGENTS pool"


class TestLevel2Behaviour:
    # Level 2: UA and language rotate, encoding stays fixed

    def test_encoding_is_always_first(self):
        for _ in range(30):
            assert get_headers(2)['Accept-Encoding'] == ACCEPT_ENCODINGS[0]

    def test_ua_rotates(self):
        uas_seen = {get_headers(2)['User-Agent'] for _ in range(50)}
        assert len(uas_seen) > 1

    def test_language_rotates(self):
        langs_seen = {get_headers(2)['Accept-Language'] for _ in range(50)}
        assert len(langs_seen) > 1, (
            "Level 2 Accept-Language never changed across 50 calls"
        )

    def test_language_values_come_from_pool(self):
        for _ in range(30):
            lang = get_headers(2)['Accept-Language']
            assert lang in ACCEPT_LANGUAGES, (
                f"Language '{lang}' is not in the ACCEPT_LANGUAGES pool"
            )


class TestLevel3Behaviour:
    # Level 3: everything rotates and optional header order is shuffled

    def test_ua_rotates(self):
        uas_seen = {get_headers(3)['User-Agent'] for _ in range(50)}
        assert len(uas_seen) > 1

    def test_language_rotates(self):
        langs_seen = {get_headers(3)['Accept-Language'] for _ in range(50)}
        assert len(langs_seen) > 1

    def test_encoding_rotates(self):
        encodings_seen = {get_headers(3)['Accept-Encoding'] for _ in range(50)}
        assert len(encodings_seen) > 1, (
            "Level 3 Accept-Encoding never changed across 50 calls"
        )

    def test_encoding_values_come_from_pool(self):
        for _ in range(30):
            enc = get_headers(3)['Accept-Encoding']
            assert enc in ACCEPT_ENCODINGS

    def test_optional_header_order_shuffles(self):
        # Run enough times to see at least two distinct orderings
        orders_seen = set()
        for _ in range(50):
            keys = tuple(list(get_headers(3).keys())[2:])
            orders_seen.add(keys)
        assert len(orders_seen) > 1, (
            "Level 3 optional header order never changed across 50 calls — "
            "shuffle not working"
        )

    def test_fixed_headers_survive_shuffle(self):
        # Even with shuffling, Host and Content-Type must stay in position
        for _ in range(30):
            keys = list(get_headers(3).keys())
            assert keys[0] == 'Host'
            assert keys[1] == 'Content-Type'