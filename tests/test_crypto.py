import os
import pytest
import cryptography.hazmat.primitives.kdf.hkdf as hkdf_module
import cryptography.hazmat.primitives.ciphers.aead as aead_module

from common.crypto import (
    derive_key,
    encrypt,
    decrypt,
    get_session_key,
    NONCE_SIZE_BYTES,
    KEY_SIZE_BYTES,
    TAG_SIZE_BYTES,
)
from common.utils import CryptoError


# Fixtures: reused across multiple tests
@pytest.fixture
def valid_key():
    return derive_key(b'A' * 32, b'test-salt-fixture')


@pytest.fixture
def different_key():
    return derive_key(b'B' * 32, b'test-salt-fixture')


@pytest.fixture
def sample_plaintext():
    return b'yae miko and changli might not be ganyu but they are goats'


@pytest.fixture
def encrypted_sample(valid_key, sample_plaintext):
    # pre-encrypted sample returned as (ciphertext_with_tag, nonce)
    return encrypt(sample_plaintext, valid_key)


# derive_key tests
class TestDeriveKey:

    def test_output_is_32_bytes(self):
        # derive_key must always return exactly 32 bytes for AES-256.
        key = derive_key(b'any psk value', b'any salt value')
        assert len(key) == KEY_SIZE_BYTES, (
            f"Expected {KEY_SIZE_BYTES} bytes, got {len(key)}"
        )

    def test_deterministic_same_inputs(self):
        # same PSK and salt must always produce the same key as HKDF is deterministic
        psk  = b'determinism-test-psk-value-112905'
        salt = b'determinism-test-salt'

        key1 = derive_key(psk, salt)
        key2 = derive_key(psk, salt)

        assert key1 == key2, (
            "derive_key returned different keys for identical inputs — "
            "HKDF must be deterministic"
        )

    def test_deterministic_across_50_calls(self):
        # test determinism across 50 calls
        psk  = b'X' * 32
        salt = b'repeated-call-salt'
        reference = derive_key(psk, salt)

        for i in range(50):
            result = derive_key(psk, salt)
            assert result == reference, (
                f"derive_key returned a different key on call {i + 1}"
            )

    def test_different_salt_produces_different_key(self):
        # test that different salts produce different keys
        psk    = b'same-psk-value-for-salt-test-xxx'
        salt_a = b'salt-alpha'
        salt_b = b'salt-beta'

        key_a = derive_key(psk, salt_a)
        key_b = derive_key(psk, salt_b)

        assert key_a != key_b, (
            "derive_key returned the same key for different salts — "
            "salt is not being mixed into derivation correctly"
        )

    def test_different_psk_produces_different_key(self):
        # different PSKs with the same salt must produce different keys.
        salt  = b'shared-salt-value'
        psk_a = b'first-pre-shared-key-value-12345'
        psk_b = b'second-pre-shared-key-value-1234'

        key_a = derive_key(psk_a, salt)
        key_b = derive_key(psk_b, salt)

        assert key_a != key_b, (
            "derive_key returned the same key for different PSKs"
        )

    def test_output_is_bytes(self):
        # derive_key must return a bytes object
        key = derive_key(b'psk-value-bytes-test-xxxxxxxxxx', b'salt')
        assert isinstance(key, bytes), (
            f"Expected bytes, got {type(key)}"
        )

    def test_empty_psk_raises_crypto_error(self):
        # empty PSK must raise CryptoError
        with pytest.raises(CryptoError):
            derive_key(b'', b'some-salt')

    def test_empty_salt_raises_crypto_error(self):
        # empty salt must raise CryptoError
        with pytest.raises(CryptoError):
            derive_key(b'some-psk-value-here-xxxxxxxxxx', b'')

    def test_internal_hkdf_failure_raises_crypto_error(self, monkeypatch):
        # Force HKDF.derive() itself to throw to cover the general except block
        original_derive = hkdf_module.HKDF.derive

        def exploding_derive(self, key_material):
            raise RuntimeError("simulated internal HKDF failure")

        monkeypatch.setattr(hkdf_module.HKDF, 'derive', exploding_derive)

        with pytest.raises(CryptoError, match="derive_key failed"):
            derive_key(b'A' * 32, b'some-salt')       


# encrypt tests
class TestEncrypt:

    def test_returns_tuple_of_two_bytes(self, valid_key, sample_plaintext):
        # encrypt must return a tuple of exactly two bytes objects
        result = encrypt(sample_plaintext, valid_key)

        assert isinstance(result, tuple), "encrypt must return a tuple"
        assert len(result) == 2, "encrypt must return exactly 2 elements"

        ciphertext, nonce = result
        assert isinstance(ciphertext, bytes), "ciphertext must be bytes"
        assert isinstance(nonce, bytes), "nonce must be bytes"

    def test_nonce_is_12_bytes(self, valid_key, sample_plaintext):
        _, nonce = encrypt(sample_plaintext, valid_key)
        assert len(nonce) == NONCE_SIZE_BYTES, (
            f"Expected {NONCE_SIZE_BYTES}-byte nonce, got {len(nonce)}"
        )

    def test_ciphertext_longer_than_plaintext(self, valid_key, sample_plaintext):
        ciphertext, _ = encrypt(sample_plaintext, valid_key)
        assert len(ciphertext) > len(sample_plaintext), (
            "Ciphertext should be longer than plaintext due to GCM tag"
        )

    def test_ciphertext_length_equals_plaintext_plus_tag(
        self, valid_key, sample_plaintext
    ): 
        # test if ciphertext length equals plaintext length plus the 16-byte tag exactly.
        ciphertext, _ = encrypt(sample_plaintext, valid_key)
        expected_len = len(sample_plaintext) + TAG_SIZE_BYTES
        assert len(ciphertext) == expected_len, (
            f"Expected {expected_len} bytes, got {len(ciphertext)}"
        )

    def test_unique_nonce_per_call(self, valid_key, sample_plaintext):
        # test if every call to encrypt() must generate a unique nonce
        nonces = set()
        for _ in range(100):
            _, nonce = encrypt(sample_plaintext, valid_key)
            nonces.add(nonce)

        assert len(nonces) == 100, (
            f"Expected 100 unique nonces, got {len(nonces)} — "
            "nonces are not sufficiently random"
        )

    def test_different_ciphertext_per_call(self, valid_key, sample_plaintext):
        # test if two encryptions of the same plaintext must produce 
        # different ciphertexts because each uses a different random nonce
        ct1, _ = encrypt(sample_plaintext, valid_key)
        ct2, _ = encrypt(sample_plaintext, valid_key)

        assert ct1 != ct2, (
            "Two encryptions of the same plaintext produced identical "
            "ciphertexts — nonce randomness may be broken"
        )

    def test_wrong_key_length_raises_crypto_error(self, sample_plaintext):
        short_key = b'tooshort'
        with pytest.raises(CryptoError):
            encrypt(sample_plaintext, short_key)

    def test_empty_plaintext_raises_crypto_error(self, valid_key):
        # empty plaintext must raise CryptoError
        with pytest.raises(CryptoError):
            encrypt(b'', valid_key)

    def test_large_plaintext(self, valid_key):
        # test if encrypt() must handle large payloads without error
        large_plaintext = os.urandom(1024 * 1024)
        ciphertext, nonce = encrypt(large_plaintext, valid_key)

        assert len(nonce) == NONCE_SIZE_BYTES
        assert len(ciphertext) == len(large_plaintext) + TAG_SIZE_BYTES

    def test_encrypt_50_random_plaintexts(self, valid_key):
        # test if encrypt() must succeed for 50 different random plaintexts
        for _ in range(50):
            length    = os.urandom(1)[0] + 1    # 1 to 256 bytes
            plaintext = os.urandom(length)
            ciphertext, nonce = encrypt(plaintext, valid_key)

            assert len(nonce) == NONCE_SIZE_BYTES
            assert len(ciphertext) == length + TAG_SIZE_BYTES

    def test_internal_aesgcm_encrypt_failure_raises_crypto_error(
        self, valid_key, sample_plaintext, monkeypatch
    ):
        original_encrypt = aead_module.AESGCM.encrypt

        def exploding_encrypt(self, nonce, data, aad):
            raise RuntimeError("simulated AESGCM failure")

        monkeypatch.setattr(aead_module.AESGCM, 'encrypt', exploding_encrypt)

        with pytest.raises(CryptoError, match="encrypt failed"):
            encrypt(sample_plaintext, valid_key)        


# decrypt tests
class TestDecrypt:

    def test_round_trip_returns_original_plaintext(
        self, valid_key, sample_plaintext, encrypted_sample
    ):
        # test if decrypt(encrypt(x)) equals x
        ciphertext, nonce = encrypted_sample
        recovered = decrypt(ciphertext, nonce, valid_key)
        assert recovered == sample_plaintext, (
            "Round-trip failed: decrypted plaintext does not match original"
        )

    def test_round_trip_50_random_plaintexts(self, valid_key):
        for i in range(50):
            plaintext = os.urandom(os.urandom(1)[0] + 1)
            ciphertext, nonce = encrypt(plaintext, valid_key)
            recovered = decrypt(ciphertext, nonce, valid_key)

            assert recovered == plaintext, (
                f"Round-trip failed on iteration {i + 1}: "
                f"original={plaintext!r}, recovered={recovered!r}"
            )

    def test_tampered_first_byte_raises_crypto_error(
        self, valid_key, encrypted_sample
    ):
        # test if flipping the first byte of the ciphertext causes GCM tag 
        # verification to fail and raise CryptoError
        ciphertext, nonce = encrypted_sample
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF    # flip all bits in byte 0

        with pytest.raises(CryptoError):
            decrypt(bytes(tampered), nonce, valid_key)

    def test_tampered_last_byte_raises_crypto_error(
        self, valid_key, encrypted_sample
    ):
        ciphertext, nonce = encrypted_sample
        tampered = bytearray(ciphertext)
        tampered[-1] ^= 0xFF   # flip all bits in the last byte (tag area)

        with pytest.raises(CryptoError):
            decrypt(bytes(tampered), nonce, valid_key)

    def test_tampered_middle_byte_raises_crypto_error(
        self, valid_key, encrypted_sample
    ):
        ciphertext, nonce = encrypted_sample
        mid = len(ciphertext) // 2
        tampered = bytearray(ciphertext)
        tampered[mid] ^= 0xFF

        with pytest.raises(CryptoError):
            decrypt(bytes(tampered), nonce, valid_key)

    def test_wrong_key_raises_crypto_error(
        self, valid_key, different_key, sample_plaintext
    ):
        # test if decrypting with a different key raises CryptoError
        ciphertext, nonce = encrypt(sample_plaintext, valid_key)

        with pytest.raises(CryptoError):
            decrypt(ciphertext, nonce, different_key)

    def test_wrong_nonce_raises_crypto_error(
        self, valid_key, sample_plaintext
    ):
        ciphertext, _ = encrypt(sample_plaintext, valid_key)
        wrong_nonce    = os.urandom(NONCE_SIZE_BYTES)

        with pytest.raises(CryptoError):
            decrypt(ciphertext, wrong_nonce, valid_key)

    def test_empty_ciphertext_raises_crypto_error(self, valid_key):
        nonce = os.urandom(NONCE_SIZE_BYTES)
        with pytest.raises(CryptoError):
            decrypt(b'', nonce, valid_key)

    def test_ciphertext_shorter_than_tag_raises_crypto_error(self, valid_key):
        # test if ciphertext shorter than the 16-byte GCM tag cannot be valid
        nonce           = os.urandom(NONCE_SIZE_BYTES)
        too_short       = os.urandom(TAG_SIZE_BYTES - 1)   # 15 bytes

        with pytest.raises(CryptoError):
            decrypt(too_short, nonce, valid_key)

    def test_wrong_nonce_length_raises_crypto_error(
        self, valid_key, encrypted_sample
    ):
        ciphertext, _ = encrypted_sample
        bad_nonce      = os.urandom(8)   # wrong length

        with pytest.raises(CryptoError):
            decrypt(ciphertext, bad_nonce, valid_key)

    def test_wrong_key_length_raises_crypto_error(
        self, encrypted_sample
    ):
        ciphertext, nonce = encrypted_sample
        bad_key           = b'tooshort'

        with pytest.raises(CryptoError):
            decrypt(ciphertext, nonce, bad_key)

    def test_truncated_ciphertext_raises_crypto_error(
        self, valid_key, encrypted_sample
    ):
        ciphertext, nonce = encrypted_sample
        truncated         = ciphertext[:len(ciphertext) // 2]

        with pytest.raises(CryptoError):
            decrypt(truncated, nonce, valid_key)

    def test_random_bytes_as_ciphertext_raises_crypto_error(self, valid_key):
        # simulate receiving a garbage or non-C2 packet
        nonce      = os.urandom(NONCE_SIZE_BYTES)
        garbage    = os.urandom(64)

        with pytest.raises(CryptoError):
            decrypt(garbage, nonce, valid_key)

    def test_internal_aesgcm_decrypt_failure_raises_crypto_error(
        self, valid_key, sample_plaintext, monkeypatch
    ):
        def exploding_decrypt(self, nonce, data, aad):
            raise RuntimeError("simulated AESGCM failure")

        monkeypatch.setattr(aead_module.AESGCM, 'decrypt', exploding_decrypt)

        ciphertext, nonce = encrypt(sample_plaintext, valid_key)

        with pytest.raises(CryptoError, match="decrypt failed"):
            decrypt(ciphertext, nonce, valid_key)            


# get_session_key tests
class TestGetSessionKey:

    def test_returns_32_bytes(self):
        key = get_session_key()
        assert len(key) == KEY_SIZE_BYTES, (
            f"Expected {KEY_SIZE_BYTES} bytes, got {len(key)}"
        )

    def test_returns_bytes(self):
        # test if get_session_key returns a bytes object
        key = get_session_key()
        assert isinstance(key, bytes)

    def test_deterministic(self):
        # test if get_session_key returns the same key on repeated calls
        key1 = get_session_key()
        key2 = get_session_key()
        assert key1 == key2, (
            "get_session_key returned different keys on repeated calls"
        )

    def test_usable_for_encrypt_decrypt(self, sample_plaintext):
        # test if a key from get_session_key works correctly with
        # encrypt() and decrypt()
        key           = get_session_key()
        ciphertext, nonce = encrypt(sample_plaintext, key)
        recovered     = decrypt(ciphertext, nonce, key)

        assert recovered == sample_plaintext

    def test_bad_psk_length_raises_crypto_error(self, monkeypatch):
        # test if get_session_key raises CryptoError if psk isnt 32 bytes
        import common.config as config
        monkeypatch.setattr(config, 'PRE_SHARED_KEY', b'tooshort')

        with pytest.raises(CryptoError):
            get_session_key()