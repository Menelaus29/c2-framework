import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag
from common.utils import CryptoError


# Constant
NONCE_SIZE_BYTES = 12    
KEY_SIZE_BYTES   = 32    
TAG_SIZE_BYTES   = 16  #authentication tag length
HKDF_INFO        = b'c2-framework-v1'  # context label for HKDF


# KDF
def derive_key(psk: bytes, salt: bytes) -> bytes:
    if not psk:
        raise CryptoError("derive_key: psk must not be empty")
    if not salt:
        raise CryptoError("derive_key: salt must not be empty")
    try:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE_BYTES,
            salt=salt,
            info=HKDF_INFO,
        )
        return hkdf.derive(psk)

    except Exception as e:
        raise CryptoError(f"derive_key failed: {e}") from e


# Encryption
def encrypt(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    if not plaintext:
        raise CryptoError("encrypt: plaintext must not be empty")

    if len(key) != KEY_SIZE_BYTES:
        raise CryptoError(
            f"encrypt: key must be {KEY_SIZE_BYTES} bytes, got {len(key)}"
        )

    try:
        nonce = os.urandom(NONCE_SIZE_BYTES) # nonce is random and unique
        aesgcm = AESGCM(key)
        # aesgcm.encrypt() returns ciphertext + 16-byte tag concatenated
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)
        return ciphertext_with_tag, nonce # nonce isnt secret to allow decryption

    except CryptoError:
        raise
    except Exception as e:
        raise CryptoError(f"encrypt failed: {e}") from e


# Decryption
def decrypt(ciphertext_with_tag: bytes, nonce: bytes, key: bytes) -> bytes:
    if not ciphertext_with_tag:
        raise CryptoError("decrypt: ciphertext must not be empty")

    if len(nonce) != NONCE_SIZE_BYTES:
        raise CryptoError(
            f"decrypt: nonce must be {NONCE_SIZE_BYTES} bytes, got {len(nonce)}"
        )

    if len(key) != KEY_SIZE_BYTES:
        raise CryptoError(
            f"decrypt: key must be {KEY_SIZE_BYTES} bytes, got {len(key)}"
        )

    # minimum valid ciphertext is at least 16 bytes (the case of empty plaintext)
    if len(ciphertext_with_tag) < TAG_SIZE_BYTES:
        raise CryptoError(
            f"decrypt: ciphertext too short to contain GCM tag "
            f"(got {len(ciphertext_with_tag)} bytes, need at least {TAG_SIZE_BYTES})"
        )

    try:
        aesgcm = AESGCM(key)
        # aesgcm.decrypt() verifies the tag and raises InvalidTag if it fails
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
        return plaintext

    except InvalidTag:
        raise CryptoError(
            "decrypt: authentication tag verification failed — "
            "ciphertext may have been tampered with"
        )
    except CryptoError:
        raise
    except Exception as e:
        raise CryptoError(f"decrypt failed: {e}") from e


# Convenience: get a ready-to-use key from config
def get_session_key() -> bytes:
    from common import config   # deferred import to avoid circular imports

    if len(config.PRE_SHARED_KEY) != KEY_SIZE_BYTES:
        raise CryptoError(
            f"config.PRE_SHARED_KEY must be exactly {KEY_SIZE_BYTES} bytes, "
            f"got {len(config.PRE_SHARED_KEY)}. "
            f"Fix the key length in common/config.py"
        )

    return derive_key(
        psk=config.PRE_SHARED_KEY,
        salt=b'c2-lab-fixed-salt-v1',
    )


# Module self-test (run with: python -m common.crypto)
if __name__ == '__main__':
    print("Running crypto self-test...")

    # 1. Key derivation is deterministic
    key1 = derive_key(b'A' * 32, b'test-salt')
    key2 = derive_key(b'A' * 32, b'test-salt')
    assert key1 == key2, "FAIL: derive_key is not deterministic"
    print("  [OK] derive_key is deterministic")

    # 2. Different salts produce different keys
    key3 = derive_key(b'A' * 32, b'other-salt')
    assert key1 != key3, "FAIL: different salts should produce different keys"
    print("  [OK] different salts produce different keys")

    # 3. Encrypt then decrypt returns original plaintext
    key = derive_key(b'B' * 32, b'self-test-salt')
    original = b'hello from the self-test'
    ct, nonce = encrypt(original, key)
    recovered = decrypt(ct, nonce, key)
    assert recovered == original, "FAIL: encrypt/decrypt round-trip failed"
    print("  [OK] encrypt/decrypt round-trip correct")

    # 4. Two encryptions of the same plaintext produce different ciphertexts
    ct2, nonce2 = encrypt(original, key)
    assert ct != ct2, "FAIL: nonces should differ between calls"
    assert nonce != nonce2, "FAIL: nonces must be unique per encryption"
    print("  [OK] each encryption uses a unique nonce")

    # 5. Tampered ciphertext raises CryptoError
    tampered = bytearray(ct)
    tampered[0] ^= 0xFF   # flip all bits in the first byte
    try:
        decrypt(bytes(tampered), nonce, key)
        print("  FAIL: tampered ciphertext should have raised CryptoError")
    except CryptoError:
        print("  [OK] tampered ciphertext raises CryptoError")

    # 6. Wrong key raises CryptoError
    wrong_key = derive_key(b'C' * 32, b'self-test-salt')
    try:
        decrypt(ct, nonce, wrong_key)
        print("  FAIL: wrong key should have raised CryptoError")
    except CryptoError:
        print("  [OK] wrong key raises CryptoError")

    print("\nAll self-tests passed.")