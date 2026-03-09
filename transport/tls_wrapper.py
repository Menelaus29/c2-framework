import os
import ssl
import hashlib
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding
from common.logger import get_logger


logger = get_logger('transport')


def create_ssl_context(cert_path: str) -> ssl.SSLContext:
    # Create a TLS client context pinned to the lab self-signed cert.
    path = os.path.abspath(cert_path)
    if not os.path.exists(path):
        raise FileNotFoundError(f'TLS cert not found: {path}')

    ctx                 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_verify_locations(path)
    ctx.check_hostname  = False   # lab cert uses IP, not hostname in CN
    ctx.verify_mode     = ssl.CERT_REQUIRED

    fingerprint = get_cert_fingerprint(path)
    logger.info('pinned cert fingerprint', extra={
        'cert_path':   path,
        'fingerprint': fingerprint,
    })

    return ctx


def get_cert_fingerprint(cert_path: str) -> str:
    # Load the DER-encoded cert and return its SHA-256 fingerprint as a hex string.
    path = os.path.abspath(cert_path)
    if not os.path.exists(path):
        raise FileNotFoundError(f'TLS cert not found: {path}')

    with open(path, 'rb') as f:
        pem_data = f.read()

    cert        = x509.load_pem_x509_certificate(pem_data, default_backend())
    der_bytes   = cert.public_bytes(Encoding.DER)
    fingerprint = hashlib.sha256(der_bytes).hexdigest()
    return fingerprint


# Self-test
if __name__ == '__main__':
    import sys
    from common import config

    print("Running tls_wrapper self-test...")

    cert_path = config.TLS_CERT_PATH

    # Test 1 — cert file exists
    assert os.path.exists(cert_path), \
        f"FAIL: cert file not found at {cert_path}"
    print(f"  [OK] cert file found at {cert_path}")

    # Test 2 — get_cert_fingerprint returns a 64-char hex string
    fp = get_cert_fingerprint(cert_path)
    assert isinstance(fp, str),    "FAIL: fingerprint should be a string"
    assert len(fp) == 64,          f"FAIL: SHA-256 hex should be 64 chars, got {len(fp)}"
    assert all(c in '0123456789abcdef' for c in fp), \
        "FAIL: fingerprint should be lowercase hex"
    print(f"  [OK] fingerprint: {fp}")

    # Test 3 — fingerprint is deterministic across calls
    fp2 = get_cert_fingerprint(cert_path)
    assert fp == fp2, "FAIL: fingerprint should be deterministic"
    print("  [OK] fingerprint is deterministic")

    # Test 4 — create_ssl_context returns ssl.SSLContext
    ctx = create_ssl_context(cert_path)
    assert isinstance(ctx, ssl.SSLContext), \
        "FAIL: create_ssl_context should return ssl.SSLContext"
    print("  [OK] create_ssl_context returns ssl.SSLContext")

    # Test 5 — context enforces TLS 1.2 minimum
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2, \
        "FAIL: minimum TLS version should be TLSv1_2"
    print("  [OK] minimum TLS version is TLSv1_2")

    # Test 6 — context requires cert verification
    assert ctx.verify_mode == ssl.CERT_REQUIRED, \
        "FAIL: verify_mode should be CERT_REQUIRED"
    print("  [OK] verify_mode is CERT_REQUIRED")

    # Test 7 — missing cert raises FileNotFoundError
    try:
        create_ssl_context('nonexistent/path/cert.crt')
        print("  FAIL: should raise FileNotFoundError for missing cert")
    except FileNotFoundError:
        print("  [OK] missing cert raises FileNotFoundError")

    # Test 8 — missing cert in get_cert_fingerprint raises FileNotFoundError
    try:
        get_cert_fingerprint('nonexistent/path/cert.crt')
        print("  FAIL: should raise FileNotFoundError for missing cert")
    except FileNotFoundError:
        print("  [OK] get_cert_fingerprint raises FileNotFoundError for missing cert")

    print("\nAll tls_wrapper self-tests passed.")