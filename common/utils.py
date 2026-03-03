"""
Custom exception hierarchy for the framework.
These exceptions are raised by all the modules instead of the built-in exceptions
to avoid catching anything irrelevant to the framework.
"""

class C2Error(Exception):
    """
    Base exception for all framework errors.
    Catch this in the beacon loop to handle any framework failure
    without crashing the agent process.
    """
    pass


class CryptoError(C2Error):
    """
    Raised by common/crypto.py on any cryptographic failure.

    Covers:
        - AES-GCM authentication tag verification failure (tampered ciphertext)
        - Invalid key length
        - Invalid nonce length
        - Any internal cryptography library error
        
    Raw exception message from the cryptography library is logged server-side only.     
    """
    pass


class ProtocolError(C2Error):
    """
    Raised by common/message_format.py on any protocol-level failure.

    Covers:
        - Wrong magic bytes in envelope header
        - Unsupported protocol version
        - Truncated or malformed envelope
        - Invalid JSON in decrypted payload
        - Missing required fields in payload dict
    """
    pass


class TransportError(C2Error):
    """
    Raised by transport/http_transport.py on any network failure.

    Covers:
        - Connection refused or timed out
        - HTTP 4xx or 5xx response from server
        - Host not in ALLOWED_HOSTS (hard safety control)
        - TLS certificate verification failure
    """
    def __init__(self, message: str, status_code: int = None):
        super().__init__(message)
        self.status_code = status_code


class EnvironmentError(C2Error):
    """
    Raised by agent/environment_checks.py when the lab gate fails.

    Covers:
        - LAB_MODE environment variable not set to '1'
        - Target host not in ALLOWED_HOSTS
    """
    pass