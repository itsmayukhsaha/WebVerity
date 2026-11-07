"""TLS socket connection and handshake management.

Establishes TLS connections using pinned destination IP and SNI hostname,
verifying trust store certificates with graceful fallback for forensic inspection.
"""

import socket
import ssl

from backend.app.core.config import settings
from backend.app.core.logging import logger


class TLSHandshakeResult:
    """Encapsulates outcomes of a TLS handshake attempt."""

    def __init__(
        self,
        der_cert: bytes | None = None,
        tls_version: str | None = None,
        cipher: str | None = None,
        is_verified: bool = False,
        verification_error: str | None = None,
        handshake_success: bool = False,
        error_type: str | None = None,
    ):
        self.der_cert = der_cert
        self.tls_version = tls_version
        self.cipher = cipher
        self.is_verified = is_verified
        self.verification_error = verification_error
        self.handshake_success = handshake_success
        self.error_type = error_type


def perform_tls_handshake(
    destination_ip: str,
    hostname: str,
    port: int = 443,
    timeout: float | None = None,
) -> TLSHandshakeResult:
    """Execute TLS handshake to a pinned destination IP with SNI.

    Args:
        destination_ip: Pre-validated public IP to connect to.
        hostname: Original hostname passed for SNI and verification.
        port: Destination port (default 443).
        timeout: Socket timeout in seconds.

    Returns:
        TLSHandshakeResult with certificate data and handshake diagnostics.
    """
    effective_timeout = timeout if timeout is not None else settings.TLS_TIMEOUT

    # Step 1: Attempt standard verified handshake against system trust store
    verified_context = ssl.create_default_context()
    try:
        with socket.create_connection((destination_ip, port), timeout=effective_timeout) as sock:
            with verified_context.wrap_socket(sock, server_hostname=hostname) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                tls_version = ssock.version()
                cipher_info = ssock.cipher()
                cipher_name = cipher_info[0] if cipher_info else None
                return TLSHandshakeResult(
                    der_cert=der_cert,
                    tls_version=tls_version,
                    cipher=cipher_name,
                    is_verified=True,
                    verification_error=None,
                    handshake_success=True,
                )
    except ssl.SSLCertVerificationError as e:
        logger.info(
            f"TLS certificate verification failed for {hostname} at {destination_ip}: {e.verify_message}"
        )
        verification_error = f"{e.verify_message} (code: {e.verify_code})"
    except ssl.SSLError as e:
        logger.info(f"TLS SSL error for {hostname} at {destination_ip}: {e}")
        verification_error = str(e)
    except TimeoutError:
        logger.warning(f"TLS connection timeout for {hostname} at {destination_ip}:{port}")
        return TLSHandshakeResult(
            error_type="TIMEOUT",
            verification_error="Connection to server timed out during TLS handshake.",
        )
    except (ConnectionRefusedError, OSError) as e:
        logger.warning(
            f"TLS connection refused or unreachable for {hostname} at {destination_ip}:{port}: {e}"
        )
        return TLSHandshakeResult(
            error_type="CONNECTION_FAILED",
            verification_error=f"Connection failed: {e}",
        )

    # Step 2: Fallback to unverified context to extract certificate for forensic analysis
    try:
        unverified_context = ssl._create_unverified_context()
        with socket.create_connection((destination_ip, port), timeout=effective_timeout) as sock:
            with unverified_context.wrap_socket(sock, server_hostname=hostname) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                tls_version = ssock.version()
                cipher_info = ssock.cipher()
                cipher_name = cipher_info[0] if cipher_info else None
                return TLSHandshakeResult(
                    der_cert=der_cert,
                    tls_version=tls_version,
                    cipher=cipher_name,
                    is_verified=False,
                    verification_error=verification_error,
                    handshake_success=True,
                )
    except Exception as e:
        logger.warning(f"Unverified fallback handshake also failed for {hostname}: {e}")
        return TLSHandshakeResult(
            is_verified=False,
            verification_error=verification_error or str(e),
            handshake_success=False,
            error_type="HANDSHAKE_FAILED",
        )
