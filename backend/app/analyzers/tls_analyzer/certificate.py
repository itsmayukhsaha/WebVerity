"""X.509 certificate parsing and metadata extraction using python-cryptography."""

from datetime import UTC, datetime
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtensionOID, NameOID


def parse_x509_certificate(der_bytes: bytes) -> dict[str, Any]:
    """Parse raw DER-encoded X.509 certificate into structured metadata.

    Args:
        der_bytes: Raw binary certificate data.

    Returns:
        Dictionary of parsed certificate fields.
    """
    cert = x509.load_der_x509_certificate(der_bytes)

    # Subject details
    subject_cn = None
    subject_org = None
    for attr in cert.subject:
        if attr.oid == NameOID.COMMON_NAME:
            subject_cn = attr.value
        elif attr.oid == NameOID.ORGANIZATION_NAME:
            subject_org = attr.value

    # Issuer details
    issuer_cn = None
    issuer_org = None
    for attr in cert.issuer:
        if attr.oid == NameOID.COMMON_NAME:
            issuer_cn = attr.value
        elif attr.oid == NameOID.ORGANIZATION_NAME:
            issuer_org = attr.value

    # Serial number
    serial_number_hex = format(cert.serial_number, "X")

    # Subject Alternative Names (SANs)
    sans: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san_value = san_ext.value
        if isinstance(san_value, x509.SubjectAlternativeName):
            for name in san_value:
                if isinstance(name, (x509.DNSName, x509.IPAddress)):
                    sans.append(str(name.value))
    except x509.ExtensionNotFound:
        pass

    # Validity dates (support both modern utc-aware and older property fallbacks)
    try:
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
    except AttributeError:
        not_before = cert.not_valid_before.replace(tzinfo=UTC)
        not_after = cert.not_valid_after.replace(tzinfo=UTC)

    now = datetime.now(UTC)
    is_expired = now > not_after
    is_not_yet_valid = now < not_before
    days_until_expiry = (not_after - now).days

    # Public key algorithm and size/curve
    pub_key = cert.public_key()
    key_algo = pub_key.__class__.__name__
    key_size: int | None = None
    curve_name: str | None = None

    if isinstance(pub_key, rsa.RSAPublicKey):
        key_algo = "RSA"
        key_size = pub_key.key_size
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        key_algo = "ECDSA"
        key_size = pub_key.key_size
        curve_name = pub_key.curve.name
    elif isinstance(pub_key, ed25519.Ed25519PublicKey):
        key_algo = "Ed25519"
        key_size = 256
    elif isinstance(pub_key, ed448.Ed448PublicKey):
        key_algo = "Ed448"
        key_size = 448
    elif isinstance(pub_key, dsa.DSAPublicKey):
        key_algo = "DSA"
        key_size = pub_key.key_size

    # Signature algorithm
    signature_algorithm = cert.signature_algorithm_oid._name

    # Fingerprint
    sha256_fingerprint = cert.fingerprint(hashes.SHA256()).hex().upper()
    formatted_fingerprint = ":".join(
        sha256_fingerprint[i : i + 2] for i in range(0, len(sha256_fingerprint), 2)
    )

    return {
        "subject": {
            "common_name": subject_cn,
            "organization": subject_org,
            "rfc4514": cert.subject.rfc4514_string(),
        },
        "issuer": {
            "common_name": issuer_cn,
            "organization": issuer_org,
            "rfc4514": cert.issuer.rfc4514_string(),
        },
        "serial_number": serial_number_hex,
        "subject_alternative_names": sans,
        "validity_start": not_before.isoformat(),
        "validity_expiry": not_after.isoformat(),
        "is_expired": is_expired,
        "is_not_yet_valid": is_not_yet_valid,
        "days_until_expiry": days_until_expiry,
        "public_key": {
            "algorithm": key_algo,
            "key_size": key_size,
            "curve": curve_name,
        },
        "signature_algorithm": signature_algorithm,
        "sha256_fingerprint": formatted_fingerprint,
    }
