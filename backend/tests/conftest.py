"""Pytest fixtures and test environment configuration."""

import datetime
from collections.abc import Generator

import pytest
from backend.app.database.connection import get_db
from backend.app.main import app
from backend.app.models.scan import Base
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

# Isolated in-memory test database
TEST_DATABASE_URL = "sqlite:///:memory:"

test_engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    """Create schema in in-memory test database."""
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture
def db_session() -> Generator[Session, None, None]:
    """Provide a transactional database session for a test."""
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture
def client(db_session: Session) -> Generator[TestClient, None, None]:
    """Test client configured with in-memory database dependency override."""

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def dummy_x509_cert_builder():
    """Generate mock DER-encoded X.509 certificates with customizable attributes."""

    def _create_cert(
        common_name: str = "example.com",
        sans: list[str] = None,
        days_valid: int = 90,
        expired: bool = False,
        not_yet_valid: bool = False,
        rsa_key_size: int = 2048,
    ) -> bytes:
        if sans is None:
            sans = [common_name]

        # Generate RSA private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=rsa_key_size,
        )

        now = datetime.datetime.now(datetime.UTC)
        if expired:
            not_before = now - datetime.timedelta(days=120)
            not_after = now - datetime.timedelta(days=30)
        elif not_yet_valid:
            not_before = now + datetime.timedelta(days=10)
            not_after = now + datetime.timedelta(days=100)
        else:
            not_before = now - datetime.timedelta(days=10)
            not_after = now + datetime.timedelta(days=days_valid)

        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Security CA"),
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ]
        )

        san_objects = [x509.DNSName(name) for name in sans]

        cert_builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(
                x509.SubjectAlternativeName(san_objects),
                critical=False,
            )
        )

        cert = cert_builder.sign(private_key, hashes.SHA256())
        return cert.public_bytes(serialization.Encoding.DER)

    return _create_cert
