from pathlib import Path

import os
from typing import Union, List

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import Certificate, load_pem_x509_certificate


class CertificateNotFoundError(KeyError):
    pass


class RootCertificatesRepository:
    """A local folder where we store as many root certificates (as PEM files) as possible.
    """

    def __init__(self, local_root_path: Path) -> None:
        self._path = local_root_path

        all_certificates = []
        for pem_file_path in self._path.glob("*.pem"):
            with open(pem_file_path) as pem_file:
                cert_pem = pem_file.read()
                cert = load_pem_x509_certificate(cert_pem.encode(encoding="ascii"), default_backend())
                all_certificates.append(cert)
        self._all_certificates = all_certificates

        # Parse each certificate so we can look them up with SHA1
        self._sha1_map = {cert.fingerprint(hashes.SHA1()): cert for cert in self._all_certificates}

    @classmethod
    def get_default(cls) -> "RootCertificatesRepository":
        root_path = Path(os.path.abspath(os.path.dirname(__file__))) / ".." / "certificates"
        return cls(root_path)

    def get_all_certificates(self) -> List[Certificate]:
        return self._all_certificates

    def lookup_certificate_with_fingerprint(
        self, fingerprint: bytes, hash_algorithm: Union[hashes.SHA1, hashes.SHA256] = hashes.SHA256()
    ) -> Certificate:
        hex_fingerprint = fingerprint.hex()
        if isinstance(hash_algorithm, hashes.SHA1):
            try:
                return self._sha1_map[fingerprint]
            except KeyError:
                raise CertificateNotFoundError(f"Could not find certificate {hex_fingerprint}")

        elif isinstance(hash_algorithm, hashes.SHA256):
            try:
                return self._lookup_certificate_with_sha256_fingerprint(fingerprint)
            except FileNotFoundError:
                raise CertificateNotFoundError(f"Could not find certificate {hex_fingerprint}")

        else:
            raise ValueError("Hash algorithm not supported")

    def _lookup_certificate_with_sha256_fingerprint(self, fingerprint: bytes) -> Certificate:
        pem_path = self._path / f"{fingerprint.hex()}.pem"
        with open(pem_path, mode="r") as pem_file:
            cert_pem = pem_file.read()

        # Parse the certificate to double check the fingerprint
        parsed_cert = load_pem_x509_certificate(cert_pem.encode(encoding="ascii"), default_backend())
        if fingerprint != parsed_cert.fingerprint(SHA256()):
            cert_fingerprint = parsed_cert.fingerprint(SHA256()).hex()
            hex_fingerprint = fingerprint.hex()
            raise ValueError(f"Fingerprint mismatch for certificate :{hex_fingerprint} VS {cert_fingerprint}")

        return parsed_cert

    def store_certificate(self, certificate: Certificate) -> Path:
        """Store the supplied certificate as a PEM file.
        """
        # A given certificate's path is always <SHA-256>.pem.
        cert_file_name = certificate.fingerprint(SHA256()).hex()
        cert_path = self._path / f"{cert_file_name}.pem"

        # If the cert is NOT already there, add it
        if not cert_path.exists():
            with open(cert_path, "w") as cert_file:
                cert_file.write(certificate.public_bytes(Encoding.PEM).decode("ascii"))

        return cert_path
