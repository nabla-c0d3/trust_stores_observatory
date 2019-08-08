from binascii import hexlify
from pathlib import Path

import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.x509 import load_pem_x509_certificate

from trust_stores_observatory.certificates_repository import RootCertificatesRepository


class TestRootCertificatesRepository:
    def test_default_repository_integrity(self):
        # Given the local repo of certificates
        repo = RootCertificatesRepository.get_default()

        # Each certificate that it returns is stored at the expected location
        expected_repo_path = Path(os.path.abspath(os.path.dirname(__file__))) / ".." / "certificates"
        all_certificates = repo.get_all_certificates()
        assert all_certificates

        for certificate in all_certificates:
            expected_file_name = hexlify(certificate.fingerprint(SHA256())).decode("ascii")
            expected_cert_path = expected_repo_path / f"{expected_file_name}.pem"
            with open(expected_cert_path) as stored_cert_file:
                stored_cert_pem = stored_cert_file.read()
                stored_cert = load_pem_x509_certificate(stored_cert_pem.encode(encoding="ascii"), default_backend())
                assert stored_cert == certificate
