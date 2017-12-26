from binascii import hexlify
from pathlib import Path

import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import Certificate, load_pem_x509_certificate


class RootCertificatesRepository:
    """A local folder where we store as many root certificates (as PEM files) as possible.
    """

    def __init__(self, local_root_path: Path) -> None:
        self._path = local_root_path

    @classmethod
    def get_default(cls):
        root_path = Path(os.path.abspath(os.path.dirname(__file__))) / '..' / 'certificates'
        return cls(root_path)

    def lookup_certificate_from_record(self, certificate_record: 'RootCertificateRecord') -> Certificate:
        pem_path = self._path / f'{certificate_record.hex_fingerprint}.pem'
        try:
            with open(pem_path, mode='r') as pem_file:
                cert_pem = pem_file.read()
        except FileNotFoundError:
            raise FileNotFoundError(f'Could not find certificate "{certificate_record.subject_name}" '
                                    f'- {certificate_record.hex_fingerprint}')

        # Parse the certificate to double check the fingerprint
        parsed_cert = load_pem_x509_certificate(cert_pem.encode(encoding='ascii'), default_backend())
        parsed_cert_fingerprint = hexlify(parsed_cert.fingerprint(SHA256())).decode('ascii')
        if certificate_record.hex_fingerprint != parsed_cert_fingerprint.lower():
            raise ValueError(f'Fingerprint mismatch for certificate "{certificate_record.subject_name}":'
                             f'{certificate_record.hex_fingerprint} VS {parsed_cert_fingerprint}')

        return parsed_cert

    def store_certificate(self, certificate: Certificate) -> Path:
        """Store the supplied certificate as a PEM file.
        """
        # A given certificate's path is always <SHA-256>.pem.
        cert_file_name = hexlify(certificate.fingerprint(SHA256())).decode('ascii')
        cert_path = self._path / f'{cert_file_name}.pem'

        # If the cert is NOT already there, add it
        if not cert_path.exists():
            with open(cert_path, 'w') as cert_file:
                cert_file.write(certificate.public_bytes(Encoding.PEM).decode('ascii'))

        return cert_path
