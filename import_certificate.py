from pathlib import Path

from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate

from trust_stores_observatory.certificates_repository import RootCertificatesRepository


cert_file = 'cert.pem'
with open(cert_file, mode='r') as pem_file:
    cert_pem = pem_file.read()

# Parse the certificate to double check the fingerprint
parsed_cert = load_pem_x509_certificate(cert_pem.encode(encoding='ascii'), default_backend())
repo = RootCertificatesRepository(Path('certificates'))
repo.store_certificate(parsed_cert)
