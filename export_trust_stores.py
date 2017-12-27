import os
from pathlib import Path

from trust_stores_observatory.certificates_repository import RootCertificatesRepository
from trust_stores_observatory.trust_store import PlatformEnum, TrustStore

certs_repo = RootCertificatesRepository.get_default()

root_path = Path(os.path.abspath(os.path.dirname(__file__)))

# Export each trust store as a PEM file
for platform in PlatformEnum:
    print(f'Exporting {platform.name}...')
    store = TrustStore.get_default_for_platform(platform)
    all_certs_pem = store.export_trusted_certificates_as_pem(certs_repo)

    out_pem_path = root_path / f'{platform.name.lower()}.pem'
    with open(out_pem_path, mode='w') as out_pem_file:
        out_pem_file.write(all_certs_pem)
