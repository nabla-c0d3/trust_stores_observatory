import os
from pathlib import Path

from trust_stores_observatory.certificates_repository import RootCertificatesRepository
from trust_stores_observatory.trust_store import PlatformEnum, TrustStore

certs_repo = RootCertificatesRepository.get_default()

# Export each trust store as a PEM file
for platform in PlatformEnum:
    print(f'Exporting {platform.name}...')
    root_path = Path(os.path.abspath(os.path.dirname(__file__)))
    store_yaml_path = root_path / 'trust_stores' / f'{platform.name.lower()}.yaml'
    store = TrustStore.from_yaml(store_yaml_path)
    all_certs_pem = store.export_as_pem(certs_repo)

    out_pem_path = root_path / f'{platform.name.lower()}.pem'
    with open(out_pem_path, mode='w') as out_pem_file:
        out_pem_file.write(all_certs_pem)
