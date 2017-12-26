import os
from pathlib import Path

from trust_stores_observatory.trust_store import PlatformEnum, TrustStore

root_path = Path(os.path.abspath(os.path.dirname(__file__)))
pem_repo_path =  root_path / 'certificates'

# Export each trust store as a PEM file
for platform in PlatformEnum:
    store_yaml_path = root_path / 'trust_stores' / f'{platform.name.lower()}.yaml'
    store = TrustStore.from_yaml(store_yaml_path)
    all_certs_pem = store.export_as_pem(pem_repo_path)

    out_pem_path = root_path / f'{platform.name.lower()}.pem'
    with open(out_pem_path, mode='w') as out_pem_file:
        out_pem_file.write(all_certs_pem)
