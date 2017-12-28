from pathlib import Path

import sys
import yaml
import os

from trust_stores_observatory.certificates_repository import RootCertificatesRepository
from trust_stores_observatory.store_fetcher import TrustStoreFetcher
from trust_stores_observatory.trust_store import PlatformEnum, TrustStore

# Also pass the local certs repo so it gets updated when fetching the trust stores
certs_repo = RootCertificatesRepository.get_default()

# For each supported platform, fetch the trust store
has_any_store_changed = False
store_fetcher = TrustStoreFetcher()
for platform in PlatformEnum:
    print(f'Refreshing {platform.name}...')
    fetched_store = store_fetcher.fetch(platform, certs_repo)
    root_path = os.path.abspath(os.path.dirname(__file__))

    # Compare the existing trust store with the one we fetched
    has_store_changed = False
    store_path = Path(root_path) / 'trust_stores' / f'{fetched_store.platform.name.lower()}.yaml'
    try:
        existing_store = TrustStore.from_yaml(store_path)
        if existing_store != fetched_store:
            has_store_changed = True
    except FileNotFoundError:
        # The store does not exist in the repo yet
        has_store_changed = True

    if has_store_changed:
        has_any_store_changed = True
        print(f'Detected changes for {platform.name}; updating store...')
        with open(store_path, mode='w') as store_file:
            yaml.dump(fetched_store, store_file, encoding='utf-8', default_flow_style=False)
    else:
        print(f'No changes detected for {platform.name}')

if has_any_store_changed:
    # Set an environment variable for Travis builds to trigger the deploy step
    sys.exit(1)