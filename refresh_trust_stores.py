from pathlib import Path

import yaml
import os

from trust_stores_observatory.store_fetcher import TrustStoreFetcher
from trust_stores_observatory.trust_store import PlatformEnum

# For each support platform, fetch the trust store and write it to a YAML file
store_fetcher = TrustStoreFetcher()
for plaform in [PlatformEnum.APPLE_IOS, PlatformEnum.APPLE_MACOS]:
    store = store_fetcher.fetch(plaform)
    root_path = os.path.abspath(os.path.dirname(__file__))
    store_path = Path(root_path) / 'trust_stores' / f'{store.platform.name.lower()}.yaml'
    with open(store_path, mode='w') as store_file:
        yaml.dump(store, store_file, encoding=('utf-8'), default_flow_style=False)
