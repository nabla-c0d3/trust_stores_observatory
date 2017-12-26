from trust_stores_observatory.store_fetcher.apple_store_fetcher import MacosTrustStoreFetcher, IosTrustStoreFetcher
from trust_stores_observatory.trust_store import PlatformEnum


class TrustStoreFetcher:

    _FETCHER_CLS = {
        PlatformEnum.APPLE_MACOS: MacosTrustStoreFetcher,
        PlatformEnum.APPLE_IOS: IosTrustStoreFetcher,
    }

    def fetch(self, platform: PlatformEnum) -> object:
        return  self._FETCHER_CLS[platform]().fetch()

