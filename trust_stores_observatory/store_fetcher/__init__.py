from trust_stores_observatory.certificates_repository import RootCertificatesRepository
from trust_stores_observatory.store_fetcher.apple_store_fetcher import MacosTrustStoreFetcher, IosTrustStoreFetcher
from trust_stores_observatory.store_fetcher.google_aosp_fetcher import AospTrustStoreFetcher
from trust_stores_observatory.trust_store import PlatformEnum, TrustStore


class TrustStoreFetcher:
    """The main class for fetching a given platform's list of root certificates.
    """

    _FETCHER_CLS = {
        PlatformEnum.APPLE_MACOS: MacosTrustStoreFetcher,
        PlatformEnum.APPLE_IOS: IosTrustStoreFetcher,
        PlatformEnum.GOOGLE_AOSP: AospTrustStoreFetcher,
    }

    def fetch(self,
              platform: PlatformEnum,
              certs_repo: RootCertificatesRepository,
              should_update_repo: bool=True,
              ) -> TrustStore:
        return self._FETCHER_CLS[platform]().fetch(certs_repo, should_update_repo)
