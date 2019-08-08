from typing import Dict, Type

from trust_stores_observatory.certificates_repository import RootCertificatesRepository
from trust_stores_observatory.store_fetcher.apple_store_fetcher import AppleTrustStoreFetcher
from trust_stores_observatory.store_fetcher.google_aosp_fetcher import AospTrustStoreFetcher
from trust_stores_observatory.store_fetcher.microsoft_fetcher import MicrosoftTrustStoreFetcher
from trust_stores_observatory.store_fetcher.mozilla_fetcher import MozillaTrustStoreFetcher
from trust_stores_observatory.store_fetcher.java_fetcher import JavaTrustStoreFetcher
from trust_stores_observatory.store_fetcher.openjdk_fetcher import OpenJDKTrustStoreFetcher
from trust_stores_observatory.store_fetcher.store_fetcher_interface import StoreFetcherInterface
from trust_stores_observatory.trust_store import PlatformEnum, TrustStore


class TrustStoreFetcher:
    """The main class for fetching a given platform's list of root certificates.
    """

    _FETCHER_CLS: Dict[PlatformEnum, Type[StoreFetcherInterface]] = {
        PlatformEnum.APPLE: AppleTrustStoreFetcher,
        PlatformEnum.GOOGLE_AOSP: AospTrustStoreFetcher,
        PlatformEnum.MICROSOFT_WINDOWS: MicrosoftTrustStoreFetcher,
        PlatformEnum.MOZILLA_NSS: MozillaTrustStoreFetcher,
        PlatformEnum.ORACLE_JAVA: JavaTrustStoreFetcher,
        PlatformEnum.OPENJDK: OpenJDKTrustStoreFetcher,
    }

    def fetch(
        self, platform: PlatformEnum, certs_repo: RootCertificatesRepository, should_update_repo: bool = True
    ) -> TrustStore:
        return self._FETCHER_CLS[platform]().fetch(certs_repo, should_update_repo)
