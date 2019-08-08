from abc import ABC, abstractmethod

from trust_stores_observatory.certificates_repository import RootCertificatesRepository
from trust_stores_observatory.trust_store import TrustStore


class StoreFetcherInterface(ABC):
    @abstractmethod
    def fetch(self, certs_repo: RootCertificatesRepository, should_update_repo: bool = True) -> TrustStore:
        pass
