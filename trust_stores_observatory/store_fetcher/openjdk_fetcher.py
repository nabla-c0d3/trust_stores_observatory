from datetime import datetime
from typing import List
from urllib.request import Request, urlopen

import jks
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import load_der_x509_certificate

from trust_stores_observatory.certificate_utils import CertificateUtils
from trust_stores_observatory.certificates_repository import RootCertificatesRepository
from trust_stores_observatory.store_fetcher.root_records_validator import RootRecordsValidator
from trust_stores_observatory.store_fetcher.scraped_root_record import ScrapedRootCertificateRecord
from trust_stores_observatory.store_fetcher.store_fetcher_interface import StoreFetcherInterface
from trust_stores_observatory.trust_store import PlatformEnum, TrustStore


class OpenJDKTrustStoreFetcher(StoreFetcherInterface):

    # latest keystore from mercurial repository:
    _URL = "http://hg.openjdk.java.net/jdk/jdk/raw-file/tip/src/java.base/share/lib/security/cacerts"
    _CACERTS_PASSWORD = 'changeit'  # default password for OpenJDK key store
    _VERSION = None  # no real version info

    def fetch(
            self,
            cert_repo: RootCertificatesRepository,
            should_update_repo: bool=True
    ) -> TrustStore:
        request = Request(
            self._URL,
        )
        response = urlopen(request)

        # Parse the JKS
        cacerts_key_store = jks.KeyStore.loads(response.read(), self._CACERTS_PASSWORD)

        # Process the cacert
        scraped_trusted_records = self._extract_trusted_root_records(cacerts_key_store, should_update_repo, cert_repo)
        trusted_records = RootRecordsValidator.validate_with_repository(cert_repo, scraped_trusted_records)

        return TrustStore(
            PlatformEnum.OPENJDK,
            self._VERSION,
            self._URL,
            datetime.utcnow().date(),
            trusted_records
        )

    @staticmethod
    def _extract_trusted_root_records(
            key_store: jks.KeyStore,
            should_update_repo: bool,
            cert_repo: RootCertificatesRepository
    ) -> List[ScrapedRootCertificateRecord]:
        root_records = []
        for alias, item in key_store.certs.items():
            parsed_cert = load_der_x509_certificate(item.cert, default_backend())
            if should_update_repo:
                cert_repo.store_certificate(parsed_cert)

            root_records.append(ScrapedRootCertificateRecord(
                CertificateUtils.get_canonical_subject_name(parsed_cert),
                parsed_cert.fingerprint(hashes.SHA256()),
                hashes.SHA256())
            )

        return root_records
