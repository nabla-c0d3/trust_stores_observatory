from datetime import datetime
from urllib.request import urlopen

from cryptography.hazmat.primitives import hashes

from trust_stores_observatory.certificates_repository import RootCertificatesRepository
from trust_stores_observatory.store_fetcher.root_records_validator import RootRecordsValidator
from trust_stores_observatory.store_fetcher.scraped_root_record import ScrapedRootCertificateRecord
from trust_stores_observatory.store_fetcher.store_fetcher_interface import StoreFetcherInterface
from trust_stores_observatory.trust_store import TrustStore, PlatformEnum
from trust_stores_observatory.nss_helper import CertdataEntryServerAuthTrustEnum, \
    CertdataCertificateEntry, CertdataTrustEntry, parse_certdata


class MozillaTrustStoreFetcher(StoreFetcherInterface):

    _PAGE_URL = 'https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt'

    def fetch(self, certs_repo: RootCertificatesRepository, should_update_repo: bool=True) -> TrustStore:
        # There's no specific version available in the certdata file
        os_version = None

        # Then fetch and parse the page
        with urlopen(self._PAGE_URL) as response:
            page_content = response.read().decode('utf-8')

        entries = parse_certdata(page_content)
        certificate_entries = [entry for entry in entries if isinstance(entry, CertdataCertificateEntry)]
        trust_entries = [entry for entry in entries if isinstance(entry, CertdataTrustEntry)]

        # Store the certificates we found in the local repo if needed
        if should_update_repo:
            for cert_entry in certificate_entries:
                certs_repo.store_certificate(cert_entry.certificate)

        trusted_certificates = RootRecordsValidator.validate_with_repository(
            certs_repo,
            [
                ScrapedRootCertificateRecord(entry.name, entry.sha1_fingerprint, hashes.SHA1())
                for entry in trust_entries if entry.trust_enum == CertdataEntryServerAuthTrustEnum.TRUSTED
            ]
        )

        blocked_certificates = RootRecordsValidator.validate_with_repository(
            certs_repo,
            [
                ScrapedRootCertificateRecord(entry.name, entry.sha1_fingerprint, hashes.SHA1())
                for entry in trust_entries if entry.trust_enum == CertdataEntryServerAuthTrustEnum.NOT_TRUSTED
            ]
        )

        return TrustStore(PlatformEnum.MOZILLA_NSS, os_version, self._PAGE_URL, datetime.utcnow().date(),
                          trusted_certificates, blocked_certificates)
