from datetime import datetime
from typing import Tuple, List
from urllib.request import urlopen

from cryptography.hazmat.primitives import hashes

from trust_stores_observatory.certificates_repository import RootCertificatesRepository
from trust_stores_observatory.store_fetcher.root_records_validator import RootRecordsValidator
from trust_stores_observatory.store_fetcher.scraped_root_record import ScrapedRootCertificateRecord
from trust_stores_observatory.store_fetcher.store_fetcher_interface import StoreFetcherInterface
from trust_stores_observatory.trust_store import TrustStore, PlatformEnum


class MicrosoftTrustStoreFetcher(StoreFetcherInterface):
    """Fetch the content of the MSFT / Windows trust store.

    This fetcher uses the newly-available CCADB described at
    https://docs.microsoft.com/en-us/security/trusted-root/participants-list.
    """

    _CSV_URL = "https://ccadb-public.secure.force.com/microsoft/IncludedCACertificateReportForMSFTCSV"
    _PAGE_URL = "https://ccadb-public.secure.force.com/microsoft/IncludedCACertificateReportForMSFT"

    def fetch(self, certs_repo: RootCertificatesRepository, should_update_repo: bool = True) -> TrustStore:
        with urlopen(self._CSV_URL) as response:
            csv_content = response.read().decode("utf-8")

        # Extract the data from the CSV
        scraped_trusted_root_records, scraped_blocked_root_records = self._parse_spreadsheet(csv_content)

        # Look for each parsed certificate in the supplied certs repo
        trusted_root_records = RootRecordsValidator.validate_with_repository(certs_repo, scraped_trusted_root_records)
        blocked_root_records = RootRecordsValidator.validate_with_repository(certs_repo, scraped_blocked_root_records)

        date_fetched = datetime.utcnow().date()
        return TrustStore(
            PlatformEnum.MICROSOFT_WINDOWS,
            None,
            self._PAGE_URL,
            date_fetched,
            trusted_root_records,
            blocked_root_records,
        )

    @staticmethod
    def _parse_spreadsheet(
        csv_content: str
    ) -> Tuple[List[ScrapedRootCertificateRecord], List[ScrapedRootCertificateRecord]]:
        # Iterate over each row in the work sheet
        parsed_trusted_root_records = []
        parsed_blocked_root_records = []

        for csv_row in csv_content.splitlines()[1::]:
            split_row = csv_row.split('","')
            subject_name = split_row[1].strip()
            if subject_name is None:
                # Most likely indicates the end of the data
                continue

            is_cert_trusted = False
            status = split_row[9].strip()
            if "Included" in status:
                # Some certs are disabled or have a notBefore constraint
                is_cert_trusted = True

            sha256_fingerprint = split_row[3].strip()
            fingerprint = bytes(bytearray.fromhex(sha256_fingerprint))

            record = ScrapedRootCertificateRecord(subject_name, fingerprint, hashes.SHA256())
            if is_cert_trusted:
                parsed_trusted_root_records.append(record)
            else:
                parsed_blocked_root_records.append(record)

        return parsed_trusted_root_records, parsed_blocked_root_records
