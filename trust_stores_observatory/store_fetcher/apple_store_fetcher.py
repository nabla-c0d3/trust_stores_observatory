import logging
from typing import Tuple, List
from urllib.request import urlopen
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from datetime import UTC, datetime

from cryptography.hazmat.primitives import hashes

from trust_stores_observatory.certificates_repository import RootCertificatesRepository
from trust_stores_observatory.store_fetcher.root_records_validator import RootRecordsValidator
from trust_stores_observatory.store_fetcher.scraped_root_record import ScrapedRootCertificateRecord
from trust_stores_observatory.store_fetcher.store_fetcher_interface import StoreFetcherInterface
from trust_stores_observatory.trust_store import TrustStore, PlatformEnum


_logger = logging.getLogger(__file__)


class AppleTrustStoreFetcher(StoreFetcherInterface):

    _INDEX_PAGE_URL = "https://support.apple.com/en-us/103272"

    def fetch(self, certs_repo: RootCertificatesRepository, should_update_repo: bool = True) -> TrustStore:
        # First find the latest page with the list of root certificates
        os_version, trust_store_url = self._find_latest_root_certificates_page()

        # Then fetch and parse the page
        _logger.info(f"Found latest Apple trust store page: {trust_store_url}")
        with urlopen(trust_store_url) as response:
            page_content = response.read()
        parsed_page = BeautifulSoup(page_content, "html.parser")

        parsed_trusted_certs: List[ScrapedRootCertificateRecord] = []
        for h2_section in parsed_page.find_all("h2"):
            if "Included Root CA Certificates" in h2_section:
                parsed_trusted_certs = self._parse_root_records_in_div(h2_section.parent)

        # Ensure we did find entries on the page
        assert parsed_trusted_certs

        # Look for each certificate in the supplied certs repo
        validated_trusted_certs = RootRecordsValidator.validate_with_repository(certs_repo, parsed_trusted_certs)

        return TrustStore(
            PlatformEnum.APPLE, os_version, trust_store_url, datetime.now(UTC).date(), validated_trusted_certs
        )

    @staticmethod
    def _parse_root_records_in_div(certs_section: BeautifulSoup) -> List[ScrapedRootCertificateRecord]:
        # Look for each certificate entry in the table
        root_records = []
        for tr_tag in certs_section.find_all("tr"):
            if tr_tag.find("th"):
                # Skip table headers
                continue

            td_tags = tr_tag.find_all("td")
            subject_name = td_tags[0].text
            fingerprint_hex = td_tags[8].text.replace(" ", "").strip()
            fingerprint = bytes(bytearray.fromhex(fingerprint_hex))
            root_records.append(ScrapedRootCertificateRecord(subject_name, fingerprint, hashes.SHA256()))

        return root_records

    @classmethod
    def _find_latest_root_certificates_page(cls) -> Tuple[str, str]:
        # Fetch and parse the page
        with urlopen(cls._INDEX_PAGE_URL) as response:
            page_content = response.read()
        parsed_page = BeautifulSoup(page_content, "html.parser")

        # The page contains links to the root certificates page for each version of iOS/macOS - find the latest one
        section_current = parsed_page.find("h2", text="Current Root Store").parent
        for p_tag in section_current.find_all("p"):
            if "List of available root certificates in" in p_tag.text:
                os_and_version = p_tag.text.split("List of available root certificates in")[1].strip()
                trust_store_path = p_tag.a["href"]
                trust_store_url = urljoin(cls._INDEX_PAGE_URL, trust_store_path)
                return os_and_version, trust_store_url

        raise ValueError(f"Could not find the store URL at {cls._INDEX_PAGE_URL}")
