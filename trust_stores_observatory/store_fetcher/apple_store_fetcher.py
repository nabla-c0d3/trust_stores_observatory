from abc import ABC
from typing import Tuple, List
from urllib.request import urlopen
from bs4 import BeautifulSoup
from datetime import datetime

from cryptography.hazmat.primitives import hashes

from trust_stores_observatory.certificates_repository import RootCertificatesRepository
from trust_stores_observatory.store_fetcher.root_records_validator import RootRecordsValidator
from trust_stores_observatory.trust_store import TrustStore, PlatformEnum


class _AppleTrustStoreFetcher(ABC):

    # To be defined in subclasses
    _PLATFORM = None
    _INDEX_PAGE_URL = None

    def fetch(self,
              certs_repo: RootCertificatesRepository,
              should_update_repo: bool=True
              ) -> TrustStore:
        # First find the latest page with the list of root certificates
        os_version, trust_store_url = self._find_latest_root_certificates_page()

        # Then fetch and parse the page
        with urlopen(trust_store_url) as response:
            page_content = response.read()
        parsed_page = BeautifulSoup(page_content, 'html.parser')

        # There are two divs on the page, one with trusted certificates and one with blocked certificates
        root_certificates = {'trusted': set(), 'blocked': set()}
        # We parse both divs
        for div_id in ['trusted', 'blocked']:
            parsed_root_records = self._parse_certificate_records_in_div(parsed_page, div_id=div_id)

            # Look for each certificate in the supplied certs repo
            root_certificates[div_id] = RootRecordsValidator.validate_with_repository(certs_repo, hashes.SHA256,
                                                                                      parsed_root_records)

        return TrustStore(self._PLATFORM, os_version, trust_store_url, datetime.utcnow().date(),
                          root_certificates['trusted'], root_certificates['blocked'])

    @staticmethod
    def _parse_certificate_records_in_div(parsed_page: BeautifulSoup, div_id: str) -> List[Tuple[str, bytes]]:
        div_to_parse = parsed_page.find('div', id=div_id)
        # Look for each certificate entry in the table
        root_records = []
        for tr_tag in div_to_parse.find_all('tr'):
            if tr_tag.find('th'):
                # Skip table headers
                continue

            td_tags = tr_tag.find_all('td')
            subject_name = td_tags[0].text
            fingerprint_hex = td_tags[8].text.replace(' ', '').strip()
            fingerprint = bytearray.fromhex(fingerprint_hex)
            root_records.append((subject_name, fingerprint))
        return root_records

    @classmethod
    def _find_latest_root_certificates_page(cls) -> Tuple[str, str]:
        # Fetch and parse the page
        with urlopen(cls._INDEX_PAGE_URL) as response:
            page_content = response.read()
        parsed_page = BeautifulSoup(page_content, 'html.parser')

        # The page contains links to the root certificates page for each version of iOS/macOS - find the latest one
        for li_tag in parsed_page.find_all('li'):
            if 'List of available trusted root certificates in' in li_tag.text:
                os_and_version = li_tag.text.split('List of available trusted root certificates in')[1].strip()

                # Split iOS/macOS to only keep the version number
                version = os_and_version.split('OS', 1)[1].strip()
                trust_store_url = li_tag.a['href']
                return version, trust_store_url

        raise ValueError(f'Could not find the store URL at {cls._INDEX_PAGE_URL}')


class MacosTrustStoreFetcher(_AppleTrustStoreFetcher):

    _PLATFORM = PlatformEnum.APPLE_MACOS
    _INDEX_PAGE_URL = 'https://support.apple.com/en-us/HT202858'


class IosTrustStoreFetcher(_AppleTrustStoreFetcher):

    _PLATFORM = PlatformEnum.APPLE_IOS
    _INDEX_PAGE_URL = 'https://support.apple.com/en-us/HT204132'
