import logging
from abc import ABC
from typing import Tuple, List
from urllib.request import urlopen
from bs4 import BeautifulSoup
from datetime import datetime

from trust_stores_observatory.certificates_repository import RootCertificatesRepository
from trust_stores_observatory.trust_store import TrustStore, PlatformEnum, RootCertificateRecord


class _AppleTrustStoreFetcher(ABC):

    # To be defined in subclasses
    _STORE_PLATFORM = None
    _STORE_PAGE_URL = None
    _STORE_VERSION = None

    def fetch(self,
              certs_repo: RootCertificatesRepository,
              should_update_repo: bool=True
              ) -> TrustStore:
        # Fetch and parse the page
        with urlopen(self._STORE_PAGE_URL) as response:
            page_content = response.read()
        parsed_page = BeautifulSoup(page_content, 'html.parser')
        parsed_root_records = self._parse_trusted_certificate_records(parsed_page)

        # Look for each certificate in the supplied certs repo
        validated_root_records = []
        for scraped_subj_name, fingerprint in parsed_root_records:
            try:
                cert = certs_repo.lookup_certificate_with_fingerprint(fingerprint)
                validated_root_records.append(RootCertificateRecord.from_certificate(cert))
            except FileNotFoundError:
                # We have never seen this certificate - use whatever name is on the Apple page for now
                logging.error(f'Could not find certificate "{scraped_subj_name}"')
                validated_root_records.append(RootCertificateRecord.from_scraped_record(scraped_subj_name, fingerprint))

        date = datetime.utcnow().date()
        return TrustStore(self._STORE_PLATFORM, self._STORE_VERSION, self._STORE_PAGE_URL, date, validated_root_records)

    @staticmethod
    def _parse_trusted_certificate_records(parsed_page: BeautifulSoup) -> List[Tuple[str, bytes]]:
        # There are other divs with blocked or "always ask" certificates - be careful
        div_trusted = parsed_page.find('div', id='trusted')

        # Look for each certificate entry in the table
        root_records = []
        for tr_tag in div_trusted.find_all('tr'):
            if tr_tag.find('th'):
                # Skip table headers
                continue

            td_tags = tr_tag.find_all('td')
            subject_name = td_tags[0].text
            fingerprint_hex = td_tags[8].text.replace(' ', '').strip()
            fingerprint = bytearray.fromhex(fingerprint_hex)
            root_records.append((subject_name, fingerprint))
        return root_records


# TODO(AD): Automatically retrieve the link to the support page for the latest version of macOS/iOS
class MacosTrustStoreFetcher(_AppleTrustStoreFetcher):

    _STORE_PLATFORM = PlatformEnum.APPLE_MACOS
    _STORE_PAGE_URL = 'https://support.apple.com/en-us/HT208127'
    _STORE_VERSION = 'High Sierra'


class IosTrustStoreFetcher(_AppleTrustStoreFetcher):

    _STORE_PLATFORM = PlatformEnum.APPLE_IOS
    _STORE_PAGE_URL = 'https://support.apple.com/en-us/HT208125'
    _STORE_VERSION = '11'
