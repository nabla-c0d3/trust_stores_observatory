from abc import ABC
from typing import Optional
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

    def fetch(self, cert_repo_to_update: Optional[RootCertificatesRepository] = None) -> TrustStore:
        # Fetch and parse the page
        with urlopen(self._STORE_PAGE_URL) as response:
            page_content = response.read()
        parsed_page = BeautifulSoup(page_content, 'html.parser')

        # There are other divs with blocked or "always ask" certificates - be careful
        div_trusted = parsed_page.find('div', id='trusted')

        # Look for each certificate entry in the table
        entries = []
        for tr_tag in div_trusted.find_all('tr'):
            if tr_tag.find('th'):
                # Skip table headers
                continue

            td_tags = tr_tag.find_all('td')
            subject_name = td_tags[0].text
            fingerprint_hex = td_tags[8].text.replace(' ', '').strip()
            fingerprint = bytearray.fromhex(fingerprint_hex)
            entries.append(RootCertificateRecord(subject_name, fingerprint))

        date_fetched = datetime.utcnow().date()
        return TrustStore(self._STORE_PLATFORM, self._STORE_VERSION, self._STORE_PAGE_URL, date_fetched, entries)


class MacosTrustStoreFetcher(_AppleTrustStoreFetcher):

    _STORE_PLATFORM = PlatformEnum.APPLE_MACOS
    _STORE_PAGE_URL = 'https://support.apple.com/en-us/HT208127'
    _STORE_VERSION = 'High Sierra'


class IosTrustStoreFetcher(_AppleTrustStoreFetcher):

    _STORE_PLATFORM = PlatformEnum.APPLE_IOS
    _STORE_PAGE_URL = 'https://support.apple.com/en-us/HT208125'
    _STORE_VERSION = '11'
