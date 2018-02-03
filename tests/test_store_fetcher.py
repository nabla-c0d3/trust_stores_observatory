import unittest
from pathlib import Path

import os

from bs4 import BeautifulSoup

from trust_stores_observatory.certificates_repository import RootCertificatesRepository
from trust_stores_observatory.store_fetcher import MacosTrustStoreFetcher, MicrosoftTrustStoreFetcher, \
    AospTrustStoreFetcher
from trust_stores_observatory.store_fetcher.mozilla_fetcher import MozillaTrustStoreFetcher, \
    _CerdataEntryServerAuthTrustEnum, _CertdataCertificateEntry, _CertdataTrustEntry


class MozillaTrustStoreFetcherTests(unittest.TestCase):

    def test_scraping(self):
        # Given a Mozilla certdata file
        certdata_path = Path(os.path.abspath(os.path.dirname(__file__))) / 'bin' / 'mozilla_certdata.txt'
        with open(certdata_path) as certdata_file:
            certdata_content = certdata_file.read()

        # When scraping it
        certdata_entries = MozillaTrustStoreFetcher._scrape_certdata(certdata_content)

        # It returns the correct entries
        self.assertEqual(len(certdata_entries), 319)

        certificate_entries = [entry for entry in certdata_entries if isinstance(entry, _CertdataCertificateEntry)]
        self.assertEqual(len(certificate_entries), 157)

        trust_entries = [entry for entry in certdata_entries if isinstance(entry, _CertdataTrustEntry)]
        self.assertEqual(len(trust_entries), 162)

        trusted_trust_entries = [entry for entry in trust_entries
                                 if entry.trust_enum == _CerdataEntryServerAuthTrustEnum.TRUSTED]
        self.assertEqual(len(trusted_trust_entries), 138)

        not_trusted_trust_entries = [entry for entry in trust_entries
                                     if entry.trust_enum == _CerdataEntryServerAuthTrustEnum.NOT_TRUSTED]
        self.assertEqual(len(not_trusted_trust_entries), 7)

        must_verify_trust_entries = [entry for entry in trust_entries
                                     if entry.trust_enum == _CerdataEntryServerAuthTrustEnum.MUST_VERIFY]
        self.assertEqual(len(must_verify_trust_entries), 17)

    def test_online(self):
        certs_repo = RootCertificatesRepository.get_default()
        store_fetcher = MozillaTrustStoreFetcher()
        fetched_store = store_fetcher.fetch(certs_repo)
        self.assertTrue(fetched_store)
        self.assertGreater(len(fetched_store.trusted_certificates), 100)
        self.assertGreater(len(fetched_store.blocked_certificates), 6)


class MacOsTrustStoreFetcherTests(unittest.TestCase):

    def test_scraping(self):
        # Given a macOS trust store page
        html_path = Path(os.path.abspath(os.path.dirname(__file__))) / 'bin' / 'macOS.html'
        with open(html_path) as html_file:
            parsed_html = BeautifulSoup(html_file.read(), 'html.parser')

        # When scraping it
        trusted_entries = MacosTrustStoreFetcher._parse_certificate_records_in_div(parsed_html, 'trusted')
        blocked_entries = MacosTrustStoreFetcher._parse_certificate_records_in_div(parsed_html, 'blocked')

        # It returns the correct entries
        self.assertEqual(len(trusted_entries), 173)
        self.assertEqual(len(blocked_entries), 38)

    def test_online(self):
        certs_repo = RootCertificatesRepository.get_default()
        store_fetcher = MacosTrustStoreFetcher()
        fetched_store = store_fetcher.fetch(certs_repo)
        self.assertTrue(fetched_store)
        self.assertGreater(len(fetched_store.trusted_certificates), 100)
        self.assertGreater(len(fetched_store.blocked_certificates), 6)


class MicrosoftStoreFetcherTests(unittest.TestCase):

    def test_scraping(self):
        # TODO(AD)
        pass

    def test_online(self):
        certs_repo = RootCertificatesRepository.get_default()
        store_fetcher = MicrosoftTrustStoreFetcher()
        fetched_store = store_fetcher.fetch(certs_repo)
        self.assertTrue(fetched_store)
        self.assertGreater(len(fetched_store.trusted_certificates), 100)
        self.assertGreater(len(fetched_store.blocked_certificates), 6)


class AospTrustStoreFetcherTests(unittest.TestCase):

    def test_scraping(self):
        # TODO(AD)
        pass

    def test_online(self):
        certs_repo = RootCertificatesRepository.get_default()
        store_fetcher = AospTrustStoreFetcher()
        fetched_store = store_fetcher.fetch(certs_repo)
        self.assertTrue(fetched_store)
        self.assertGreater(len(fetched_store.trusted_certificates), 100)
        self.assertEqual(len(fetched_store.blocked_certificates), 0)
