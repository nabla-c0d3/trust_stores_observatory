import unittest
from pathlib import Path

import os

from bs4 import BeautifulSoup
from openpyxl import load_workbook

from trust_stores_observatory.certificates_repository import RootCertificatesRepository
from trust_stores_observatory.store_fetcher import MacosTrustStoreFetcher, MicrosoftTrustStoreFetcher, \
    AospTrustStoreFetcher, JavaTrustStoreFetcher, UbuntuTrustStoreFetcher, MozillaTrustStoreFetcher


class MozillaTrustStoreFetcherTests(unittest.TestCase):

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
        trusted_entries = MacosTrustStoreFetcher._parse_root_records_in_div(parsed_html, 'trusted')
        blocked_entries = MacosTrustStoreFetcher._parse_root_records_in_div(parsed_html, 'blocked')

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
        # Given a Microsoft root CA spreadsheet
        spreadsheet_path = Path(os.path.abspath(os.path.dirname(__file__))) / 'bin' / 'microsoft.xlsx'
        workbook = load_workbook(spreadsheet_path)

        # When parsing it
        version, trusted_records, blocked_records = MicrosoftTrustStoreFetcher._parse_spreadsheet(workbook)

        # The right data is returned
        self.assertEqual(version, 'March 29, 2018')
        self.assertEqual(len(trusted_records), 294)
        self.assertEqual(len(blocked_records), 85)

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


class JavaTrustStoreFetcherTests(unittest.TestCase):

    def test_online(self):
        certs_repo = RootCertificatesRepository.get_default()
        store_fetcher = JavaTrustStoreFetcher()
        fetched_store = store_fetcher.fetch(certs_repo)
        self.assertTrue(fetched_store)
        self.assertGreater(len(fetched_store.trusted_certificates), 100)
        self.assertGreater(len(fetched_store.blocked_certificates), 10)


class UbuntuTrustStoreFetcherTests(unittest.TestCase):

    def test_online(self):
        certs_repo = RootCertificatesRepository.get_default()
        store_fetcher = UbuntuTrustStoreFetcher()
        fetched_store = store_fetcher.fetch(certs_repo)
        self.assertTrue(fetched_store)
        self.assertGreater(len(fetched_store.trusted_certificates), 102)
        self.assertGreater(len(fetched_store.blocked_certificates), 5)
