from pathlib import Path

import os

import pytest

from trust_stores_observatory.certificates_repository import RootCertificatesRepository
from trust_stores_observatory.store_fetcher import (
    AppleTrustStoreFetcher,
    MicrosoftTrustStoreFetcher,
    AospTrustStoreFetcher,
    JavaTrustStoreFetcher,
    OpenJDKTrustStoreFetcher,
)
from trust_stores_observatory.store_fetcher.mozilla_fetcher import (
    MozillaTrustStoreFetcher,
    _CerdataEntryServerAuthTrustEnum,
    _CertdataCertificateEntry,
    _CertdataTrustEntry,
)


class TestMozillaTrustStoreFetcher:
    def test_scraping(self):
        # Given a Mozilla certdata file
        certdata_path = Path(os.path.abspath(os.path.dirname(__file__))) / "bin" / "mozilla_certdata.txt"
        with open(certdata_path) as certdata_file:
            certdata_content = certdata_file.read()

        # When scraping it
        certdata_entries = MozillaTrustStoreFetcher._scrape_certdata(certdata_content)

        # It returns the correct entries
        assert 319 == len(certdata_entries)

        certificate_entries = [entry for entry in certdata_entries if isinstance(entry, _CertdataCertificateEntry)]
        assert 157 == len(certificate_entries)

        trust_entries = [entry for entry in certdata_entries if isinstance(entry, _CertdataTrustEntry)]
        assert 162 == len(trust_entries)

        trusted_trust_entries = [
            entry for entry in trust_entries if entry.trust_enum == _CerdataEntryServerAuthTrustEnum.TRUSTED
        ]
        assert 138 == len(trusted_trust_entries)

        not_trusted_trust_entries = [
            entry for entry in trust_entries if entry.trust_enum == _CerdataEntryServerAuthTrustEnum.NOT_TRUSTED
        ]
        assert 7 == len(not_trusted_trust_entries)

        must_verify_trust_entries = [
            entry for entry in trust_entries if entry.trust_enum == _CerdataEntryServerAuthTrustEnum.MUST_VERIFY
        ]
        assert 17 == len(must_verify_trust_entries)

    def test_online(self):
        certs_repo = RootCertificatesRepository.get_default()
        store_fetcher = MozillaTrustStoreFetcher()
        fetched_store = store_fetcher.fetch(certs_repo)
        assert fetched_store
        assert 100 < len(fetched_store.trusted_certificates)
        assert 0 == len(fetched_store.blocked_certificates)


class TestAppleTrustStoreFetcher:
    def test_online(self):
        certs_repo = RootCertificatesRepository.get_default()
        store_fetcher = AppleTrustStoreFetcher()
        fetched_store = store_fetcher.fetch(certs_repo)
        assert fetched_store
        assert 100 < len(fetched_store.trusted_certificates)
        assert 0 == len(fetched_store.blocked_certificates)


class TestMicrosoftStoreFetcher:
    def test_online(self):
        certs_repo = RootCertificatesRepository.get_default()
        store_fetcher = MicrosoftTrustStoreFetcher()
        fetched_store = store_fetcher.fetch(certs_repo)
        assert fetched_store
        assert 100 < len(fetched_store.trusted_certificates)
        assert 6 < len(fetched_store.blocked_certificates)


class TestAospTrustStoreFetcher:
    def test_scraping(self):
        # TODO(AD)
        pass

    def test_online(self):
        certs_repo = RootCertificatesRepository.get_default()
        store_fetcher = AospTrustStoreFetcher()
        fetched_store = store_fetcher.fetch(certs_repo)
        assert fetched_store
        assert 100 < len(fetched_store.trusted_certificates)
        assert 0 == len(fetched_store.blocked_certificates)


@pytest.mark.skip("TODO: Fix the Java fetcher")
class TestJavaTrustStoreFetcher:
    def test_online(self):
        certs_repo = RootCertificatesRepository.get_default()
        store_fetcher = JavaTrustStoreFetcher()
        fetched_store = store_fetcher.fetch(certs_repo)
        assert fetched_store
        assert 80 < len(fetched_store.trusted_certificates)
        assert 10 < len(fetched_store.blocked_certificates)


@pytest.mark.skip("TODO: Fix the OpenJDK fetcher")
class TestOpenJdkTrustStoreFetcher:
    def test_online(self):
        certs_repo = RootCertificatesRepository.get_default()
        store_fetcher = OpenJDKTrustStoreFetcher()
        fetched_store = store_fetcher.fetch(certs_repo)
        assert fetched_store
        assert 80 < len(fetched_store.trusted_certificates)
        assert 10 < len(fetched_store.blocked_certificates)
