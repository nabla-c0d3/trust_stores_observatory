import os
import tarfile

from datetime import datetime
from typing import Any, Optional, Type
from urllib.request import urlopen
from bs4 import BeautifulSoup
from tempfile import NamedTemporaryFile

from cryptography.hazmat.primitives import hashes

from trust_stores_observatory.certificates_repository import RootCertificatesRepository
from trust_stores_observatory.store_fetcher.root_records_validator import RootRecordsValidator
from trust_stores_observatory.store_fetcher.scraped_root_record import ScrapedRootCertificateRecord
from trust_stores_observatory.store_fetcher.store_fetcher_interface import StoreFetcherInterface
from trust_stores_observatory.trust_store import PlatformEnum, TrustStore
from trust_stores_observatory.nss_helper import CertdataEntryServerAuthTrustEnum, \
    CertdataCertificateEntry, CertdataTrustEntry, parse_certdata


class UbuntuPackage:
    """Helper class to extract necessary items from an Ubuntu package.
    """

    _CERT_DATA_FILE = 'certdata.txt'

    def __init__(self, tar_file_path: str, mode: str) -> None:
        self._tar_file_path = tar_file_path
        self.mode = mode

    def __enter__(self) -> 'UbuntuPackage':
        self._tar_file = tarfile.open(name=self._tar_file_path, mode=self.mode)
        return self

    def __exit__(
            self,
            exc_type: Optional[Type[BaseException]],
            exc_value: Optional[BaseException],
            traceback: Optional[Any]
    ) -> None:
        if self._tar_file:
            self._tar_file.close()

    def get_cert_data(self) -> str:
        """Return the content of certdata.txt, found in ca-certificates/mozilla/certdata.txt, as a string
        """
        file_names = self._tar_file.getnames()
        for file_name in file_names:
            if 'certdata.txt' in file_name:
                cert_data_file = file_name
                break

        cert_data = self._tar_file.extractfile(cert_data_file)
        if not cert_data:
            raise ValueError(f'Could not extract certdata.txt')
        return cert_data.read().decode('utf-8')


class UbuntuTrustStoreFetcher(StoreFetcherInterface):

    _PAGE_URL = 'http://archive.ubuntu.com/ubuntu/pool/main/c/ca-certificates/'
    _TARGET_EXTENSION = 'tar'

    def fetch(self, certs_repo: RootCertificatesRepository, should_update_repo: bool=True) -> TrustStore:
        # There's no specific version available in the certdata file
        os_version = None

        download_file_name = self._get_download_file_name()
        response = urlopen(self._PAGE_URL + download_file_name)
        mode = f"r:{download_file_name[download_file_name.rindex('.') + 1:]}"

        ubuntu_temp_file = NamedTemporaryFile(delete=False)
        try:
            ubuntu_temp_file.write(response.read())
            ubuntu_temp_file.close()
            with UbuntuPackage(ubuntu_temp_file.name, mode) as extracted_package:
                # Extract the data we need: cert data
                certdata_content = extracted_package.get_cert_data()
        finally:
            os.remove(ubuntu_temp_file.name)

        # Process the data
        entries = parse_certdata(certdata_content)
        # Steps taken from Mozilla fetcher
        certificate_entries = [entry for entry in entries if isinstance(entry, CertdataCertificateEntry)]
        trust_entries = [entry for entry in entries if isinstance(entry, CertdataTrustEntry)]

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

        return TrustStore(PlatformEnum.UBUNTU_NSS, os_version, self._PAGE_URL, datetime.utcnow().date(),
                          trusted_certificates, blocked_certificates)

    @classmethod
    def _get_download_file_name(cls) -> str:
        with urlopen(cls._PAGE_URL) as response:
            page_content = response.read()

        souped_page = BeautifulSoup(page_content, 'html.parser')
        anchor_elements = souped_page.find_all('a')
        for elem in reversed(anchor_elements):
            href = elem.get('href')
            if cls._TARGET_EXTENSION in href:
                download_file_name = href
                break

        return download_file_name
