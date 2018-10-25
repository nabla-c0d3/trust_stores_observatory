import os
from datetime import datetime
from typing import Any, List, Optional, Type
from urllib.request import Request, urlopen

import jks
from bs4 import BeautifulSoup
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import load_der_x509_certificate
from urllib.error import HTTPError
import logging

import tarfile
from tempfile import NamedTemporaryFile
from trust_stores_observatory.certificate_utils import CertificateUtils
from trust_stores_observatory.certificates_repository import RootCertificatesRepository
from trust_stores_observatory.store_fetcher.root_records_validator import RootRecordsValidator
from trust_stores_observatory.store_fetcher.scraped_root_record import ScrapedRootCertificateRecord
from trust_stores_observatory.store_fetcher.store_fetcher_interface import StoreFetcherInterface
from trust_stores_observatory.trust_store import PlatformEnum, TrustStore


class JrePackage:
    """Helper class to extract the things we need from a Java Runtime Environment package.
    """

    _PATH_TO_SECURITY = '/lib/security'

    _PATH_TO_CACERTS = f'{_PATH_TO_SECURITY}/cacerts'
    _CACERTS_PASSWORD = 'changeit'  # default password for key store

    _PATH_TO_BLACKLISTED_CERTS = f'{_PATH_TO_SECURITY}/blacklisted.certs'

    def __init__(self, tar_gz_path: str) -> None:
        self._tar_file_path = tar_gz_path

    def __enter__(self) -> 'JrePackage':
        self._tar_file = tarfile.open(name=self._tar_file_path, mode='r:gz')
        self._root_folder_path = self._tar_file.getnames()[0].split('/', 1)[0]
        return self

    def __exit__(
            self,
            exc_type: Optional[Type[BaseException]],
            exc_value: Optional[BaseException],
            traceback: Optional[Any]
    ) -> None:
        if self._tar_file:
            self._tar_file.close()

    def get_version(self) -> str:
        # It looks like this: jre-10.0.1
        return self._root_folder_path

    def get_blacklisted_certs(self) -> str:
        """Return the content of /lib/security/blacklisted.certs as a string.
        """
        blacklisted_certs_path = self._root_folder_path + self._PATH_TO_BLACKLISTED_CERTS
        blacklisted_certs = self._tar_file.extractfile(blacklisted_certs_path)
        if not blacklisted_certs:
            raise ValueError(f'Could not extract {blacklisted_certs_path}')
        # This file is expected to contain utf-8 text so we return its content as a str
        return blacklisted_certs.read().decode('utf-8')

    def get_cacerts(self) -> bytes:
        """Return the content of /lib/security/cacerts as bytes.
        """
        cacerts_path = self._root_folder_path + self._PATH_TO_CACERTS
        cacerts = self._tar_file.extractfile(cacerts_path)
        if not cacerts:
            raise ValueError(f'Could not extract {cacerts_path}')
        return cacerts.read()

    def get_cacerts_password(self) -> str:
        """Return the default password to open the key store returned by get_cacerts().
        """
        return self._CACERTS_PASSWORD


class JavaTrustStoreFetcher(StoreFetcherInterface):

    _BASE_URL = "https://www.oracle.com"
    _DOWNLOADS_INDEX = "/technetwork/java/javase/downloads/index.html"

    def fetch(
            self,
            cert_repo: RootCertificatesRepository,
            should_update_repo: bool=True
    ) -> TrustStore:
        # Fetch the latest JRE package
        final_url = self._get_latest_download_url()
        request = Request(
            final_url,
            # Cookie set when 'Accept License Agreement' is selected
            headers={'Cookie': 'oraclelicense=accept-securebackup-cookie'}
        )
        response = urlopen(request)

        # Parse the JRE package
        jre_temp_file = NamedTemporaryFile(delete=False)
        try:
            jre_temp_file.write(response.read())
            jre_temp_file.close()
            with JrePackage(jre_temp_file.name) as parsed_jre:
                # Extract the data we need
                version = parsed_jre.get_version()
                blacklisted_file_content = parsed_jre.get_blacklisted_certs()
                cacerts_key_store = jks.KeyStore.loads(parsed_jre.get_cacerts(), parsed_jre.get_cacerts_password())
        finally:
            os.remove(jre_temp_file.name)

        # Process the data extracted from the JRE
        # Trusted CA certs
        scraped_trusted_records = self._extract_trusted_root_records(cacerts_key_store, should_update_repo, cert_repo)
        trusted_records = RootRecordsValidator.validate_with_repository(cert_repo, scraped_trusted_records)

        # Blacklisted CA certs - will fail if a blacklisted cert is not already available in the local repo
        scraped_blacklisted_records = self._extract_blacklisted_root_records(blacklisted_file_content)
        blacklisted_records = RootRecordsValidator.validate_with_repository(cert_repo, scraped_blacklisted_records)

        return TrustStore(
            PlatformEnum.ORACLE_JAVA,
            version,
            final_url,
            datetime.utcnow().date(),
            trusted_records,
            blacklisted_records
        )

    @staticmethod
    def _extract_trusted_root_records(
            key_store: jks.KeyStore,
            should_update_repo: bool,
            cert_repo: RootCertificatesRepository
    ) -> List[ScrapedRootCertificateRecord]:
        root_records = []
        for alias, item in key_store.certs.items():
            parsed_cert = load_der_x509_certificate(item.cert, default_backend())
            if should_update_repo:
                cert_repo.store_certificate(parsed_cert)

            root_records.append(ScrapedRootCertificateRecord(
                CertificateUtils.get_canonical_subject_name(parsed_cert),
                parsed_cert.fingerprint(hashes.SHA256()),
                hashes.SHA256())
            )

        return root_records

    @staticmethod
    def _extract_blacklisted_root_records(blacklisted_certs_content: str) -> List[ScrapedRootCertificateRecord]:
        # The file only contains a list of SHA-256 fingerprints
        blacklisted_records = []
        for fingerprint in blacklisted_certs_content.split("\n")[1:]:
            fingerprint = fingerprint.replace("\r", "")
            fingerprint = fingerprint.replace(".", "")
            if not fingerprint:
                continue
            blacklisted_records.append(
                ScrapedRootCertificateRecord('Blacklisted', bytes(bytearray.fromhex(fingerprint)), hashes.SHA256())
            )

        return blacklisted_records

    @classmethod
    def _get_latest_download_url(cls) -> str:
        # Parse the main download page - rety 3 times as it sometimes fail on CI
        for _ in range(3):
            try:
                with urlopen(cls._BASE_URL + cls._DOWNLOADS_INDEX) as response:
                    page_content = response.read()
                main_page = BeautifulSoup(page_content, 'html.parser')
                break
            except HTTPError:
                # Retry
                logging.info('HTTP error when fetching the download URL for Oracle; retrying...')
                pass

        # Find the link to the latest JRE's download page
        href = main_page.find('img', alt='Download JRE').parent
        latest_download_link = href.get('href')

        with urlopen(cls._BASE_URL + latest_download_link) as download_page:
            latest_download_page = download_page.read().decode('utf-8')

        # The final download link for the .tar.gz JRE package is in a script tag
        jre_download_url = latest_download_page.split('linux-x64.tar.gz"')[0].rsplit('download.oracle.com', 1)[1]
        final_download_url = f'http://download.oracle.com{jre_download_url}linux-x64.tar.gz'
        return final_download_url
