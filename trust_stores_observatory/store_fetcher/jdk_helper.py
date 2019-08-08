from typing import Any, List, Optional, Type

import jks
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import load_der_x509_certificate

import tarfile
from trust_stores_observatory.certificate_utils import CertificateUtils
from trust_stores_observatory.certificates_repository import RootCertificatesRepository
from trust_stores_observatory.store_fetcher.scraped_root_record import ScrapedRootCertificateRecord


class JdkPackage:
    """Helper class to extract the things we need from a Java Runtime Environment package.
    """

    _PATH_TO_SECURITY = "/lib/security"

    _PATH_TO_CACERTS = f"{_PATH_TO_SECURITY}/cacerts"
    _CACERTS_PASSWORD = "changeit"  # default password for key store

    _PATH_TO_BLACKLISTED_CERTS = f"{_PATH_TO_SECURITY}/blacklisted.certs"

    def __init__(self, tar_gz_path: str) -> None:
        self._tar_file_path = tar_gz_path

    def __enter__(self) -> "JdkPackage":
        self._tar_file = tarfile.open(name=self._tar_file_path, mode="r:gz")
        self._root_folder_path = self._tar_file.getnames()[0].split("/", 1)[0]
        return self

    def __exit__(
        self, exc_type: Optional[Type[BaseException]], exc_value: Optional[BaseException], traceback: Optional[Any]
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
            raise ValueError(f"Could not extract {blacklisted_certs_path}")
        # This file is expected to contain utf-8 text so we return its content as a str
        return blacklisted_certs.read().decode("utf-8")

    def get_cacerts(self) -> bytes:
        """Return the content of /lib/security/cacerts as bytes.
        """
        cacerts_path = self._root_folder_path + self._PATH_TO_CACERTS
        cacerts = self._tar_file.extractfile(cacerts_path)
        if not cacerts:
            raise ValueError(f"Could not extract {cacerts_path}")
        return cacerts.read()

    def get_cacerts_password(self) -> str:
        """Return the default password to open the key store returned by get_cacerts().
        """
        return self._CACERTS_PASSWORD

    @staticmethod
    def extract_trusted_root_records(
        key_store: jks.KeyStore, should_update_repo: bool, cert_repo: RootCertificatesRepository
    ) -> List[ScrapedRootCertificateRecord]:
        root_records = []
        for alias, item in key_store.certs.items():
            parsed_cert = load_der_x509_certificate(item.cert, default_backend())
            if should_update_repo:
                cert_repo.store_certificate(parsed_cert)

            root_records.append(
                ScrapedRootCertificateRecord(
                    CertificateUtils.get_canonical_subject_name(parsed_cert),
                    parsed_cert.fingerprint(hashes.SHA256()),
                    hashes.SHA256(),
                )
            )

        return root_records

    @staticmethod
    def extract_blacklisted_root_records(blacklisted_certs_content: str) -> List[ScrapedRootCertificateRecord]:
        # The file only contains a list of SHA-256 fingerprints
        blacklisted_records = []
        for fingerprint in blacklisted_certs_content.split("\n")[1:]:
            if not fingerprint:
                continue
            blacklisted_records.append(
                ScrapedRootCertificateRecord("Blacklisted", bytes(bytearray.fromhex(fingerprint)), hashes.SHA256())
            )

        return blacklisted_records
