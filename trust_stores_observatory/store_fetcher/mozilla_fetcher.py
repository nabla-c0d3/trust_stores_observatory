import logging
from abc import ABC
from datetime import datetime
from enum import Enum
from typing import List
from urllib.request import urlopen

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import load_der_x509_certificate, Certificate

from trust_stores_observatory.certificates_repository import RootCertificatesRepository
from trust_stores_observatory.store_fetcher.root_records_validator import RootRecordsValidator
from trust_stores_observatory.store_fetcher.scraped_root_record import ScrapedRootCertificateRecord
from trust_stores_observatory.store_fetcher.store_fetcher_interface import StoreFetcherInterface
from trust_stores_observatory.trust_store import TrustStore, PlatformEnum


class _CerdataEntryServerAuthTrustEnum(Enum):
    #  We only look at the trust value for issuing SSL certificates (CKA_TRUST_SERVER_AUTH)
    # Cert trusted for issuing SSL certs
    TRUSTED = "CKA_TRUST_SERVER_AUTH CK_TRUST CKT_NSS_TRUSTED_DELEGATOR"

    # Cert trusted for other usages than issuing SSL certs
    MUST_VERIFY = "CKA_TRUST_SERVER_AUTH CK_TRUST CKT_NSS_MUST_VERIFY_TRUST"

    # Explicitly distruted cert (DigiNotar etc)
    NOT_TRUSTED = "CKA_TRUST_SERVER_AUTH CK_TRUST CKT_NSS_NOT_TRUSTED"


class _CertdataEntry(ABC):
    pass


class _CertdataCertificateEntry(_CertdataEntry):
    def __init__(self, certificate: Certificate) -> None:
        self.certificate = certificate


class _CertdataTrustEntry(_CertdataEntry):
    def __init__(
        self, scraped_subject_name: str, trust_enum: _CerdataEntryServerAuthTrustEnum, sha_fingerprint: bytes
    ) -> None:
        self.name = scraped_subject_name
        self.trust_enum = trust_enum
        self.sha1_fingerprint = sha_fingerprint


class MozillaTrustStoreFetcher(StoreFetcherInterface):

    _PAGE_URL = "https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt"

    def fetch(self, certs_repo: RootCertificatesRepository, should_update_repo: bool = True) -> TrustStore:
        # There's no specific version available in the certdata file
        os_version = None

        # Then fetch and parse the page
        with urlopen(self._PAGE_URL) as response:
            page_content = response.read().decode("utf-8")

        entries = self._scrape_certdata(page_content)
        certificate_entries = [entry for entry in entries if isinstance(entry, _CertdataCertificateEntry)]
        trust_entries = [entry for entry in entries if isinstance(entry, _CertdataTrustEntry)]

        # Store the certificates we found in the local repo if needed
        if should_update_repo:
            for cert_entry in certificate_entries:
                certs_repo.store_certificate(cert_entry.certificate)

        trusted_certificates = RootRecordsValidator.validate_with_repository(
            certs_repo,
            [
                ScrapedRootCertificateRecord(entry.name, entry.sha1_fingerprint, hashes.SHA1())
                for entry in trust_entries
                if entry.trust_enum == _CerdataEntryServerAuthTrustEnum.TRUSTED
            ],
        )

        blocked_certificates = RootRecordsValidator.validate_with_repository(
            certs_repo,
            [
                ScrapedRootCertificateRecord(entry.name, entry.sha1_fingerprint, hashes.SHA1())
                for entry in trust_entries
                if entry.trust_enum == _CerdataEntryServerAuthTrustEnum.NOT_TRUSTED
            ],
        )

        return TrustStore(
            PlatformEnum.MOZILLA_NSS,
            os_version,
            self._PAGE_URL,
            datetime.utcnow().date(),
            trusted_certificates,
            blocked_certificates,
        )

    @staticmethod
    def _scrape_certdata(certdata_content: str) -> List[_CertdataEntry]:
        # Skip the header
        certdata_content = certdata_content.split("CKA_CLASS CK_OBJECT_CLASS CKO_NSS_BUILTIN_ROOT_LIST", 1)[1]

        # Parse each entry
        parsed_entries: List[_CertdataEntry] = []
        page_object_entries = certdata_content.split("# Issuer: ")[1::]
        for entry in page_object_entries:
            entry_name = entry.split('CKA_LABEL UTF8 "', 1)[1].split('"\n', 1)[0].strip()
            if "CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE" in entry:
                # A certificate entry
                # Extract the multiline octal data and make it one line
                cert_as_str = entry.split("CKA_VALUE MULTILINE_OCTAL", 1)[1].split("END", 1)[0]
                cert_as_str = cert_as_str.strip().replace("\n", "")
                # Convert to bytes
                cert_bytes = bytes([int(octal_number, 8) for octal_number in cert_as_str.split("\\")[1::]])
                # Parse the certificate
                certificate = load_der_x509_certificate(cert_bytes, default_backend())

                parsed_entries.append(_CertdataCertificateEntry(certificate))

            elif "CKA_CLASS CK_OBJECT_CLASS CKO_NSS_TRUST" in entry:
                # A trust entry
                # Parse the SHA1 fingerprint if available
                if "Fingerprint (SHA1):" not in entry:
                    logging.error(f"No fingerprint available for {entry_name} - skipping...")
                    continue
                else:
                    sha1_section = entry.split("Fingerprint (SHA1):", 1)[1].split("\n", 1)[0]
                    sha1_fingerprint_hex = sha1_section.replace(":", "").strip()
                    sha1_fingerprint = bytes(bytearray.fromhex(sha1_fingerprint_hex))

                # Parse the trust value
                # Based on https://github.com/agl/extract-nss-root-certs/blob/master/convert_mozilla_certdata.go#L264
                entry_trust_enum = None
                for enum in _CerdataEntryServerAuthTrustEnum:
                    if enum.value in entry:
                        entry_trust_enum = enum
                        break
                if entry_trust_enum is None:
                    raise ValueError(f"Could not detect trust setting for CKO_NSS_TRUST in {entry_name}")

                parsed_entries.append(_CertdataTrustEntry(entry_name, entry_trust_enum, sha1_fingerprint))

            else:
                raise ValueError(f"Unknown entry in certdata {entry_name}")

        return parsed_entries
