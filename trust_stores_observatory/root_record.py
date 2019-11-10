from binascii import hexlify
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.x509 import Certificate

from trust_stores_observatory.certificate_utils import CertificateUtils

if TYPE_CHECKING:
    from trust_stores_observatory.store_fetcher.scraped_root_record import ScrapedRootCertificateRecord  # noqa: F401


class RootCertificateRecord:
    """A validated/sanitized root certificate listed on a trust store page of one of the supported platforms.

    This is the object we export to the trust store YAML files.
    """

    def __init__(self, canonical_subject_name: str, sha256_fingerprint: bytes) -> None:
        self.subject_name = canonical_subject_name

        if len(sha256_fingerprint) != 32:
            raise ValueError(f'Supplied SHA 256 fingerprint is not 32 bytes long: "{sha256_fingerprint.hex()}"')
        self.fingerprint = sha256_fingerprint

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, RootCertificateRecord):
            return False
        return self.__dict__ == other.__dict__

    def __hash__(self) -> int:
        # Required so we can have sets of RootCertificateRecords
        return hash(self.subject_name + self.hex_fingerprint)

    @classmethod
    def from_certificate(cls, certificate: Certificate) -> "RootCertificateRecord":
        subject_name = CertificateUtils.get_canonical_subject_name(certificate)
        fingerprint = certificate.fingerprint(SHA256())
        return cls(subject_name, fingerprint)

    @classmethod
    def from_unknown_record(cls, record: "ScrapedRootCertificateRecord") -> "RootCertificateRecord":
        """For some platforms (such as Apple), we fetch the list of root certificates by scraping a web page that
        only contains basic information about each cert, but not the actual PEM data. This method should be used when
        the certificate corresponding to the scraped fingerprint was not found in the local certificate repository.
        """
        # I will have to manually find and add this certificate
        temp_subject_name = f" CERTIFICATE NOT IN REPO: {record.subject_name}"
        return cls(temp_subject_name, record.fingerprint)

    @property
    def hex_fingerprint(self) -> str:
        """The SHA 256 fingerprint of the certificate as a hex string.
        """
        return hexlify(self.fingerprint).decode("ascii")
