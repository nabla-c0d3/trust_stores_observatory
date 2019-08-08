from typing import Union

from cryptography.hazmat.primitives import hashes


class ScrapedRootCertificateRecord:
    """A root certificate subject name and fingerprint scraped from a list of root records (Apple's, MSFT, etc.).

    It needs to be validated and sanitized by the RootRecordsValidator before we can do anything with it.
    """

    def __init__(
        self, subject_name: str, fingerprint: bytes, fingerprint_hash_algorithm: Union[hashes.SHA1, hashes.SHA256]
    ) -> None:
        self.subject_name = subject_name
        self.fingerprint = fingerprint
        self.fingerprint_hash_algorithm = fingerprint_hash_algorithm
