from binascii import hexlify, unhexlify
from enum import Enum

from datetime import datetime
from operator import attrgetter
from pathlib import Path
from typing import List

import os
import yaml
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import Certificate

from trust_stores_observatory.certificate_utils import CertificateUtils
from trust_stores_observatory.certificates_repository import RootCertificatesRepository


class PlatformEnum(Enum):
    """The list of platforms supported by TSO.
    """
    APPLE_IOS = 1
    APPLE_MACOS = 2
    GOOGLE_AOSP = 3

    # TODO(AD)
    # MOZILLA_NSS = 3
    # MICROSOFT_WINDOWS = 5
    # ORACLE_JAVA = 6


class RootCertificateRecord:
    """A root certificate listed on a trust store page of one of the supported platforms.

    This is the object we export to the trust store YAML files.
    """

    def __init__(self, canonical_subject_name: str, sha256_fingerprint: bytes) -> None:
        self.subject_name = canonical_subject_name
        self.fingerprint = sha256_fingerprint

        # TODO(AD): Track additional constraints such as whether the cert is trusted, blocked, or "always ask" (Apple)
        # or Disabled / notBefore (MSFT) - basically anything that has to do with what the certificate can do but that
        # is not stored as a field in the certificate itself

    @classmethod
    def from_certificate(cls, certificate: Certificate) -> 'RootCertificateRecord':
        subject_name = CertificateUtils.get_canonical_subject_name(certificate)
        fingerprint = certificate.fingerprint(SHA256())
        return cls(subject_name, fingerprint)

    @classmethod
    def from_scraped_record(cls, scraped_subject_name: str, scraped_fingerprint: bytes) -> 'RootCertificateRecord':
        """For some platforms (such as Apple), we fetch the list of root certificates by scraping a web page that
        only contains basic information about each cert, but not the actual PEM data. This method should be used when
        the certificate corresponding to the scraped fingerprint was not found in the local certificate repository.
        """
        # I will have to manually find and add this certificate
        temp_subject_name = f' NOT IN REPO: {scraped_subject_name}'
        return cls(temp_subject_name, scraped_fingerprint)


    @property
    def hex_fingerprint(self) -> str:
        """The SHA 256 fingerprint of the certificate as a hex string.
        """
        return hexlify(self.fingerprint).decode('ascii')


class TrustStore:
    """The set of root certificates that compose the trust store of one platform at a specific time.
    """

    def __init__(
            self,
            platform: PlatformEnum,
            version: str,
            url: str,
            date_fetched: datetime.date,
            trusted_certificates: List[RootCertificateRecord],
            blocked_certificates: List[RootCertificateRecord]=None,
    ) -> None:
        if blocked_certificates is None:
            blocked_certificates = []
        self.platform = platform
        self.version = version.strip()
        self.url = url.strip()
        self.date_fetched = date_fetched
        self.trusted_certificates = trusted_certificates
        self.blocked_certificates = blocked_certificates

    @property
    def trusted_certificates_count(self) -> int:
        return len(self.trusted_certificates)

    @property
    def blocked_certificates_count(self) -> int:
        return len(self.blocked_certificates)

    @classmethod
    def get_default_for_platform(cls, platform: PlatformEnum) -> 'TrustStore':
        module_path = Path(os.path.abspath(os.path.dirname(__file__)))
        store_yaml_path = module_path / '..' / 'trust_stores' / f'{platform.name.lower()}.yaml'
        return cls.from_yaml(store_yaml_path)

    @classmethod
    def from_yaml(cls, yaml_file_path: Path) -> 'TrustStore':
        with open(yaml_file_path, mode='r') as store_file:
            store_dict = yaml.load(store_file)

        trusted_certificates = [RootCertificateRecord(entry['subject_name'], unhexlify(entry['fingerprint']))
                                for entry in store_dict['trusted_certificates']]

        blocked_certificates = [RootCertificateRecord(entry['subject_name'], unhexlify(entry['fingerprint']))
                                for entry in store_dict['blocked_certificates']]

        return cls(
            PlatformEnum[store_dict['platform']],
            store_dict['version'],
            store_dict['url'],
            store_dict['date_fetched'],
            trusted_certificates,
            blocked_certificates
        )

    def export_trusted_certificates_as_pem(self, certs_repository: RootCertificatesRepository) -> str:
        # Lookup each certificate in the folders we use as the repository of all root certs
        all_certs_as_pem = []
        for cert_record in self.trusted_certificates:
            cert = certs_repository.lookup_certificate_with_fingerprint(cert_record.fingerprint)
            # Export each certificate as PEM
            all_certs_as_pem.append(cert.public_bytes(Encoding.PEM).decode('ascii'))

        return '\n'.join(all_certs_as_pem)


# YAML serialization helpers
def _represent_trust_store(dumper: yaml.Dumper, store: TrustStore) -> yaml.Node:
    # Always sort the certificates alphabetically so it is easy to diff the list
    sorted_trusted_certs = sorted(store.trusted_certificates, key=attrgetter('subject_name', 'hex_fingerprint'))
    sorted_blocked_certs = sorted(store.blocked_certificates, key=attrgetter('subject_name', 'hex_fingerprint'))

    # TODO(AD): this seems to maintain order for fields because dicts in Python 3.6 keep the order - it "should not be
    # relied upon" but let's rely on it anyway for now
    final_dict = {
        'platform': store.platform.name,
        'version': store.version,
        'url': store.url,
        'date_fetched': store.date_fetched,
        'trusted_certificates_count': store.trusted_certificates_count,
        'trusted_certificates': sorted_trusted_certs,
        'blocked_certificates_count': store.blocked_certificates_count,
        'blocked_certificates': sorted_blocked_certs,
    }

    return dumper.represent_dict(final_dict.items())


yaml.add_representer(TrustStore, _represent_trust_store)


def _represent_root_certificate_entry(dumper: yaml.Dumper, entry: RootCertificateRecord) -> yaml.Node:
    # TODO(AD): this seems to maintain order for fields because dicts in Python 3.6 keep the order - it "should not be
    # relied upon" but let's rely on it anyway for now
    final_dict = {
        'subject_name': entry.subject_name,
        'fingerprint': entry.hex_fingerprint,
    }
    return dumper.represent_dict(final_dict.items())


yaml.add_representer(RootCertificateRecord, _represent_root_certificate_entry)
