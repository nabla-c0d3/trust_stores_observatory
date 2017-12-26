from binascii import hexlify
from enum import Enum

from datetime import datetime
from operator import attrgetter
from typing import List

import yaml


class PlatformEnum(Enum):
    """The list of platforms supported by TSO.
    """
    APPLE_IOS = 1
    APPLE_MACOS = 2

    # TODO(AD)
    MOZILLA_NSS = 3
    GOOGLE_AOSP = 4
    MICROSOFT_WINDOWS = 5
    ORACLE_JAVA = 6


# TODO(AD): Add an enum to keep track of whether the certificate is trusted, blocked, or "always ask"
class RootCertificateEntry:
    """A root certificate listed on a trust store page of one of the supported platforms.
    """

    def __init__(self, subject_name: str, fingerprint: bytes) -> None:
        self.subject_name = subject_name.strip()
        self.fingerprint = fingerprint

    @property
    def hex_fingerprint(self) -> str:
        """The SHA 256 fingerprint of the certificate as hex.
        """
        return hexlify(self.fingerprint).decode('ascii')


class TrustStore:

    def __init__(
            self,
            platform: PlatformEnum,
            version: str,
            url: str,
            date_fetched: datetime.date,
            trusted_certificates: List[RootCertificateEntry]
    ) -> None:
        self.platform = platform
        self.version = version.strip()
        self.url = url.strip()
        self.date_fetched = date_fetched
        self.trusted_certificates = trusted_certificates

    @property
    def trusted_certificates_count(self) -> int:
        return len(self.trusted_certificates)


def represent_trust_store(dumper: yaml.Dumper, store: TrustStore) -> yaml.Node:
    # TODO(AD): this seems to maintain order for fields because dicts in Python 3.6 keep the order - it "should not be
    # relied upon" but let's rely on it anyway for now
    final_dict = {
        'platform': store.platform.name,
        'version': store.version,
        'url': store.url,
        'date_fetched': store.date_fetched,
        'trusted_certificates_count': store.trusted_certificates_count,
    }
    # Always sort the certificates alphabetically so it is easy to diff the list
    sorted_trusted_certs = sorted(store.trusted_certificates, key=attrgetter('subject_name', 'hex_fingerprint'))
    final_dict['trusted_certificates'] = sorted_trusted_certs

    return dumper.represent_dict(final_dict.items())

yaml.add_representer(TrustStore, represent_trust_store)


def represent_root_certificate_entry(dumper: yaml.Dumper, entry: RootCertificateEntry) -> yaml.Node:
    # TODO(AD): this seems to maintain order for fields because dicts in Python 3.6 keep the order - it "should not be
    # relied upon" but let's rely on it anyway for now
    final_dict = {
        'subject_name': entry.subject_name,
        'fingerprint': entry.hex_fingerprint,
    }
    return dumper.represent_dict(final_dict.items())

yaml.add_representer(RootCertificateEntry, represent_root_certificate_entry)
