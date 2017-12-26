from binascii import hexlify, unhexlify
from enum import Enum

from datetime import datetime
from operator import attrgetter
from pathlib import Path
from typing import List

import yaml
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.x509 import load_pem_x509_certificate


class PlatformEnum(Enum):
    """The list of platforms supported by TSO.
    """
    APPLE_IOS = 1
    APPLE_MACOS = 2

    # TODO(AD)
    #MOZILLA_NSS = 3
    #GOOGLE_AOSP = 4
    #MICROSOFT_WINDOWS = 5
    #ORACLE_JAVA = 6


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

    @classmethod
    def from_yaml(cls, yaml_file_path: Path) -> 'TrustStore':
        with open(yaml_file_path, mode='r') as store_file:
            store_dict = yaml.load(store_file)

        trusted_certificates = [RootCertificateEntry(entry['subject_name'], unhexlify(entry['fingerprint']))
                                for entry in store_dict['trusted_certificates']]

        return cls(
            PlatformEnum[store_dict['platform']],
            store_dict['version'],
            store_dict['url'],
            store_dict['date_fetched'],
            trusted_certificates,
        )

    # TODO(AD): Add an argument to choose which certificates to export (trusted, blocked, etc.)
    def export_as_pem(self, path_to_pem_repository: Path) -> str:
        # Lookup each certificate in the folders we use as the repository of all root certs
        all_certs_as_pem = []
        for cert_entry in self.trusted_certificates:
            pem_path = path_to_pem_repository / f'{cert_entry.hex_fingerprint}.pem'
            try:
                with open(pem_path, mode='r') as pem_file:
                    cert_pem = pem_file.read()

                # Parse the certificate to double check the fingerprint
                parsed_cert = load_pem_x509_certificate(cert_pem.encode(encoding='ascii'), default_backend())
                parsed_cert_fingerprint = hexlify(parsed_cert.fingerprint(SHA256())).decode('ascii')
                if cert_entry.hex_fingerprint != parsed_cert_fingerprint.lower():
                    raise ValueError(f'Fingerprint mismatch for certificate "{cert_entry.subject_name}":'
                                     f'{cert_entry.hex_fingerprint} VS {parsed_cert_fingerprint}')

                # Export the certificate as PEM
                all_certs_as_pem.append(cert_pem)
            except FileNotFoundError:
                raise FileNotFoundError(f'Could not find certificate "{cert_entry.subject_name}" '
                                        f'- {cert_entry.hex_fingerprint}')

        return '\n'.join(all_certs_as_pem)


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
