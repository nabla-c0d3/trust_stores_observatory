from binascii import unhexlify
from enum import Enum

import datetime
from operator import attrgetter
from pathlib import Path
from typing import Set, Optional

import os
import yaml
from cryptography.hazmat.primitives.serialization import Encoding

from trust_stores_observatory.certificates_repository import RootCertificatesRepository
from trust_stores_observatory.root_record import RootCertificateRecord


class PlatformEnum(Enum):
    """The list of platforms supported by TSO.
    """

    APPLE = 1
    GOOGLE_AOSP = 2
    MICROSOFT_WINDOWS = 3
    MOZILLA_NSS = 4
    ORACLE_JAVA = 5
    OPENJDK = 6

    # TODO(AD)
    # DEBIAN or UBUNTU?


class TrustStore:
    """The set of root certificates that compose the trust store of one platform at a specific time.
    """

    def __init__(
        self,
        platform: PlatformEnum,
        version: Optional[str],
        url: str,
        date_fetched: datetime.date,
        trusted_certificates: Set[RootCertificateRecord],
        blocked_certificates: Set[RootCertificateRecord] = None,
    ) -> None:
        if blocked_certificates is None:
            blocked_certificates = set()
        self.platform = platform

        if version is not None:
            version = version.strip()
        self.version = version

        self.url = url.strip()
        self.date_fetched = date_fetched
        self.trusted_certificates = trusted_certificates
        self.blocked_certificates = blocked_certificates
        # TODO(AD): Track additional constraints such as whether the cert is trusted, blocked, or "always ask" (Apple)
        # or Disabled / notBefore (MSFT) - basically anything that has to do with what the certificate can do but that
        # is not stored as a field in the certificate itself

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, TrustStore):
            return False
        # Two stores are equal if all their fields except for date_fetched are equal
        self_dict = self.__dict__.copy()
        self_dict.pop("date_fetched")
        other_dict = other.__dict__.copy()
        other_dict.pop("date_fetched")
        return other_dict == self_dict

    @property
    def trusted_certificates_count(self) -> int:
        return len(self.trusted_certificates)

    @property
    def blocked_certificates_count(self) -> int:
        return len(self.blocked_certificates)

    @classmethod
    def get_default_for_platform(cls, platform: PlatformEnum) -> "TrustStore":
        module_path = Path(os.path.abspath(os.path.dirname(__file__)))
        store_yaml_path = module_path / ".." / "trust_stores" / f"{platform.name.lower()}.yaml"
        return cls.from_yaml(store_yaml_path)

    @classmethod
    def from_yaml(cls, yaml_file_path: Path) -> "TrustStore":
        with open(yaml_file_path, mode="r") as store_file:
            store_dict = yaml.safe_load(store_file)

        trusted_certificates = [
            RootCertificateRecord(entry["subject_name"], unhexlify(entry["fingerprint"]))
            for entry in store_dict["trusted_certificates"]
        ]

        blocked_certificates = [
            RootCertificateRecord(entry["subject_name"], unhexlify(entry["fingerprint"]))
            for entry in store_dict["blocked_certificates"]
        ]

        return cls(
            PlatformEnum[store_dict["platform"]],
            store_dict["version"],
            store_dict["url"],
            store_dict["date_fetched"],
            set(trusted_certificates),
            set(blocked_certificates),
        )

    def export_trusted_certificates_as_pem(self, certs_repository: RootCertificatesRepository) -> str:
        # Lookup each certificate in the folders we use as the repository of all root certs
        all_certs_as_pem = []
        for cert_record in self.trusted_certificates:
            cert = certs_repository.lookup_certificate_with_fingerprint(cert_record.fingerprint)
            # Export each certificate as PEM
            all_certs_as_pem.append(cert.public_bytes(Encoding.PEM).decode("ascii"))

        return "\n".join(all_certs_as_pem)


# YAML serialization helpers
def _represent_trust_store(dumper: yaml.Dumper, store: TrustStore) -> yaml.Node:
    # Always sort the certificates alphabetically so it is easy to diff the list
    sorted_trusted_certs = sorted(store.trusted_certificates, key=attrgetter("subject_name", "hex_fingerprint"))
    sorted_blocked_certs = sorted(store.blocked_certificates, key=attrgetter("subject_name", "hex_fingerprint"))

    # TODO(AD): this seems to maintain order for fields because dicts in Python 3.6 keep the order - it "should not be
    # relied upon" but let's rely on it anyway for now
    final_dict = {
        "platform": store.platform.name,
        "version": store.version,
        "url": store.url,
        "date_fetched": store.date_fetched,
        "trusted_certificates_count": store.trusted_certificates_count,
        "trusted_certificates": sorted_trusted_certs,
        "blocked_certificates_count": store.blocked_certificates_count,
        "blocked_certificates": sorted_blocked_certs,
    }

    return dumper.represent_dict(final_dict.items())


yaml.add_representer(TrustStore, _represent_trust_store)


def _represent_root_certificate_entry(dumper: yaml.Dumper, entry: RootCertificateRecord) -> yaml.Node:
    # TODO(AD): this seems to maintain order for fields because dicts in Python 3.6 keep the order - it "should not be
    # relied upon" but let's rely on it anyway for now
    final_dict = {"subject_name": entry.subject_name, "fingerprint": entry.hex_fingerprint}
    return dumper.represent_dict(final_dict.items())


yaml.add_representer(RootCertificateRecord, _represent_root_certificate_entry)
