from os import environ
from pathlib import Path
import argparse

import yaml

from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate, load_der_x509_certificate

from trust_stores_observatory import __version__
from trust_stores_observatory.certificates_repository import RootCertificatesRepository
from trust_stores_observatory.store_fetcher import TrustStoreFetcher
from trust_stores_observatory.trust_store import PlatformEnum, TrustStore


ROOT_PATH = Path(__file__).parent.resolve()


def import_certificates(folder_with_certs_to_import: Path) -> None:
    for cert_path in folder_with_certs_to_import.glob("*"):
        if cert_path.name.endswith(".pem"):
            cert_as_pem = cert_path.read_text()
            parsed_cert = load_pem_x509_certificate(cert_as_pem.encode(encoding="ascii"), default_backend())
        elif cert_path.name.endswith(".der"):
            cert_as_der = cert_path.read_bytes()
            parsed_cert = load_der_x509_certificate(cert_as_der, default_backend())
        else:
            print(f"Skipping file {cert_path}.")
            continue

        repo = RootCertificatesRepository(Path("certificates"))
        new_cert_path = repo.store_certificate(parsed_cert)
        print(f"Stored certificate at {new_cert_path}")


def refresh_trust_stores() -> None:
    """Fetch the trust store of each supported platform and update the corresponding local YAML file at ./trust_stores.
    """
    # Also pass the local certs repo so it gets updated when fetching the trust stores
    certs_repo = RootCertificatesRepository.get_default()

    # For each supported platform, fetch the trust store
    store_fetcher = TrustStoreFetcher()
    for platform in PlatformEnum:
        if platform == PlatformEnum.ORACLE_JAVA:
            # TODO: Fix this
            print(f"Skipping {platform.name}... TODO: Fixme")
            continue
        print(f"Refreshing {platform.name}...")
        fetched_store = store_fetcher.fetch(platform, certs_repo)

        # Compare the existing trust store with the one we fetched
        has_store_changed = False
        store_path = Path(ROOT_PATH) / "trust_stores" / f"{fetched_store.platform.name.lower()}.yaml"
        try:
            existing_store = TrustStore.from_yaml(store_path)
            if existing_store != fetched_store:
                has_store_changed = True
        except FileNotFoundError:
            # The store does not exist in the repo yet
            has_store_changed = True

        if has_store_changed:
            print(f"Detected changes for {platform.name}; updating store...")
            with open(store_path, mode="w") as store_file:
                yaml.dump(fetched_store, store_file, encoding="utf-8", default_flow_style=False)
        else:
            print(f"No changes detected for {platform.name}")


def export_trust_stores() -> None:
    """Export the content of the trust store of each supported platform to a PEM file at ./export.
    """
    certs_repo = RootCertificatesRepository.get_default()
    out_pem_folder = ROOT_PATH / "export"
    out_pem_folder.mkdir(exist_ok=True)

    # Export each trust store as a PEM file to ./export
    print(f"Exporting stores as PEM to {out_pem_folder}...")
    for platform in PlatformEnum:
        print(f"Exporting {platform.name}...")
        store = TrustStore.get_default_for_platform(platform)
        all_certs_pem = store.export_trusted_certificates_as_pem(certs_repo)

        out_pem_path = out_pem_folder / f"{platform.name.lower()}.pem"
        with open(out_pem_path, mode="w") as out_pem_file:
            out_pem_file.write(all_certs_pem)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Trust Store Observatory CLI.")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--import_certificates", action="store", help=str(import_certificates.__doc__))
    parser.add_argument("--export", action="store_true", help=str(export_trust_stores.__doc__))
    parser.add_argument("--refresh", action="store_true", help=str(refresh_trust_stores.__doc__))
    args = parser.parse_args()

    if (args.export and args.import_certificates) or (args.refresh and args.import_certificates):
        raise ValueError("Cannot combine --import_certificate with other options.")

    if args.import_certificates:
        certs_folder = Path(args.import_certificates)
        import_certificates(certs_folder)

    # Always refresh before exporting
    if args.refresh:
        refresh_trust_stores()

    if args.export:
        export_trust_stores()
