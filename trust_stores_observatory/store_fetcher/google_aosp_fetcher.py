import subprocess
from pathlib import Path
from sys import platform
from tempfile import TemporaryDirectory

import os
import stat
from datetime import datetime

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import load_pem_x509_certificate

from trust_stores_observatory.certificate_utils import CertificateUtils
from trust_stores_observatory.certificates_repository import RootCertificatesRepository
from trust_stores_observatory.store_fetcher.root_records_validator import RootRecordsValidator
from trust_stores_observatory.store_fetcher.scraped_root_record import ScrapedRootCertificateRecord
from trust_stores_observatory.store_fetcher.store_fetcher_interface import StoreFetcherInterface
from trust_stores_observatory.trust_store import TrustStore, PlatformEnum


class AospTrustStoreFetcher(StoreFetcherInterface):

    _REPO_URL = "https://android.googlesource.com/platform/system/ca-certificates"

    _GIT_CMD = 'git clone --branch master {repo_url} "{local_path}"'
    _GIT_FIND_TAG_CMD = "git tag -l android-[0-9]*"
    _GIT_CHECKOUT_TAG_CMD = "git checkout tags/{tag}"

    def fetch(self, certs_repo: RootCertificatesRepository, should_update_repo: bool = True) -> TrustStore:
        # Fetch all the certificates from the the AOSP repo
        cert_records = []
        temp_dir = TemporaryDirectory()
        try:
            # TODO(AD): Stop using shell commands
            # Clone the AOSP repo
            git_command = self._GIT_CMD.format(repo_url=self._REPO_URL, local_path=temp_dir.name)

            with open(os.devnull, "w") as dev_null:
                subprocess.check_output(git_command, shell=True, stderr=dev_null)

                # Find the latest tag that looks like android-8XXX - we don't care about android-iot or android-wear
                tag_list = subprocess.check_output(
                    self._GIT_FIND_TAG_CMD, shell=True, cwd=temp_dir.name, stderr=dev_null
                ).decode("ascii")
                last_tag = tag_list.strip().rsplit("\n", 1)[1].strip()

                # Switch to this tag
                subprocess.check_output(
                    self._GIT_CHECKOUT_TAG_CMD.format(tag=last_tag), shell=True, cwd=temp_dir.name, stderr=dev_null
                )

                # Inspect each certificate
                cert_files_path = Path(temp_dir.name) / "files"
                for cert_path in cert_files_path.glob("*"):
                    with open(cert_path, mode="r") as cert_file:
                        cert_pem = cert_file.read()

                    # Parse each certificate and store it if needed
                    parsed_cert = load_pem_x509_certificate(cert_pem.encode(encoding="ascii"), default_backend())
                    if should_update_repo:
                        certs_repo.store_certificate(parsed_cert)

                    cert_records.append(
                        ScrapedRootCertificateRecord(
                            CertificateUtils.get_canonical_subject_name(parsed_cert),
                            parsed_cert.fingerprint(hashes.SHA256()),
                            hashes.SHA256(),
                        )
                    )
        finally:
            # Workaround for Windows https://bugs.python.org/issue26660
            if platform == "win32":
                for file_path in Path(temp_dir.name).glob("**/*"):
                    os.chmod(file_path, stat.S_IWRITE)
            temp_dir.cleanup()

        # Finally generate the records
        trusted_cert_records = RootRecordsValidator.validate_with_repository(certs_repo, cert_records)

        date_fetched = datetime.utcnow().date()
        version = last_tag.split("android-")[1]
        return TrustStore(PlatformEnum.GOOGLE_AOSP, version, self._REPO_URL, date_fetched, trusted_cert_records)
