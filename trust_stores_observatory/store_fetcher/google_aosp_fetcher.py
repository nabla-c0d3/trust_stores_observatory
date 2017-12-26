import shutil
import subprocess
from abc import ABC
from pathlib import Path
from tempfile import TemporaryDirectory

import os
import stat
from datetime import datetime
from typing import Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.x509 import load_pem_x509_certificate

from trust_stores_observatory.certificate_utils import CertificateUtils
from trust_stores_observatory.certificates_repository import RootCertificatesRepository
from trust_stores_observatory.trust_store import TrustStore, RootCertificateRecord, PlatformEnum


# Workaround for Windows https://bugs.python.org/issue26660
def _remove_readonly(func, path, _):
    os.chmod(path, stat.S_IWRITE)
    func(path)


class AospTrustStoreFetcher(ABC):

    _REPO_URL = 'https://android.googlesource.com/platform/system/ca-certificates'
    _VERSION = '8.0.0_r36'

    _GIT_CMD = 'git clone --branch android-{tag} {repo_url} "{local_path}"'

    def fetch(self, cert_repo_to_update: Optional[RootCertificatesRepository] = None) -> TrustStore:
        # Fetch all the certificates from the the AOSP repo
        temp_dir_path = TemporaryDirectory().name
        try:
            # TODO(AD): Stop using shell commands
            # Clone the AOSP repo
            git_command = self._GIT_CMD.format(tag=self._VERSION, repo_url=self._REPO_URL, local_path=temp_dir_path)
            print(git_command)
            subprocess.call(git_command, shell=True)

            # Inspect each certificate
            cert_entries = []
            cert_files_path = Path(temp_dir_path) / 'files'
            for cert_path in cert_files_path.glob('*'):
                with open(cert_path, mode='r') as cert_file:
                    cert_pem = cert_file.read()

                # Parse each certificate and store it
                parsed_cert = load_pem_x509_certificate(cert_pem.encode(encoding='ascii'), default_backend())
                subject_name = CertificateUtils.get_name_as_short_text(parsed_cert.subject)
                cert_entries.append(RootCertificateRecord(subject_name, parsed_cert.fingerprint(SHA256())))

                # If a certificate repository was passed, dump all certificate to it
                if cert_repo_to_update:
                    cert_repo_to_update.store_certificate(parsed_cert)

        finally:
            shutil.rmtree(temp_dir_path, onerror=_remove_readonly)


        date_fetched = datetime.utcnow().date()
        return TrustStore(PlatformEnum.GOOGLE_AOSP, self._VERSION, self._REPO_URL, date_fetched, cert_entries)
