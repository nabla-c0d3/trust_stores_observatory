import shutil
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory

import os
import stat
from datetime import datetime

from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate

from trust_stores_observatory.certificates_repository import RootCertificatesRepository
from trust_stores_observatory.trust_store import TrustStore, RootCertificateRecord, PlatformEnum


# Workaround for Windows https://bugs.python.org/issue26660
def _remove_readonly(func, path, _):
    os.chmod(path, stat.S_IWRITE)
    func(path)


class AospTrustStoreFetcher:

    _REPO_URL = 'https://android.googlesource.com/platform/system/ca-certificates'

    _GIT_CMD = 'git clone --branch master {repo_url} "{local_path}"'
    _GIT_FIND_TAG_CMD = 'git tag -l android-[0-9]*'
    _GIT_CHECKOUT_TAG_CMD = 'git checkout tags/{tag}'

    def fetch(self,
              certs_repo: RootCertificatesRepository,
              should_update_repo: bool=True
              ) -> TrustStore:
        # Fetch all the certificates from the the AOSP repo
        temp_dir_path = TemporaryDirectory().name
        try:
            # TODO(AD): Stop using shell commands
            # Clone the AOSP repo
            git_command = self._GIT_CMD.format(repo_url=self._REPO_URL, local_path=temp_dir_path)
            subprocess.check_output(git_command, shell=True, stderr=open(os.devnull, 'w'))

            # Find the latest tag that looks like android-8XXX - we don't care about android-iot or android-wear
            tag_list = subprocess.check_output(self._GIT_FIND_TAG_CMD, shell=True, cwd=temp_dir_path,
                                               stderr=open(os.devnull, 'w')).decode('ascii')
            last_tag = tag_list.strip().rsplit('\n', 1)[1].strip()

            # Switch to this tag
            subprocess.check_output(self._GIT_CHECKOUT_TAG_CMD.format(tag=last_tag), shell=True, cwd=temp_dir_path,
                                    stderr=open(os.devnull, 'w'))

            # Inspect each certificate
            cert_entries = []
            cert_files_path = Path(temp_dir_path) / 'files'
            for cert_path in cert_files_path.glob('*'):
                with open(cert_path, mode='r') as cert_file:
                    cert_pem = cert_file.read()

                # Parse each certificate and store it if needed
                parsed_cert = load_pem_x509_certificate(cert_pem.encode(encoding='ascii'), default_backend())
                cert_entries.append(RootCertificateRecord.from_certificate(parsed_cert))
                if should_update_repo:
                    certs_repo.store_certificate(parsed_cert)

        finally:
            shutil.rmtree(temp_dir_path, onerror=_remove_readonly)


        date_fetched = datetime.utcnow().date()
        version = last_tag.split('android-')[1]
        return TrustStore(PlatformEnum.GOOGLE_AOSP, version, self._REPO_URL, date_fetched, set(cert_entries))
