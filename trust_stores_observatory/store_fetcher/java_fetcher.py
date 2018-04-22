from typing import List
from tempfile import NamedTemporaryFile
from datetime import datetime
from urllib.request import urlopen
from urllib.request import Request
from bs4 import BeautifulSoup
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import load_der_x509_certificate, NameOID
from cryptography.hazmat.backends import default_backend

from trust_stores_observatory.certificates_repository import RootCertificatesRepository
from trust_stores_observatory.store_fetcher.root_records_validator import RootRecordsValidator
from trust_stores_observatory.store_fetcher.scraped_root_record import ScrapedRootCertificateRecord
from trust_stores_observatory.store_fetcher.store_fetcher_interface import StoreFetcherInterface
from trust_stores_observatory.trust_store import TrustStore, PlatformEnum

import jks
import tarfile


class JavaTrustStoreFetcher(StoreFetcherInterface):

    _BASE_URL = "http://www.oracle.com"
    _DOWNLOADS_INDEX = "/technetwork/java/javase/downloads/index.html"

    def fetch(self,
              cert_repo: RootCertificatesRepository,
              should_update_repo: bool = True) -> TrustStore:
        path_to_security = '/lib/security/'
        cacerts = 'cacerts'
        blacklisted = 'blacklisted.certs'
        default_password = 'changeit'  # default password for key store

        try:
            cookie_header = {}
            # cookie set when 'Accept License Agreement' is selected
            cookie_header[
                'Cookie'] = 'oraclelicense=accept-securebackup-cookie'
            url = self._get_latest_download_url()
            req = Request(url, headers=cookie_header)

            download_content = urlopen(req)

            with NamedTemporaryFile(mode='wb') as fh:
                fh.write(download_content.read())
                with tarfile.open(name=fh.name, mode='r:gz') as tar_file:
                    cacert_filename = [
                        i for i in tar_file.getnames()
                        if path_to_security + cacerts in i
                    ]
                    blacklist_filename = [
                        i for i in tar_file.getnames()
                        if path_to_security + blacklisted in i
                    ]
                    try:
                        s_cacert_filename = cacert_filename[0]
                        s_blacklist_filename = blacklist_filename[0]
                        version = s_cacert_filename[:s_cacert_filename.find(
                            '/')]
                    except Exception as e:
                        raise e

                    blacklist_cert_file = tar_file.extractfile(
                        s_blacklist_filename)
                    cacert_file = tar_file.extractfile(s_cacert_filename)
                    with NamedTemporaryFile(mode='wb') as blacklist:
                        blacklist.write(blacklist_cert_file.read())
                        blacklist.flush()
                        with open(blacklist.name) as blacklisted_file:
                            blacklisted_certs = blacklisted_file.read()

                    with NamedTemporaryFile(mode='wb') as fh2:
                        fh2.write(cacert_file.read())
                        fh2.flush()
                        key_store = jks.KeyStore.load(fh2.name,
                                                      default_password)

        except Exception:
            raise ValueError('Could not fetch file')
        else:
            root_records = self._parse_root_records(
                key_store, should_update_repo, cert_repo)
            blacklisted_records = self._parse_blacklisted_fingerprints(
                blacklisted_certs, should_update_repo, cert_repo)

            trusted_certificates = RootRecordsValidator.validate_with_repository(
                cert_repo, root_records)
            blacklisted_certificates = RootRecordsValidator.validate_with_repository(
                cert_repo, blacklisted_records)

        return TrustStore(PlatformEnum.ORACLE_JAVA, version, url,
                          datetime.utcnow().date(), trusted_certificates,
                          blacklisted_certificates)

    @staticmethod
    def _parse_root_records(key_store: any, should_update_repo: bool,
                            cert_repo: RootCertificatesRepository
                            ) -> List[ScrapedRootCertificateRecord]:
        root_records = []
        for alias, item in key_store.certs.items():
            cert = load_der_x509_certificate(item.cert, default_backend())

            if should_update_repo:
                cert_repo.store_certificate(cert)

            fingerprint = cert.fingerprint(hashes.SHA256())
            subject_name = ''

            try:
                subject_name = cert.subject.get_attributes_for_oid(
                    NameOID.COMMON_NAME)[0].value
            except Exception:
                pass

            if not subject_name:
                try:
                    subject_name = cert.subject.get_attributes_for_oid(
                        NameOID.ORGANIZATION_NAME)[0].value
                except Exception:
                    pass

            root_records.append(
                ScrapedRootCertificateRecord(subject_name, fingerprint,
                                             hashes.SHA256()))

        return root_records

    @classmethod
    def _get_latest_download_url(cls) -> str:

        with urlopen(cls._BASE_URL + cls._DOWNLOADS_INDEX) as response:
            page_content = response.read()
        main_page = BeautifulSoup(page_content, 'html.parser')

        href = main_page.find('img', alt='Download JRE').parent
        latest_download_link = href.get('href')

        with urlopen(cls._BASE_URL + latest_download_link) as download_page:
            download_content = download_page.read()
        latest_download_page = BeautifulSoup(download_content, 'html.parser')

        scripts = latest_download_page.find_all('script')
        download_script = None
        for script in scripts:
            if 'tar.gz' in script.text:
                download_script = script.text
                break
        try:
            filepath = cls._get_file(download_script)
        except ValueError as error:
            print(
                f'Could not parse URL {cls._BASE_URL}{latest_download_link} -- {error}'
            )
        else:
            return filepath

        raise ValueError(
            f'Could not find the store URL at {cls._BASE_URL}{cls._DOWNLOADS_INDEX}'
        )

    @staticmethod
    def _get_file(download_script: str) -> str:
        try:
            start_ind = download_script.rfind('http')
            if start_ind == -1:
                start_ind = download_script.rfind('download.oracle.com')

            end_ind = download_script.rfind('gz') + 2  # add in gz
            filepath = download_script[start_ind:end_ind]

        except Exception:
            raise ValueError('Error parsing download script')
        else:
            return filepath

    @staticmethod
    def _parse_blacklisted_fingerprints(
            raw_certs: str, should_update_repo: bool,
            cert_repo: RootCertificatesRepository
    ) -> List[ScrapedRootCertificateRecord]:
        # first item contains hash algorithm
        fingerprints = [cert for cert in raw_certs.split("\n")[1:] if cert]
        blacklisted_records = []

        for fingerprint in fingerprints:
            blacklisted_records.append(
                ScrapedRootCertificateRecord(
                    '', bytes(bytearray.fromhex(fingerprint)),
                    hashes.SHA256()))

        return blacklisted_records
