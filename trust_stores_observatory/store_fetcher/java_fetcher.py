from typing import Tuple, List
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
from trust_stores_observatory.store_fetcher.store_fetcher_interface import StoreFetcherInterface
from trust_stores_observatory.trust_store import TrustStore, PlatformEnum

import jks
import tarfile

class JavaTrustStoreFetcher(StoreFetcherInterface):
  _BASE_URL = "http://www.oracle.com"
  _DOWNLOADS_INDEX = "/technetwork/java/javase/downloads/index.html"

  def fetch(self, cert_repo: RootCertificatesRepository, should_update_repo: bool=True) -> TrustStore:
    path_to_cacert = '/lib/security/cacerts'
    default_password = 'changeit' #default password for key store
    try:
      cookie_header = {}
      #cookie set when 'Accept License Agreement' is selected
      cookie_header['Cookie'] = 'oraclelicense=accept-securebackup-cookie'
    
      url,version = self._get_latest_download_url()
      
      req = Request(url, headers=cookie_header)

      download_content = urlopen(req)  

      with NamedTemporaryFile(mode='wb') as fh:
        fh.write(download_content.read())
        with tarfile.open(name=fh.name, mode='r:gz') as tar_file:
          cacert_file = tar_file.extractfile(version + path_to_cacert)
          with NamedTemporaryFile(mode='wb') as fh2:
            fh2.write(cacert_file.read()) 
            fh2.flush()
            key_store = jks.KeyStore.load(fh2.name, default_password) 
    except Exception:
      raise ValueError('Could not fetch file')
    else:
      root_records = self._get_root_records(key_store, should_update_repo, cert_repo)
      trusted_certificates = RootRecordsValidator.validate_with_repository(cert_repo, 
                      hashes.SHA256(), root_records)  

    return TrustStore(PlatformEnum.ORACLE_JAVA, version, url, datetime.utcnow().date(), 
                      trusted_certificates)
    
  @staticmethod
  def _get_root_records(key_store, should_update_repo: bool, cert_repo: RootCertificatesRepository) -> List[Tuple[str,bytes]]:
    root_records = [] 
    for alias, sk in key_store.certs.items():
      cert = load_der_x509_certificate(sk.cert, default_backend())

#      if should_update_repo:
#        cert_repo.store_certificate(cert)
    
      fingerprint = cert.fingerprint(hashes.SHA256()) 
      subject_name = ''

      try:
        subject_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
      except Exception:
        pass

      if not subject_name:
        try:
           subject_name = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
        except Exception:
          pass
      
      root_records.append((subject_name, fingerprint))

    return root_records

  @classmethod
  def _get_latest_download_url(cls) -> Tuple[str,str]:

    with urlopen(cls._BASE_URL + cls._DOWNLOADS_INDEX) as response:
      page_content = response.read()
    parsed_page = BeautifulSoup(page_content, 'html.parser')
  
    href = parsed_page.find('img',alt='Download JRE').parent
    latest_download_link = href.get('href') 
    
    with urlopen(cls._BASE_URL + latest_download_link) as download_page:
      download_content = download_page.read()
    parsed = BeautifulSoup(download_content, 'html.parser')

    scripts = parsed.find_all('script')
    download_script = None
    for script in scripts:
      if 'tar.gz' in script.text:
        download_script = script.text
        break
    
    try:
      filepath, version = cls._get_file_and_version(download_script)
    except ValueError as error:
      print(f'Could not parse URL {cls._BASE_URL}{latest_download_link} -- {error}') 
    else:
      return filepath, version

    raise ValueError(f'Could not find the store URL at {cls._BASE_URL}{cls._DOWNLOADS_INDEX}') 

  @staticmethod
  def _get_file_and_version(download_script: str) -> Tuple[str,str]:
    try:
      start_ind = download_script.rfind('http')
      if start_ind == -1:
        start_ind = download_script.rfind('download.oracle.com')

      end_ind = download_script.rfind('gz') + 2
      filepath = download_script[start_ind:end_ind]

      start_ind = filepath.find('jre')
      end_ind = filepath.find('_')
      version = filepath[start_ind:end_ind]
    except:
      raise ValueError('Error parsing download script') 
    else:
      return filepath, version
   
