from typing import Tuple, List
from tempfile import NamedTemporaryFile
import subprocess
import re
import tarfile
from datetime import datetime
from urllib.parse import urljoin
from urllib.request import urlopen
from urllib.request import urlretrieve
from urllib.request import Request

from bs4 import BeautifulSoup
from cryptography.hazmat.primitives import hashes

from trust_stores_observatory.certificates_repository import RootCertificatesRepository
from trust_stores_observatory.store_fetcher.root_records_validator import RootRecordsValidator
from trust_stores_observatory.store_fetcher.store_fetcher_interface import StoreFetcherInterface
from trust_stores_observatory.trust_store import TrustStore, PlatformEnum

class JavaTrustStoreFetcher(StoreFetcherInterface):
  _BASE_URL = "http://www.oracle.com"
  _DOWNLOADS_INDEX = "/technetwork/java/javase/downloads/index.html"

  def fetch(self, cert_repo: RootCertificatesRepository, should_update_report: bool=True) -> TrustStore:
    path_to_cacert = '/lib/security/cacerts'
    try:
      headers = {}
      headers['User-Agent'] = "Mozilla/5.0 Gecko/2010 Firefox/5"
      headers['Accept'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
      headers['Accept-Language'] = 'en-us,en;q=0.5'
      headers['Accept-Encoding'] = 'gzip, deflate'
      #cookie set when 'Accept License Agreement' is selected
      headers['Cookie'] = 'oraclelicense=accept-securebackup-cookie'
    
      url,version_num = self._get_latest_package_url()
      
      req = Request(url, headers=headers)

      download_content = urlopen(req)  
      with NamedTemporaryFile(mode='wb') as fh:
        fh.write(download_content.read())
        with tarfile.open(name=fh.name, mode='r:gz') as tar_file:
          cacert_file = tar_file.extractfile('jre-'+version_num+path_to_cacert)
          with NamedTemporaryFile(mode='wb') as fh2:
            fh2.write(cacert_file.read()) 
            fh2.flush()
            result = subprocess.run(['keytool', '-list', '-v', '-keystore', fh2.name], stdout=subprocess.PIPE, input=b'')
            result = result.stdout.decode('utf-8')
    except Exception as inst:
      raise ValueError('Could not fetch file')
    else:
      parsed_root_records = self._get_root_records(result)
      trusted_certificates = RootRecordsValidator.validate_with_repository(cert_repo, hashes.SHA256(), parsed_root_records)  
  
    return TrustStore(PlatformEnum.ORACLE_JAVA, version_num, url, datetime.utcnow().date(), 
                      trusted_certificates)
    
  @staticmethod
  def _get_root_records(raw_file: str) -> List[Tuple[str,bytes]]:
    # asterisks seperate each certificate record
    result = re.split(r'\*+', raw_file)
    root_records = []

    for item in result:
      owner_index = item.find('Owner')
      if owner_index != -1:
        n = item[owner_index:]
        m = n.split('\n')
        owner_name = m[0]
        potential_subject = re.search('((?:CN=|OU=)([^,]+),?)',owner_name)
        if potential_subject is not None:
          subject_name = potential_subject.group(2)
        fingerprint = None
        for inner in m:
          if 'SHA256' not in inner:
            continue
          fingerprint_hex = re.search('(?<=SHA256:)(.+)', inner)
          if fingerprint_hex is not None:
            fingerprint_hex = fingerprint_hex.group(0).replace(':', '').strip()
            fingerprint = bytes(bytearray.fromhex(fingerprint_hex))
            break

        root_records.append((subject_name, fingerprint))
    return root_records  

  @classmethod
  def _get_latest_package_url(cls) -> Tuple[str,str]:

    with urlopen(cls._BASE_URL + cls._DOWNLOADS_INDEX) as response:
      page_content = response.read()
    parsed_page = BeautifulSoup(page_content, 'html.parser')

    href = parsed_page.find('img',alt='Download JRE').parent
    latest_link = href.get('href')

    with urlopen(cls._BASE_URL+latest_link) as download_page:
      download_content = download_page.read()
    parsed = BeautifulSoup(download_content, 'html.parser')

    #table is populated dynamically so we need to use regex to extract link
    download_array = re.findall("downloads\[.+\]", str(parsed))
    tar_files = [p for p in download_array if p.endswith("tar.gz']")]
    potential_target_file = tar_files[-1]
    potential_target_file = re.search("\['files'\]\['(.+tar\.gz)'", potential_target_file)
    if potential_target_file is not None:
      link = potential_target_file.group(1)
      potential_filepath = re.search('.+'+link, str(parsed))
      potential_filepath = potential_filepath.group(0)
      version = re.search("jre-(\w+\.\w+\.\w+)", potential_filepath).group(1)
      filepath = re.search("(?<=\"filepath\":)(.+)", potential_filepath)
      filepath = filepath.group(0).replace('"', '')
      return filepath, version
  
    raise ValueError(f'Could not find the store URL at {cls._BASE_URL}{cls._DOWNLOADS_INDEX}') 

