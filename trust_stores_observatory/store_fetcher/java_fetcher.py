import os
from datetime import datetime
from urllib.request import Request, urlopen

import jks
from bs4 import BeautifulSoup
from urllib.error import HTTPError
import logging

from tempfile import NamedTemporaryFile
from trust_stores_observatory.certificates_repository import RootCertificatesRepository
from trust_stores_observatory.store_fetcher.root_records_validator import (
    RootRecordsValidator,
)
from trust_stores_observatory.store_fetcher.store_fetcher_interface import (
    StoreFetcherInterface,
)
from trust_stores_observatory.trust_store import PlatformEnum, TrustStore

from trust_stores_observatory.store_fetcher.jdk_helper import JdkPackage


class JavaTrustStoreFetcher(StoreFetcherInterface):
    _BASE_URL = "https://www.oracle.com"
    _DOWNLOADS_INDEX = "/technetwork/java/javase/downloads/index.html"

    def fetch(self, cert_repo: RootCertificatesRepository, should_update_repo: bool = True) -> TrustStore:
        # Fetch the latest JDK package
        final_url = self._get_latest_download_url()
        request = Request(
            final_url,
            # Cookie set when 'Accept License Agreement' is selected
            headers={"Cookie": "oraclelicense=accept-securebackup-cookie"},
        )
        response = urlopen(request)

        # Parse the JDK package
        jdk_temp_file = NamedTemporaryFile(delete=False)
        try:
            jdk_temp_file.write(response.read())
            jdk_temp_file.close()
            with JdkPackage(jdk_temp_file.name) as parsed_jre:
                # Extract the data we need
                version = parsed_jre.get_version()
                blacklisted_file_content = parsed_jre.get_blacklisted_certs()
                cacerts_key_store = jks.KeyStore.loads(parsed_jre.get_cacerts(), parsed_jre.get_cacerts_password())
        finally:
            os.remove(jdk_temp_file.name)

        # Process the data extracted from the JRE
        # Trusted CA certs
        scraped_trusted_records = JdkPackage.extract_trusted_root_records(
            cacerts_key_store, should_update_repo, cert_repo
        )
        trusted_records = RootRecordsValidator.validate_with_repository(cert_repo, scraped_trusted_records)

        # Blacklisted CA certs - will fail if a blacklisted cert is not already available in the local repo
        scraped_blacklisted_records = JdkPackage.extract_blacklisted_root_records(blacklisted_file_content)
        blacklisted_records = RootRecordsValidator.validate_with_repository(cert_repo, scraped_blacklisted_records)

        return TrustStore(
            PlatformEnum.ORACLE_JAVA,
            version,
            final_url,
            datetime.utcnow().date(),
            trusted_records,
            blacklisted_records,
        )

    @classmethod
    def _get_latest_download_url(cls) -> str:
        # Parse the main download page - rety 3 times as it sometimes fail on CI
        for _ in range(3):
            try:
                with urlopen(cls._BASE_URL + cls._DOWNLOADS_INDEX) as response:
                    page_content = response.read()
                main_page = BeautifulSoup(page_content, "html.parser")
                break
            except HTTPError:
                # Retry
                logging.info("HTTP error when fetching the download URL for Oracle; retrying...")
                pass

        # Find the link to the latest JRE's download page
        download_jdk_img_tag = main_page.find("img", alt="Download JDK")
        assert download_jdk_img_tag

        href_tag = download_jdk_img_tag.parent
        assert href_tag

        latest_download_link = href_tag.get("href")
        assert isinstance(latest_download_link, str)

        with urlopen(cls._BASE_URL + latest_download_link) as download_page:
            latest_download_page = download_page.read().decode("utf-8")

        # The final download link for the .tar.gz JRE package is in a script tag
        jre_download_url = latest_download_page.split('linux-x64_bin.tar.gz"')[0].rsplit("download.oracle.com", 1)[1]
        final_download_url = f"http://download.oracle.com{jre_download_url}linux-x64_bin.tar.gz"
        return final_download_url
