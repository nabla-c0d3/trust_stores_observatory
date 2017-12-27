import logging
from typing import Tuple, List

from trust_stores_observatory.certificates_repository import RootCertificatesRepository
from trust_stores_observatory.trust_store import RootCertificateRecord


class RootRecordsValidator:

    @staticmethod
    def validate_with_repository(
            certs_repo: RootCertificatesRepository,
            parsed_root_records: List[Tuple[str, bytes]]
    ) -> List[RootCertificateRecord]:
        """Given a list of subject names and SHA 256 fingerprints scraped from a web page, try to look for each
        certificate in the local certificates repository and if the certificate was found, normalize the subject name
        we use to refer to this certificate.
        """
        validated_root_records = []
        for scraped_subj_name, fingerprint in parsed_root_records:
            try:
                cert = certs_repo.lookup_certificate_with_fingerprint(fingerprint)
                validated_root_records.append(RootCertificateRecord.from_certificate(cert))
            except FileNotFoundError:
                # We have never seen this certificate - use whatever name we scraped from the page
                logging.error(f'Could not find certificate "{scraped_subj_name}"')
                record = RootCertificateRecord.from_scraped_record(scraped_subj_name, fingerprint)
                validated_root_records.append(record)

        return validated_root_records
