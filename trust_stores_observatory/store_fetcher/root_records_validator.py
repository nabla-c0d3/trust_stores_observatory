import logging
from typing import List, Set

from trust_stores_observatory.certificates_repository import RootCertificatesRepository, CertificateNotFoundError
from trust_stores_observatory.store_fetcher.scraped_root_record import ScrapedRootCertificateRecord
from trust_stores_observatory.root_record import RootCertificateRecord


class RootRecordsValidator:
    """Given a list of subject names and SHA 256 fingerprints scraped from a web page, try to look for each
    certificate in the local certificates repository and if the certificate was found, normalize the subject name
    we use to refer to this certificate.
    """

    @staticmethod
    def validate_with_repository(
        certs_repo: RootCertificatesRepository, scraped_records: List[ScrapedRootCertificateRecord]
    ) -> Set[RootCertificateRecord]:
        validated_root_records = set()

        # For each (subj_name, fingerprint) try to find the corresponding certificate in the supplied cert repo
        for scraped_record in scraped_records:
            try:
                cert = certs_repo.lookup_certificate_with_fingerprint(
                    scraped_record.fingerprint, scraped_record.fingerprint_hash_algorithm
                )
                validated_root_records.add(RootCertificateRecord.from_certificate(cert))
            except CertificateNotFoundError:
                # We have never seen this certificate - use whatever name we scraped from the page
                logging.error(f'Could not find certificate "{scraped_record.subject_name}" in local repository')
                record = RootCertificateRecord.from_unknown_record(scraped_record)
                validated_root_records.add(record)
            except ValueError as e:
                if "Unsupported ASN1 string type" in e.args[0]:
                    # Could not parse the certificate: https://github.com/pyca/cryptography/issues/3542
                    logging.error(f'Parsing error for certificate "{scraped_record.subject_name}"')
                    # Give up and just use the scraped name
                    record = RootCertificateRecord.from_unknown_record(scraped_record)
                    validated_root_records.add(record)
                else:
                    raise

        return validated_root_records
