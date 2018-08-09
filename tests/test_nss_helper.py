import os
import unittest
from pathlib import Path

from trust_stores_observatory.nss_helper import CertdataEntryServerAuthTrustEnum, CertdataCertificateEntry, \
    CertdataTrustEntry, parse_certdata


class NssHelperTests(unittest.TestCase):

    def test_mozilla_scraping(self):
        # Given a Mozilla certdata file
        certdata_path = Path(os.path.abspath(os.path.dirname(__file__))) / 'bin' / 'mozilla_certdata.txt'
        with open(certdata_path) as certdata_file:
            certdata_content = certdata_file.read()

        # When scraping it
        certdata_entries = parse_certdata(certdata_content)

        # It returns the correct entries
        self.assertEqual(len(certdata_entries), 319)

        certificate_entries = [entry for entry in certdata_entries if isinstance(entry, CertdataCertificateEntry)]
        self.assertEqual(len(certificate_entries), 157)

        trust_entries = [entry for entry in certdata_entries if isinstance(entry, CertdataTrustEntry)]
        self.assertEqual(len(trust_entries), 162)

        trusted_trust_entries = [entry for entry in trust_entries
                                 if entry.trust_enum == CertdataEntryServerAuthTrustEnum.TRUSTED]
        self.assertEqual(len(trusted_trust_entries), 138)

        not_trusted_trust_entries = [entry for entry in trust_entries
                                     if entry.trust_enum == CertdataEntryServerAuthTrustEnum.NOT_TRUSTED]
        self.assertEqual(len(not_trusted_trust_entries), 7)

        must_verify_trust_entries = [entry for entry in trust_entries
                                     if entry.trust_enum == CertdataEntryServerAuthTrustEnum.MUST_VERIFY]
        self.assertEqual(len(must_verify_trust_entries), 17)

    def test_ubuntu_scraping(self):

        certdata_path = Path(os.path.abspath(os.path.dirname(__file__))) / 'bin' / 'ubuntu_certdata.txt'
        with open(certdata_path) as certdata_file:
            certdata_content = certdata_file.read()

        # Parse data
        certdata_entries = parse_certdata(certdata_content)
        # Ensure the correct entries are returned
        self.assertEqual(len(certdata_entries), 311)

        # CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE entry
        certificate_entries = [entry for entry in certdata_entries if isinstance(entry, CertdataCertificateEntry)]
        self.assertEqual(len(certificate_entries), 153)

        # CKA_CLASS CK_OBJECT_CLASS CKO_NSS_TRUST entry
        trust_entries = [entry for entry in certdata_entries if isinstance(entry, CertdataTrustEntry)]
        # 160 total entries with two missing a fingerprint
        self.assertEqual(len(trust_entries), 158)

        trusted_trust_entries = [entry for entry in trust_entries
                                 if entry.trust_enum == CertdataEntryServerAuthTrustEnum.TRUSTED]
        self.assertEqual(len(trusted_trust_entries), 133)

        not_trusted_trust_entries = [entry for entry in trust_entries
                                     if entry.trust_enum == CertdataEntryServerAuthTrustEnum.NOT_TRUSTED]
        self.assertEqual(len(not_trusted_trust_entries), 7)

        must_verify_trust_entries = [entry for entry in trust_entries
                                     if entry.trust_enum == CertdataEntryServerAuthTrustEnum.MUST_VERIFY]
        self.assertEqual(len(must_verify_trust_entries), 18)
