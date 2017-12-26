from typing import List

from cryptography.x509 import NameOID, Name


class CertificateUtils:

    @staticmethod
    def get_common_names(name_field: Name) -> List[str]:
        return [cn.value for cn in name_field.get_attributes_for_oid(NameOID.COMMON_NAME)]

    @classmethod
    def get_name_as_text(cls, name_field: Name) -> str:
        return ', '.join(['{}={}'.format(attr.oid._name, attr.value) for attr in name_field])

    @classmethod
    def get_name_as_short_text(cls, name_field: Name) -> str:
        """Convert a name field returned by the cryptography module to a string suitable for displaying it to the user.
        """
        # Name_field is supposed to be a Subject or an Issuer; print the CN if there is one
        common_names = cls.get_common_names(name_field)
        if common_names:
            # We don't support certs with multiple CNs
            return common_names[0]
        else:
            # Otherwise show the whole field
            return cls.get_name_as_text(name_field)
