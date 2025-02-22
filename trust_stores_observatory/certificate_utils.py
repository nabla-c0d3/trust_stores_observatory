from cryptography.x509 import ObjectIdentifier, Name, Certificate, NameOID


class CertificateUtils:
    @staticmethod
    def _get_names_with_oid(name_field: Name, name_oid: ObjectIdentifier) -> list[str]:
        all_names_values = []
        for cn in name_field.get_attributes_for_oid(name_oid):
            assert isinstance(cn.value, str)
            all_names_values.append(cn.value)
        return all_names_values

    @classmethod
    def _get_name_as_text(cls, name_field: Name) -> str:
        return ", ".join([f"{attr.rfc4514_string()}={attr.value}" for attr in name_field])  # type: ignore

    @classmethod
    def get_canonical_subject_name(cls, certificate: Certificate) -> str:
        """Compute the certificate's canonical name.

        This string is what we use in the serialized YAML trust stores. It should more or less follow Apple's logic
        for the subject names they display on the pages at https://support.apple.com/en-us/HT204132.
        """
        name_field = certificate.subject
        # If everything fails, we return the whole Subject field
        final_name = cls._get_name_as_text(name_field)
        # Return CN if there is one
        common_names = cls._get_names_with_oid(name_field, NameOID.COMMON_NAME)
        if common_names:
            # We don't support certs with multiple CNs
            final_name = common_names[0]
        else:
            # Otherwise try the Organization Unit Name
            orgun_names = cls._get_names_with_oid(name_field, NameOID.ORGANIZATIONAL_UNIT_NAME)
            if orgun_names:
                final_name = orgun_names[0]
            else:
                # Otherwise try the Organization
                org_names = cls._get_names_with_oid(name_field, NameOID.ORGANIZATION_NAME)
                if org_names:
                    final_name = org_names[0]

        return final_name.strip()
