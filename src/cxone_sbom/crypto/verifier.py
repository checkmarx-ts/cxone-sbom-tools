from __future__ import annotations
import json, rfc8785
from datetime import datetime, timezone
from cryptography import x509
from cryptography.x509.verification import (
    Criticality,
    ExtensionPolicy,
    PolicyBuilder,
    Store,
    VerificationError,
)
from joserfc import jwk, jws
from joserfc.errors import InvalidKeyTypeError
from pathlib import PurePath, Path
from typing import Dict
from typing import BinaryIO
from os import PathLike
from base64 import urlsafe_b64decode
from cryptography.x509 import (
    load_pem_x509_certificate,
    load_pem_x509_certificates,
    load_der_x509_certificate,
    Certificate,
)
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError
from .base import SbomOpBase
from .exceptions import KeyLoadException
from .enums import ValidationResult


class SbomVerifier(SbomOpBase):
    """The SbomVerifier object is used to verify the signature of a signed SBOM and if the
    signer should be trusted.
    """

    @staticmethod
    def __decode(urlencoded_base64: str) -> bytes:
        return urlsafe_b64decode(
            urlencoded_base64 + "=" * (-len(urlencoded_base64) % 4)
        )

    @staticmethod
    def __validate_sbom(sbom: Dict) -> None:

        if sbom is None:
            raise ValueError("Invalid SBOM")

        if "signature" in sbom.keys() and (
            sbom["signature"].get("chain") or sbom["signature"].get("signers")
        ):
            raise ValueError(
                "Multiple signatures and signature chains are not supported."
            )

    @staticmethod
    def _load_sbom(sbom: Dict | PathLike[str] | BinaryIO) -> Dict:
        loaded_sbom = None

        if isinstance(sbom, dict):
            loaded_sbom = sbom
        elif SbomOpBase._is_io(sbom):
            loaded_sbom = json.load(sbom)
        elif isinstance(sbom, (str, PurePath)) and Path(sbom).is_file():
            with open(sbom, "rt") as sb:
                loaded_sbom = json.load(sb)

        SbomVerifier.__validate_sbom(loaded_sbom)
        return loaded_sbom

    def signature_validates(
        self, sbom: Dict | PathLike[str] | BinaryIO
    ) -> ValidationResult:
        """Validate the signature of a signed SBOM against this verifier's public key.

        :param sbom: The signed SBOM document, or a path/file-like object referencing it.
        :type sbom: Dict | PathLike[str] | BinaryIO
        :return: The outcome of the signature validation.
        :rtype: ValidationResult
        :raises ValueError: If the SBOM is invalid or contains an unsupported signature format.
        """
        new_sbom = SbomVerifier._duplicate_sbom(SbomVerifier._load_sbom(sbom))
        encoded_signature = new_sbom["signature"]["value"]
        del new_sbom["signature"]["value"]
        canonicalized = rfc8785.dumps(new_sbom)
        algorithm = new_sbom["signature"]["algorithm"]

        signature_valid = jws.JWSRegistry.algorithms[algorithm].verify(
            canonicalized,
            SbomVerifier.__decode(encoded_signature),
            self.__public_key,
        )

        if signature_valid:
            return (
                ValidationResult.VALIDATION_SUCCESS
                if not self.__notrust
                else ValidationResult.UNTRUSTED_VALIDATION_SUCCESS
            )
        else:
            return ValidationResult.VALIDATION_FAIL

    @staticmethod
    def __is_cert_trusted(
        x509cert: Certificate,
        ca_bundle_pem: str | PathLike[str] | BinaryIO | bytes | None = None,
        intermediates_bundle_pem: str | PathLike[str] | BinaryIO | bytes | None = None,
    ) -> bool:
        if ca_bundle_pem is not None:
            ca_certs = load_pem_x509_certificates(
                SbomVerifier._load_data(ca_bundle_pem)
            )
        else:
            return False

        _EE_POLICY = ExtensionPolicy.permit_all()
        _CA_POLICY = ExtensionPolicy.permit_all().require_present(
            x509.BasicConstraints, Criticality.AGNOSTIC, None
        )

        roots = [c for c in ca_certs if c.subject == c.issuer]
        inters = [c for c in ca_certs if c.subject != c.issuer]

        if intermediates_bundle_pem is not None:
            for cert_entry in load_pem_x509_certificates(
                SbomVerifier._load_data(intermediates_bundle_pem)
            ):
                if cert_entry.subject != cert_entry.issuer:
                    inters.append(cert_entry)
                elif cert_entry.subject == cert_entry.issuer:
                    roots.append(cert_entry)

        verifier = (
            PolicyBuilder()
            .store(Store(roots))
            .extension_policies(ee_policy=_EE_POLICY, ca_policy=_CA_POLICY)
            .time(datetime.now(timezone.utc))
            .build_client_verifier()
        )
        try:
            return verifier.verify(x509cert, inters).chain is not None
        except VerificationError:
            return False

    @staticmethod
    def from_cert_file(
        x509pem: str | PathLike[str] | BinaryIO | bytes,
        *,
        ca_bundle_pem: str | PathLike[str] | BinaryIO | bytes | None = None,
        intermediate_bundle_pem: str | PathLike[str] | BinaryIO | bytes | None = None,
    ) -> SbomVerifier:
        """Create an :class:`SbomVerifier` using a signer's public key from a certificate file.

        :param x509pem: A path, file-like object, or raw bytes containing the PEM
            encoded certificate holding the signer's public key.
        :type x509pem: str | PathLike[str] | BinaryIO | bytes
        :param ca_bundle_pem: A path, file-like object, or raw bytes containing one or
            more PEM encoded trusted root CA certificates, used to establish trust in
            the signer's certificate.
        :type ca_bundle_pem: str | PathLike[str] | BinaryIO | bytes | None
        :param intermediate_bundle_pem: A path, file-like object, or raw bytes containing
            one or more PEM encoded trusted intermediate CA certificates.
        :type intermediate_bundle_pem: str | PathLike[str] | BinaryIO | bytes | None
        :return: A new verifier instance.
        :rtype: SbomVerifier
        :raises KeyLoadException: If the certificate or bundles cannot be loaded.
        """
        try:
            assert x509pem is not None and SbomOpBase._key_load_input_valid(x509pem)
            assert ca_bundle_pem is None or SbomOpBase._key_load_input_valid(
                ca_bundle_pem
            )
            assert intermediate_bundle_pem is None or SbomOpBase._key_load_input_valid(
                intermediate_bundle_pem
            )

            inst = SbomVerifier()
            inst.__cert = load_pem_x509_certificate(SbomVerifier._load_data(x509pem))

            if ca_bundle_pem is not None:
                inst.__notrust = not SbomVerifier.__is_cert_trusted(
                    inst.__cert, ca_bundle_pem, intermediate_bundle_pem
                )
            else:
                inst.__notrust = True

            inst.__public_key = jwk.import_key(
                inst.__cert.public_key(),
                SbomVerifier._get_key_type(inst.__cert.public_key()),
            )

            return inst
        except AssertionError:
            raise KeyLoadException()
        except Exception as ex:
            raise KeyLoadException(ex)

    @staticmethod
    def from_embedded_key(sbom: str | Dict | PathLike[str] | BinaryIO) -> SbomVerifier:
        """Create an :class:`SbomVerifier` using the public key embedded in the SBOM's signature.

        The resulting verifier never establishes trust in the signer, since no
        certificate or CA information is used.

        :param sbom: The signed SBOM document, or a path/file-like object referencing it.
        :type sbom: str | Dict | PathLike[str] | BinaryIO
        :return: A new verifier instance.
        :rtype: SbomVerifier
        :raises KeyLoadException: If no usable public key is found in the SBOM, or its
            key type is unsupported.
        """
        try:
            assert sbom is not None
            assert SbomOpBase._sbom_load_input_valid(sbom)

            inst = SbomVerifier()
            inst.__cert = None
            inst.__notrust = True

            loaded_sbom = SbomVerifier._load_sbom(sbom)
            inst.__public_key = jwk.import_key(
                loaded_sbom.get("signature", {}).get("publicKey")
            )

            return inst
        except InvalidKeyTypeError:
            raise KeyLoadException.unsupported_key(
                loaded_sbom.get("signature", {}).get("publicKey", {}).get("algorithm")
            )
        except ValueError:
            raise KeyLoadException.public_key_not_in_sbom()

    @staticmethod
    def from_embedded_cert(
        sbom: str | Dict | PathLike[str] | BinaryIO,
        *,
        ca_bundle_pem: str | PathLike[str] | BinaryIO | bytes | None = None,
        intermediate_bundle_pem: str | PathLike[str] | BinaryIO | bytes | None = None,
    ) -> SbomVerifier:
        """Create an :class:`SbomVerifier` using the signing certificate embedded in the SBOM.

        :param sbom: The signed SBOM document, or a path/file-like object referencing it.
        :type sbom: str | Dict | PathLike[str] | BinaryIO
        :param ca_bundle_pem: A path, file-like object, or raw bytes containing one or
            more PEM encoded trusted root CA certificates, used to establish trust in
            the embedded signing certificate.
        :type ca_bundle_pem: str | PathLike[str] | BinaryIO | bytes | None
        :param intermediate_bundle_pem: A path, file-like object, or raw bytes containing
            one or more PEM encoded trusted intermediate CA certificates.
        :type intermediate_bundle_pem: str | PathLike[str] | BinaryIO | bytes | None
        :return: A new verifier instance.
        :rtype: SbomVerifier
        :raises KeyLoadException: If the embedded certificate path is missing or empty,
            or the certificate/bundles cannot be loaded.
        """
        try:
            assert sbom is not None
            assert SbomOpBase._sbom_load_input_valid(sbom)
            assert ca_bundle_pem is None or SbomOpBase._key_load_input_valid(
                ca_bundle_pem
            )
            assert intermediate_bundle_pem is None or SbomOpBase._key_load_input_valid(
                intermediate_bundle_pem
            )

            inst = SbomVerifier()
            loaded_sbom = SbomVerifier._load_sbom(sbom)

            if (not "certificatePath" in loaded_sbom["signature"].keys()) or (
                len(loaded_sbom["signature"]["certificatePath"]) == 0
            ):
                raise KeyLoadException.public_key_not_in_sbom()

            # First cert in path is supposed to be signer according to CycloneDX 1.7 standard
            # The standard also wants the cert DER encoded.
            inst.__cert = load_der_x509_certificate(
                SbomVerifier.__decode(loaded_sbom["signature"]["certificatePath"][0])
            )

            if ca_bundle_pem is not None:
                inst.__notrust = not SbomVerifier.__is_cert_trusted(
                    inst.__cert, ca_bundle_pem, intermediate_bundle_pem
                )
            else:
                inst.__notrust = True

            inst.__public_key = jwk.import_key(
                inst.__cert.public_key(),
                SbomVerifier._get_key_type(inst.__cert.public_key()),
            )

            return inst
        except AssertionError as ex:
            raise KeyLoadException(ex)
