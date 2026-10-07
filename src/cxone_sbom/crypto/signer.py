from __future__ import annotations
import rfc8785
from joserfc import jwk, jws
from joserfc._rfc7517.models import AsymmetricKey
from typing import BinaryIO, Callable, Dict
from os import PathLike
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519, ed448, ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from base64 import urlsafe_b64encode
from .exceptions import KeyLoadException, UnsupportedKey
from .enums import HashAlgorithm
from .dto import RepositoryInfo
from cxone_sbom.__version__ import __version__
from cxone_sbom.__agent__ import __agent__
from .base import SbomOpBase


class SbomSigner(SbomOpBase):
    """The SbomSigner object is used to produce a signed SBOM.  The static factory
    methods are used to create an instance of the signer.

    """

    @staticmethod
    def __external_ref_scan(scan_url: str) -> Dict:
        return {
            "url": scan_url if scan_url is not None else "",
            "comment": "SCA Scan Results",
            "type": "component-analysis-report",
        }

    @staticmethod
    def __external_ref_repo(info: RepositoryInfo) -> Dict:
        properties = []

        if info.commit is not None:
            properties.append({"name": "commit", "value": info.commit})

        if info.branch is not None:
            properties.append({"name": "branch", "value": info.branch})

        repo = {"url": info.cloneUrl, "type": "vcs"}

        if len(properties) > 0:
            repo["properties"] = properties

        return repo

    @staticmethod
    def __hash_selector(
        requested_hash: HashAlgorithm, imported_key: AsymmetricKey
    ) -> HashAlgorithm:
        if isinstance(imported_key.public_key, ec.EllipticCurvePublicKey):
            return HashAlgorithm(imported_key.curve_name)
        else:
            return requested_hash

    @staticmethod
    def __signing_method_selector(
        inst: SbomSigner, imported_key: AsymmetricKey
    ) -> Callable:

        if isinstance(imported_key.public_key, rsa.RSAPublicKey):
            return inst.__sign_sbom_rsa
        elif isinstance(imported_key.public_key, ec.EllipticCurvePublicKey):
            return inst.__sign_sbom_ec
        elif isinstance(
            imported_key.public_key, ed25519.Ed25519PublicKey
        ) or isinstance(imported_key.public_key, ed448.Ed448PublicKey):
            return inst.__sign_sbom_okp
        else:
            raise UnsupportedKey(imported_key.thumbprint())

    def __validate_sbom(self, sbom: Dict) -> None:
        if "signature" in sbom.keys():
            raise ValueError(
                "Multiple signatures and signature chains are not supported."
            )

    def __get_signature_stub(self, algorithm: str):
        return {
            "algorithm": algorithm,
            "keyId": self.__public_key.thumbprint(),
            "publicKey": self.__public_key.as_dict(),
            "certificatePath": [
                urlsafe_b64encode(self.__cert.public_bytes(Encoding.DER))
                .rstrip(b"=")
                .decode("UTF-8")
            ],
        }

    def __modify_sbom(
        self,
        sbom: Dict,
        scanUrl: str | None = None,
        repository: RepositoryInfo | None = None,
    ) -> Dict:

        new_sbom = SbomSigner._duplicate_sbom(sbom)

        new_sbom["version"] = new_sbom.get("version", 0) + 1

        if not new_sbom.get("metadata"):
            new_sbom["metadata"] = {}

        if not new_sbom["metadata"].get("tools"):
            new_sbom["metadata"]["tools"] = {}

        if not new_sbom["metadata"]["tools"].get("components"):
            new_sbom["metadata"]["tools"]["components"] = []

        new_sbom["metadata"]["tools"]["components"].append(
            {
                "type": "application",
                "publisher": "Checkmarx Professional Services",
                "name": __agent__,
                "version": __version__,
                "isExternal": True,
            }
        )

        if scanUrl is not None:
            if not new_sbom.get("externalReferences"):
                new_sbom["externalReferences"] = []

            new_sbom["externalReferences"].append(self.__external_ref_scan(scanUrl))

        if repository is not None and repository.cloneUrl is not None:
            if not new_sbom.get("externalReferences"):
                new_sbom["externalReferences"] = []

            new_sbom["externalReferences"].append(self.__external_ref_repo(repository))

        return new_sbom

    def __sign_sbom_rsa(
        self,
        sbom: Dict,
        hash: HashAlgorithm,
    ) -> Dict:

        # Try PSS padding first
        redo_with_pkcs = False
        try:
            algorithm = f"PS{hash.name[3:]}"
            sbom["signature"] = self.__get_signature_stub(algorithm)

            sbom["signature"]["value"] = (
                urlsafe_b64encode(
                    jws.JWSRegistry.algorithms[algorithm].sign(
                        rfc8785.dumps(sbom), self.__private
                    )
                )
                .rstrip(b"=")
                .decode("UTF-8")
            )
        except Exception as ex:
            redo_with_pkcs = True

        if redo_with_pkcs:
            # Use PKCS padding if PSS has an issue
            algorithm = f"RS{hash.name[3:]}"
            sbom["signature"] = self.__get_signature_stub(algorithm)

            sbom["signature"]["value"] = (
                urlsafe_b64encode(
                    jws.JWSRegistry.algorithms[algorithm].sign(
                        rfc8785.dumps(sbom), self.__private
                    )
                )
                .rstrip(b"=")
                .decode("UTF-8")
            )

        return sbom

    def __sign_sbom_ec(self, sbom: Dict, hash: HashAlgorithm) -> Dict:

        algorithm = f"ES{hash.name[3:]}"

        sbom["signature"] = self.__get_signature_stub(algorithm)

        sbom["signature"]["value"] = (
            urlsafe_b64encode(
                jws.JWSRegistry.algorithms[algorithm].sign(
                    rfc8785.dumps(sbom), self.__private
                )
            )
            .rstrip(b"=")
            .decode("UTF-8")
        )

        return sbom

    def __sign_sbom_okp(
        self,
        sbom: Dict,
        hash: HashAlgorithm,
    ) -> Dict:

        if isinstance(self.__cert.public_key(), ed25519.Ed25519PublicKey):
            algorithm = "Ed25519"

        elif isinstance(self.__cert.public_key(), ed448.Ed448PublicKey):
            algorithm = "Ed448"
        else:
            raise UnsupportedKey(self.__public_key.thumbprint())

        sbom["signature"] = self.__get_signature_stub(algorithm)

        sbom["signature"]["value"] = (
            urlsafe_b64encode(
                jws.JWSRegistry.algorithms[algorithm].sign(
                    rfc8785.dumps(sbom), self.__private
                )
            )
            .rstrip(b"=")
            .decode("UTF-8")
        )

        return sbom

    def sign_sbom(
        self,
        sbom: Dict,
        scanUrl: str | None = None,
        repository: RepositoryInfo | None = None,
    ) -> Dict:
        """Sign an SBOM, optionally adding scan and repository external references.

        :param sbom: The SBOM document to sign.
        :type sbom: Dict
        :param scanUrl: A URL to the scan results to add as an external reference.
        :type scanUrl: str | None
        :param repository: Repository information to add as an external reference.
        :type repository: RepositoryInfo | None
        :return: A new SBOM document containing the added signature.
        :rtype: Dict
        :raises ValueError: If the SBOM already contains a ``signature`` entry.
        """
        self.__validate_sbom(sbom)
        new_sbom = self.__modify_sbom(sbom, scanUrl, repository)
        return self.__sign_method(new_sbom, self.__hash)

    @staticmethod
    def from_cert_bundle(
        x509pem: str | PathLike[str] | BinaryIO | bytes,
        password: str | bytes | None = None,
        hash: HashAlgorithm = HashAlgorithm.SHA256,
    ) -> SbomSigner:
        """Create an :class:`SbomSigner` from a PEM bundle containing both the
        certificate and the private key.

        :param x509pem: A path, file-like object, or raw bytes containing the PEM
            encoded certificate and private key bundle.
        :type x509pem: str | PathLike[str] | BinaryIO | bytes
        :param password: The password protecting the private key, if encrypted.
        :type password: str | bytes | None
        :param hash: The hash algorithm to use when signing, if applicable to the key type.
        :type hash: HashAlgorithm
        :return: A new signer instance ready to sign SBOMs.
        :rtype: SbomSigner
        :raises KeyLoadException: If the certificate or private key cannot be loaded.
        :raises UnsupportedKey: If the key type is not supported.
        """
        try:
            key_data = SbomSigner._load_data(x509pem)

            inst = SbomSigner()
            inst.__cert = load_pem_x509_certificate(key_data)
            inst.__public_key = jwk.import_key(
                inst.__cert.public_key(),
                SbomSigner._get_key_type(inst.__cert.public_key()),
            )

            inst.__hash = SbomSigner.__hash_selector(hash, inst.__public_key)

            assert inst.__public_key.as_dict()

            inst.__private = inst.__public_key.import_key(
                load_pem_private_key(key_data, SbomSigner._password(password))
            )

            inst.__sign_method = SbomSigner.__signing_method_selector(
                inst, inst.__public_key
            )

            return inst
        except TypeError as tex:
            raise KeyLoadException(str(tex))
        except KeyLoadException:
            raise
        except Exception as ex:
            raise UnsupportedKey(ex)

    @staticmethod
    def from_cert_files(
        x509pem: str | PathLike[str] | BinaryIO | bytes,
        private_key_pem: str | PathLike[str] | BinaryIO | bytes,
        password: str | bytes | None = None,
        hash: HashAlgorithm = HashAlgorithm.SHA256,
    ) -> SbomSigner:
        """Create an :class:`SbomSigner` from separate certificate and private key files.

        :param x509pem: A path, file-like object, or raw bytes containing the PEM
            encoded certificate.
        :type x509pem: str | PathLike[str] | BinaryIO | bytes
        :param private_key_pem: A path, file-like object, or raw bytes containing the
            PEM encoded private key.
        :type private_key_pem: str | PathLike[str] | BinaryIO | bytes
        :param password: The password protecting the private key, if encrypted.
        :type password: str | bytes | None
        :param hash: The hash algorithm to use when signing, if applicable to the key type.
        :type hash: HashAlgorithm
        :return: A new signer instance ready to sign SBOMs.
        :rtype: SbomSigner
        :raises KeyLoadException: If the certificate or private key cannot be loaded.
        :raises UnsupportedKey: If the key type is not supported.
        """
        try:
            public_key_data = SbomSigner._load_data(x509pem)
            private_key_data = SbomSigner._load_data(private_key_pem)

            inst = SbomSigner()
            inst.__cert = load_pem_x509_certificate(public_key_data)
            inst.__public_key = jwk.import_key(
                inst.__cert.public_key(),
                SbomSigner._get_key_type(inst.__cert.public_key()),
            )

            assert inst.__public_key.as_dict()

            inst.__private = inst.__public_key.import_key(
                load_pem_private_key(private_key_data, SbomSigner._password(password))
            )

            inst.__sign_method = SbomSigner.__signing_method_selector(
                inst, inst.__public_key
            )

            inst.__hash = SbomSigner.__hash_selector(hash, inst.__public_key)
            return inst
        except TypeError as tex:
            raise KeyLoadException(str(tex))
        except KeyLoadException:
            raise
        except Exception as ex:
            raise UnsupportedKey(ex)
