from cryptography.hazmat.primitives import hashes
from aenum import MultiValueEnum
from enum import Enum
from .exceptions import UnsupportedAlgorithm


class SupportedAlgorithms(MultiValueEnum):
    """Enumerates the JWS signing algorithms supported for SBOM signatures.

    Members may be looked up by their JWS algorithm name, and for EC-based
    algorithms, additionally by their curve name (e.g. ``"P-256"``).

    :raises UnsupportedAlgorithm: If a value not matching any member is looked up.
    """

    RS256 = "RS256"
    RS384 = "RS384"
    RS512 = "RS512"
    PS256 = "PS256"
    PS384 = "PS384"
    PS512 = "PS512"
    ES256 = "ES256", "P-256"
    ES384 = "ES384", "P-384"
    ES512 = "ES512", "P-521"
    Ed25519 = "Ed25519"
    Ed448 = "Ed448"

    @classmethod
    def _missing_(cls, value):
        raise UnsupportedAlgorithm(str(value))


class HashAlgorithm(MultiValueEnum):
    """Enumerates the supported SHA hash algorithms used when signing an SBOM.

    Members may be looked up by their :mod:`cryptography` hash instance, by
    the EC curve name they correspond to (e.g. ``"P-256"``), or by their
    digest length as a string (e.g. ``"256"``).
    """

    SHA256 = hashes.SHA256(), "P-256", "256"
    SHA384 = hashes.SHA384(), "P-384", "384"
    SHA512 = hashes.SHA512(), "P-521", "512"


class ValidationResult(Enum):
    """Enumerates the possible outcomes of validating a signed SBOM's signature.

    :cvar VALIDATION_SUCCESS: The signature is valid and the signer is trusted.
    :cvar UNTRUSTED_VALIDATION_SUCCESS: The signature is valid but the signer is not trusted.
    :cvar VALIDATION_FAIL: The signature failed validation.
    """

    VALIDATION_SUCCESS = 0
    UNTRUSTED_VALIDATION_SUCCESS = 254
    VALIDATION_FAIL = 1
