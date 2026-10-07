import io, copy
from os import PathLike
from pathlib import PurePath, Path
from typing import Any, BinaryIO, Dict
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519, ed448, ec
from .exceptions import KeyLoadException


class SbomOpBase:
    """Base class providing shared helper utilities for SBOM signing and
    verification operations, such as input validation and key/data loading.
    """

    @staticmethod
    def _key_load_input_valid(
        value: str | PathLike[str] | BinaryIO | bytes,
    ) -> bool:
        if isinstance(value, (io.RawIOBase, io.BufferedIOBase)) or isinstance(
            value, bytes
        ):
            return True
        elif isinstance(value, PathLike):
            path_eval = value
        elif isinstance(value, str):
            path_eval = Path(value)
        else:
            raise KeyLoadException.unsupported_key(value)

        if not (path_eval.exists() and path_eval.is_file()):
            raise KeyLoadException.file_not_found(path_eval)
        else:
            return True

    @staticmethod
    def _sbom_load_input_valid(
        value: Dict | str | PathLike[str] | BinaryIO | bytes,
    ) -> bool:
        if isinstance(value, Dict):
            return True
        else:
            return SbomOpBase._key_load_input_valid(value)

    @staticmethod
    def _duplicate_sbom(sbom: Dict) -> Dict:
        return copy.deepcopy(sbom)

    @staticmethod
    def _is_io(object: Any) -> bool:
        return isinstance(object, (io.RawIOBase, io.BufferedIOBase))

    @staticmethod
    def _password(password: str | bytes | None):
        if password is None:
            return None
        elif isinstance(password, str):
            return password.encode("UTF-8")
        elif isinstance(password, bytes):
            return password

        raise KeyLoadException.unknown_pass_type(password)

    @staticmethod
    def _load_data(source: str | PathLike[str] | BinaryIO | bytes) -> bytes:
        loaded_key = None

        if isinstance(source, bytes):
            loaded_key = source
        elif SbomOpBase._is_io(source):
            loaded_key = source.read()
        elif isinstance(source, (str, PurePath)) and Path(source).is_file():
            with open(source, "rb") as k:
                loaded_key = k.read()

        return loaded_key

    @staticmethod
    def _get_key_type(
        key_class: (
            rsa.RSAPublicKey
            | ec.EllipticCurvePublicKey
            | ed25519.Ed25519PublicKey
            | ed448.Ed448PublicKey
        ),
    ) -> str:
        if isinstance(key_class, rsa.RSAPublicKey):
            return "RSA"
        elif isinstance(key_class, ec.EllipticCurvePublicKey):
            return "EC"
        elif isinstance(key_class, ed25519.Ed25519PublicKey) or isinstance(
            key_class, ed448.Ed448PublicKey
        ):
            return "OKP"
