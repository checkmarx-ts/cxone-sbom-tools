from __future__ import annotations
from typing import Any
from os import PathLike


class UnsupportedAlgorithm(Exception):
    """An exception class used to indicate signature operation errors."""

    def __init__(self, algo_description: str):
        super().__init__(f"Unsupported algorithm: {algo_description}")


class UnsupportedKey(Exception):
    """An exception class used to indicate signature operation errors."""

    def __init__(self, key_description: str):
        super().__init__(f"Unsupported key: {key_description}")


class KeyLoadException(Exception):
    """An exception class used to indicate signature operation errors."""

    @staticmethod
    def unsupported_key(_type: Any) -> KeyLoadException:
        return KeyLoadException(f"Key object with type {type(_type)} unsupported.")

    @staticmethod
    def file_not_found(path: str | PathLike[str]) -> KeyLoadException:
        return KeyLoadException(f"File not found: [{str(path)}]")

    @staticmethod
    def unknown_pass_type(password: Any) -> KeyLoadException:
        return KeyLoadException(f"Password type unknown: {type(password)}")

    @staticmethod
    def public_key_not_in_sbom() -> KeyLoadException:
        return KeyLoadException("No public key found in SBOM")
