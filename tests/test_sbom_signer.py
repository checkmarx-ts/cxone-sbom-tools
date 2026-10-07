"""Unit tests for the ``cxone_sbom.crypto.SbomSigner`` factory methods.

``SbomSigner`` can be built two ways, and each is a separate test variation:

* **bundles** -- ``SbomSigner.from_cert_bundle(bundle, password=, hash=)``, where the
  certificate and private key arrive as one combined PEM (``bundle.pem``)
* **separate files** -- ``SbomSigner.from_cert_files(cert, key, password=, hash=)``, where
  the certificate (``cert.pem``) and private key (``cert.pkey.pem``) are distinct files

Both variations must behave identically, so each gets the same three behaviours. The class
name states the variation first, then the behaviour:

    behaviour                bundles                                     separate files
    ----------------------   -----------------------------------------   -----------------------------------------------
    supported algorithms     SbomSignerBundleSupportedAlgTest            SbomSignerSeparateFilesSupportedAlgTest
    unsupported algorithms   SbomSignerBundleUnsupportedAlgTest          SbomSignerSeparateFilesUnsupportedAlgTest
    unusable input           SbomSignerBundleInvalidInputTest            SbomSignerSeparateFilesInvalidInputTest

**Supported algorithms** -- material under ``testdata/certs/valid/``. A load must return an
``SbomSigner``; any exception is a test failure. One pair of methods is generated per
``HashAlgorithm`` member, and every call passes that member as the ``hash`` keyword
argument:

* ``test_valid_unencrypted_<MEMBER>`` -> no password
* ``test_valid_encrypted_<MEMBER>``   -> password supplied as both a ``str`` and a UTF-8
  encoded ``bytes``

These names are variation-neutral on purpose; the enclosing class supplies the variation,
and each generated docstring names it explicitly.

Generating a method per member rather than looping inside one test keeps each hash
independently selectable from the command line and independently reported.

**Unsupported algorithms** -- structurally sound material under ``testdata/certs/invalid/``
whose key algorithm is not supported. Must raise ``cxone_sbom.crypto.UnsupportedKey``.

**Unusable input** -- must raise ``cxone_sbom.crypto.KeyLoadException``: a missing or empty
password on encrypted material, a nonexistent path, an ``io.TextIOBase`` where binary is
required, and an ``int``.

Every test drives all accepted forms of the positional arguments -- ``str``,
``pathlib.Path``, ``BinaryIO`` and ``bytes``. For ``from_cert_files`` both positional
arguments are converted to the *same* form together, so a loader that handles only one of
them is caught. ``subTest`` isolates each combination.

``pathlib.Path`` is used rather than a concrete flavour, so the suite runs unmodified on
any platform: it resolves to ``PosixPath`` or ``WindowsPath`` as appropriate, and the
loaders only require ``os.PathLike``.

Path arguments are deliberately *relative* to ``.``, so the working directory is pinned to
the directory holding ``testdata/`` for the duration of each class. That keeps the tests
independent of where the runner was invoked from.
"""

import io
import os
import unittest
from contextlib import ExitStack
from pathlib import Path
from typing import Any, Iterator

from cxone_sbom.crypto import (
    HashAlgorithm,
    KeyLoadException,
    SbomSigner,
    UnsupportedKey,
)

#: Common anchor for both certificate trees; used to locate the project root.
CERTS_DIR = Path("testdata") / "certs"

#: Material whose key algorithm is supported.
VALID_CERTS_DIR = CERTS_DIR / "valid"

#: Material whose key algorithm is not supported.
INVALID_CERTS_DIR = CERTS_DIR / "invalid"

#: The password protecting every encrypted private key.
BUNDLE_PASSWORD = "password"

#: Both accepted spellings of that password: text, and its UTF-8 encoding.
VALID_PASSWORDS = (BUNDLE_PASSWORD, BUNDLE_PASSWORD.encode("utf-8"))

#: Passwords that must be rejected for encrypted material. ``None`` has no encoded
#: counterpart; the empty password is checked as both text and bytes.
INVALID_PASSWORDS = (None, "", b"")

#: Paths guaranteed not to resolve, in positional order.
MISSING_PATHS = ("/foo/bar.pem", "/foo/bar.pkey.pem")

#: Integers must not be mistaken for file descriptors -- 0 and 1 are stdin/stdout.
NON_KEY_INTEGERS = (0, 1, 42)

#: The two sets present in every combination directory: unencrypted and encrypted.
UNENCRYPTED, ENCRYPTED = "", ".encrypt"


def _locate_certs_parent() -> Path:
    """Return the directory that ``testdata/certs`` hangs off of.

    Searches the cwd first, then walks upward from this file. Anchoring on the shared
    ``testdata/certs`` parent rather than on either subtree keeps ``valid/`` and
    ``invalid/`` resolvable from the same working directory.
    """
    candidates = [Path.cwd(), Path(__file__).resolve().parent]
    candidates.extend(Path(__file__).resolve().parents)
    for base in candidates:
        if (base / CERTS_DIR).is_dir():
            return base
    raise FileNotFoundError(
        f"could not locate {str(CERTS_DIR)!r} relative to {Path.cwd()} "
        f"or any parent of {Path(__file__).resolve()}"
    )


def _iter_arg_forms(paths: tuple[Path, ...]) -> Iterator[tuple[str, tuple[Any, ...]]]:
    """Yield ``(label, positional args)`` for each accepted representation of ``paths``.

    All positional arguments are converted together, so a loader that accepts one form
    for the certificate but not for the key is caught. ``BinaryIO`` handles stay open only
    for the duration of their own iteration step, so each caller gets fresh, unconsumed
    streams.
    """
    yield "str", tuple(str(p) for p in paths)
    yield "Path", tuple(Path(p) for p in paths)
    with ExitStack() as stack:
        yield "BinaryIO", tuple(stack.enter_context(p.open("rb")) for p in paths)
    yield "bytes", tuple(p.read_bytes() for p in paths)


def _iter_text_stream_forms(
    paths: tuple[Path, ...],
) -> Iterator[tuple[str, tuple[Any, ...]]]:
    """Yield ``(label, positional args)`` as text streams, which must all be rejected."""
    yield "io.StringIO", tuple(
        io.StringIO(p.read_text(encoding="utf-8")) for p in paths
    )
    with ExitStack() as stack:
        yield "io.TextIOWrapper", tuple(
            stack.enter_context(p.open("r", encoding="utf-8")) for p in paths
        )


class _BundleLoader:
    """Call shapes for ``SbomSigner.from_cert_bundle``: a single combined PEM."""

    #: Human-readable name of the factory variation, used in generated docstrings.
    variation = "bundles"
    arity = 1

    @staticmethod
    def call(args: tuple[Any, ...], **kwargs: Any) -> Any:
        return SbomSigner.from_cert_bundle(*args, **kwargs)

    @staticmethod
    def paths(combo: Path, tag: str) -> tuple[Path, ...]:
        return (combo / f"bundle{tag}.pem",)


class _SeparateFilesLoader:
    """Call shapes for ``SbomSigner.from_cert_files``: certificate then private key."""

    #: Human-readable name of the factory variation, used in generated docstrings.
    variation = "separate files"
    arity = 2

    @staticmethod
    def call(args: tuple[Any, ...], **kwargs: Any) -> Any:
        return SbomSigner.from_cert_files(*args, **kwargs)

    @staticmethod
    def paths(combo: Path, tag: str) -> tuple[Path, ...]:
        return (combo / f"cert{tag}.pem", combo / f"cert{tag}.pkey.pem")


class _CertFixture(unittest.TestCase):
    """Pins the working directory so ``testdata/certs`` paths stay relative to ``.``."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._original_cwd = Path.cwd()
        os.chdir(_locate_certs_parent())

    @classmethod
    def tearDownClass(cls) -> None:
        os.chdir(cls._original_cwd)

    def _combos(self, root: Path) -> list[Path]:
        """Relative paths to every combination directory under ``root``.

        A missing or empty tree is a failure rather than a skip: silently dropping the
        fixtures would silently drop the coverage.
        """
        self.assertTrue(root.is_dir(), f"{root} is not a directory")
        combos = sorted(entry for entry in root.iterdir() if entry.is_dir())
        self.assertTrue(combos, f"no certificate combinations found under {root}")
        for combo in combos:
            self.assertFalse(combo.is_absolute(), f"{combo} should be relative to '.'")
        return combos

    def _paths_for(self, combo: Path, tag: str) -> tuple[Path, ...]:
        """This loader's positional file paths within ``combo``, checked for presence."""
        paths = self.paths(combo, tag)
        for path in paths:
            self.assertTrue(path.is_file(), f"missing fixture file {path}")
        return paths


class _SupportedAlgTests:
    """Material with a supported key algorithm loads from every argument form."""

    def _load(self, args: tuple[Any, ...], **kwargs: Any) -> Any:
        """Invoke the loader, turning any exception into a test failure."""
        try:
            return self.call(args, **kwargs)
        except Exception as exc:
            raise self.failureException(
                f"loader raised {type(exc).__name__}: {exc}"
            ) from exc

    def _assert_loads(self, combo: Path, tag: str, **kwargs: Any) -> None:
        for form, args in _iter_arg_forms(self._paths_for(combo, tag)):
            with self.subTest(arg_form=form):
                signer = self._load(args, **kwargs)
                self.assertIsInstance(
                    signer,
                    SbomSigner,
                    f"loader returned {type(signer).__name__}, expected SbomSigner",
                )

    def test_hash_algorithm_enum_is_populated(self) -> None:
        """Guard the generated methods: an empty enum would yield silent zero coverage."""
        self.assertTrue(
            list(HashAlgorithm),
            "HashAlgorithm has no members, so no per-hash tests were generated",
        )


class _UnsupportedAlgTests:
    """Material under ``testdata/certs/invalid`` raises ``UnsupportedKey``.

    It parses as well-formed PEM -- it is the key itself that is unacceptable, so the
    failure must be reported as ``UnsupportedKey`` specifically and not as a generic load
    error.
    """

    def _assert_raises(
        self, expected: type[BaseException], combo: Path, tag: str, **kwargs: Any
    ) -> None:
        for form, args in _iter_arg_forms(self._paths_for(combo, tag)):
            with self.subTest(arg_form=form):
                with self.assertRaises(expected):
                    self.call(args, **kwargs)

    def test_unsupported_key_unencrypted(self) -> None:
        """Unsupported unencrypted material is rejected from every argument form."""
        for combo in self._combos(INVALID_CERTS_DIR):
            with self.subTest(combo=str(combo)):
                self._assert_raises(UnsupportedKey, combo, UNENCRYPTED)

    def test_unsupported_key_encrypted(self) -> None:
        """Unsupported encrypted material is rejected even with the correct password."""
        for combo in self._combos(INVALID_CERTS_DIR):
            for password in VALID_PASSWORDS:
                with self.subTest(
                    combo=str(combo), password_type=type(password).__name__
                ):
                    self._assert_raises(
                        UnsupportedKey, combo, ENCRYPTED, password=password
                    )


class _InvalidInputTests:
    """Unusable input raises ``KeyLoadException``.

    ``assertRaises`` is deliberately narrow: any other exception type propagates and marks
    the case as an error, so a leaked ``TypeError``/``ValueError``/``FileNotFoundError`` is
    reported rather than silently accepted.
    """

    def test_encrypted_without_password_raises(self) -> None:
        """Encrypted material cannot be loaded with a missing or empty password."""
        for combo in self._combos(VALID_CERTS_DIR):
            for password in INVALID_PASSWORDS:
                paths = self._paths_for(combo, ENCRYPTED)
                for form, args in _iter_arg_forms(paths):
                    with self.subTest(
                        combo=str(combo), password=password, arg_form=form
                    ):
                        with self.assertRaises(KeyLoadException):
                            self.call(args, password=password)

    def test_nonexistent_path_raises(self) -> None:
        """Paths that do not exist are rejected, as both str and pathlib.Path."""
        missing = MISSING_PATHS[: self.arity]
        for path in missing:
            self.assertFalse(Path(path).exists(), f"{path} unexpectedly exists")
        forms = (
            ("str", tuple(missing)),
            ("Path", tuple(Path(p) for p in missing)),
        )
        for form, args in forms:
            with self.subTest(arg_form=form):
                with self.assertRaises(KeyLoadException):
                    self.call(args)

    def test_text_stream_raises(self) -> None:
        """Text-mode streams are rejected; the loader needs bytes, not str."""
        combo = self._combos(VALID_CERTS_DIR)[0]
        paths = self._paths_for(combo, UNENCRYPTED)
        for form, args in _iter_text_stream_forms(paths):
            with self.subTest(arg_form=form):
                for arg in args:
                    self.assertIsInstance(arg, io.TextIOBase)
                with self.assertRaises(KeyLoadException):
                    self.call(args)

    def test_integer_raises(self) -> None:
        """Integers are rejected rather than treated as file descriptors."""
        for value in NON_KEY_INTEGERS:
            with self.subTest(value=value):
                with self.assertRaises(KeyLoadException):
                    self.call((value,) * self.arity)


def _add_per_hash_tests(cls: type) -> type:
    """Attach one pair of load tests to ``cls`` for every ``HashAlgorithm`` member.

    The member is bound as a default argument rather than captured, so each generated
    method keeps its own value instead of sharing the loop variable.
    """
    for member in HashAlgorithm:

        def unencrypted(self, hash_alg: HashAlgorithm = member) -> None:
            for combo in self._combos(VALID_CERTS_DIR):
                with self.subTest(combo=str(combo)):
                    self._assert_loads(combo, UNENCRYPTED, hash=hash_alg)

        def encrypted(self, hash_alg: HashAlgorithm = member) -> None:
            for combo in self._combos(VALID_CERTS_DIR):
                for password in VALID_PASSWORDS:
                    with self.subTest(
                        combo=str(combo), password_type=type(password).__name__
                    ):
                        self._assert_loads(
                            combo, ENCRYPTED, password=password, hash=hash_alg
                        )

        specs = (
            ("test_valid_unencrypted", unencrypted, "with no password"),
            (
                "test_valid_encrypted",
                encrypted,
                "given the password as str or UTF-8 bytes",
            ),
        )
        for prefix, method, suffix in specs:
            name = f"{prefix}_{member.name}"
            method.__name__ = name
            method.__qualname__ = f"{cls.__name__}.{name}"
            method.__doc__ = (
                f"hash={member.name}: loads from {cls.variation} in every argument "
                f"form, {suffix}."
            )
            setattr(cls, name, method)
    return cls


# --- Bundle variation: SbomSigner.from_cert_bundle --------------------------------


@_add_per_hash_tests
class SbomSignerBundleSupportedAlgTest(_BundleLoader, _SupportedAlgTests, _CertFixture):
    """``from_cert_bundle``: supported algorithms loaded from a bundle."""


class SbomSignerBundleUnsupportedAlgTest(
    _BundleLoader, _UnsupportedAlgTests, _CertFixture
):
    """``from_cert_bundle``: unsupported algorithms loaded from a bundle."""


class SbomSignerBundleInvalidInputTest(_BundleLoader, _InvalidInputTests, _CertFixture):
    """``from_cert_bundle``: unusable input in place of a bundle."""


# --- Separate files variation: SbomSigner.from_cert_files -------------------------


@_add_per_hash_tests
class SbomSignerSeparateFilesSupportedAlgTest(
    _SeparateFilesLoader, _SupportedAlgTests, _CertFixture
):
    """``from_cert_files``: supported algorithms loaded from separate files."""


class SbomSignerSeparateFilesUnsupportedAlgTest(
    _SeparateFilesLoader, _UnsupportedAlgTests, _CertFixture
):
    """``from_cert_files``: unsupported algorithms loaded from separate files."""


class SbomSignerSeparateFilesInvalidInputTest(
    _SeparateFilesLoader, _InvalidInputTests, _CertFixture
):
    """``from_cert_files``: unusable input in place of the certificate and key."""


if __name__ == "__main__":
    unittest.main()
