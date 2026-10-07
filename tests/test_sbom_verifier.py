"""Unit tests for the ``cxone_sbom.crypto.SbomVerifier`` factory methods.

Companion to ``test_sbom_signer.py``. That suite proves an ``SbomSigner`` can be *built*;
this one signs with it and proves the resulting SBOM *verifies*. Signing is exercised only
against ``testdata/certs/simple/``, whose combinations are all expected to hold supported,
loadable material -- so there is no ``UnsupportedKey`` variant here, the signer suite
already owning that behaviour.

``SbomVerifier`` can be built three ways, and each is a separate test variation:

* **certificate file** -- ``SbomVerifier.from_cert_file(x509pem, ...)``, where the
  verifying certificate is supplied directly (``cert.pem``)
* **embedded certificate** -- ``SbomVerifier.from_embedded_cert(sbom, ...)``, where the
  certificate is recovered from the signed SBOM itself
* **embedded key** -- ``SbomVerifier.from_embedded_key(sbom)``, where only the public key
  is recovered from the signed SBOM

The first two accept ``ca_bundle_pem`` and ``intermediate_bundle_pem``; the third accepts
neither. The class name states the variation first, then the behaviour:

    behaviour             cert file                         embedded cert                         embedded key
    -------------------   -------------------------------   -----------------------------------   ---------------------------------
    no trust bundles      SbomVerifierCertFileUntrusted..    SbomVerifierEmbeddedCertUntrusted..   SbomVerifierEmbeddedKeyUntrusted..
    trust bundles given   SbomVerifierCertFileTrustBundle..  SbomVerifierEmbeddedCertTrustBundle.. (not applicable)
    unusable input        SbomVerifierCertFileInvalid..      SbomVerifierEmbeddedCertInvalid..     SbomVerifierEmbeddedKeyInvalid..

**Outcomes.** ``signature_validates`` returns a ``ValidationResult`` member, and the tests
assert the exact member rather than truthiness, so a change in trust semantics cannot pass
silently:

    ca_bundle_pem   intermediate_bundle_pem   payload    expected
    -------------   -----------------------   --------   ----------------------------
    unset           unset                     intact     UNTRUSTED_VALIDATION_SUCCESS
    unset           signing cert              intact     UNTRUSTED_VALIDATION_SUCCESS
    signing cert    unset                     intact     VALIDATION_SUCCESS
    signing cert    signing cert              intact     VALIDATION_SUCCESS
    any             any                       tampered   VALIDATION_FAIL

Two independent questions are being asked, in order. First, does the signature verify? A
tampered payload yields ``VALIDATION_FAIL`` regardless of what trust material is present,
including the intermediate-without-CA case. Only once the signature holds is the second
question reached: does the certificate chain to a supplied root? Only a CA bundle is a
trust root. An intermediate bundle extends a chain *toward* a root, so supplying one
without a CA anchors nothing.

An intermediate without a CA therefore has two outcomes, not one --
``UNTRUSTED_VALIDATION_SUCCESS`` on a good signature, ``VALIDATION_FAIL`` on a bad one --
and both are asserted. That is also why the trust-bundle classes are named for the inputs
they supply rather than for the outcome they expect.

``from_embedded_key`` is a special case: it accepts no bundles at all, so a good signature
is always ``UNTRUSTED_VALIDATION_SUCCESS`` -- a bare public key can anchor no chain.

**Per-hash coverage.** Unlike the signer factories, no ``SbomVerifier`` factory takes a
``hash`` keyword -- the algorithm is a property of the signature being checked, not of the
verifier. Per-``HashAlgorithm`` generation therefore moves to the fixture step: sign with a
member, then verify.

The sweep runs only against combinations whose directory name contains ``rsa`` -- the path
element immediately above the certificate and bundle files. RSA leaves the digest a free
choice, so every member is a legitimate pairing. Other key types fix or constrain it, so
each non-RSA combination is signed exactly once with the ``hash`` keyword omitted, letting
the signer pick the digest its key requires. Every behaviour therefore generates one
``..._rsa_<MEMBER>`` method per member plus a single ``..._default_hash`` method:

* ``test_untrusted_valid_signature_rsa_SHA256`` -> RSA material, that digest
* ``test_untrusted_valid_signature_default_hash`` -> non-RSA material, signer's choice

As in the signer suite the member is bound as a default argument rather than captured, so
each generated method keeps its own value, and each hash stays independently selectable
from the command line and independently reported.

An RSA-less tree is a failure, since the generated sweep would report green while covering
nothing; a tree with no non-RSA material is a skip, since shipping only RSA fixtures is a
configuration choice rather than a missing fixture.

**Signer provenance arguments.** ``sign_sbom`` takes two optional arguments beyond the SBOM:
``scanUrl``, a plain string, and a ``RepositoryInfo`` dataclass carrying ``cloneUrl``
(required), ``commit`` and ``branch`` (optional). These describe where the scan came from
rather than how it is signed, so the contract under test is that supplying them changes
nothing about verification: the SBOM must still sign, and must still yield the same
``ValidationResult``.

Note they go to ``sign_sbom``, not to the signer factory -- the factory is built once per
``(combo, tag, hash, password)`` and the provenance rides on the signing call.

Because ``cloneUrl`` is required, there is no variation with an empty or ``cloneUrl``-less
repository; the axis swept is which *optional* fields accompany it. Every behaviour
generates one ``..._provenance_<variation>`` method per entry in
``SIGN_PROVENANCE_BUILDERS``: ``none``, ``scan_url``, ``repo_minimal`` (the required field
alone), ``repo_commit``, ``repo_branch``, ``repo_full``, ``scan_url_and_repo_minimal``, and
``all``. That is a chosen subset rather than an exhaustive cross-product, which would
multiply the suite without covering a new code path; the singles exist so an unsupported
optional field pins itself to one failing method.

These methods sweep every combination at the signer's default digest, provenance being
orthogonal to the digest. ``test_provenance_fields`` guards the table against the dataclass
itself: the dummy values collide on purpose -- both URLs share one string and both VCS
fields share another -- so a transposed field could not be caught by inspecting values, and
the field names are checked against ``dataclasses.fields(RepositoryInfo)`` instead. It also
asserts the required/optional split both ways, so a ``cloneUrl`` that gains a default, or a
``commit`` that loses one, fails there with a message saying which variations need revising
rather than surfacing as a wall of construction errors.

Note the limit of this coverage: it proves provenance arguments do not *break* signing or
verification. It does not prove they are *recorded*, since where they land in the signed
document is not something this suite knows.

**Password types.** No ``SbomVerifier`` factory takes a password, so this is not one of the
verifier variations. It is covered here because the signer keyword is what unlocks every
encrypted fixture in this file. The declared type is ``str | bytes | None``, and the values
are not interchangeable -- ``None`` is for unencrypted keys only:

    key state      accepted password              rejected
    ------------   ----------------------------   ------------------------------
    encrypted      str, bytes                     None, and every wrong type
    unencrypted    None, or the keyword omitted   (wrong types not asserted)

``SbomSignerPasswordTypeTest`` proves each accepted spelling yields a *verifiable* SBOM,
that ``str`` and ``bytes`` unlock the same key, that ``None`` works on an unencrypted key
either spelled out or omitted, and that everything else raises ``KeyLoadException`` from
the factory itself. ``bytearray`` and ``memoryview`` are among the rejected values, not the
accepted ones: the type is ``bytes``, not ``ByteString``, and since both carry the correct
password bytes they would slip past a factory that merely duck-typed its argument. Wrong
types are driven against the encrypted tag only, since an unencrypted bundle may never
consult the password at all.

**Argument forms.** Two form-sets are in play, because the factories do not agree:

* certificate and bundle parameters take ``str``, ``pathlib.Path``, ``BinaryIO`` and
  ``bytes`` -- the same set the signer suite drives
* ``sbom`` parameters take ``Dict``, ``os.PathLike`` and ``BinaryIO``. A plain ``str`` is
  not ``PathLike`` and is therefore *not* driven here, and there is no ``bytes`` form

Every factory in this file is arity 1, so the form iterators yield single values rather
than the tuples the signer suite needs for its two-argument loader.

Trust-bundle argument forms are exercised in one dedicated test per variation rather than
crossed with every outcome, which would multiply the case count without adding coverage.

**Tampering.** The ``version`` key of the signed SBOM is mutated. The ``Dict`` form is
mutated directly and the ``PathLike``/``BinaryIO`` forms are re-serialised from that same
mutated dict, so the only difference between the intact and tampered cases is that one
field. For the embedded variations the verifier is built from the *same* tampered artifact
that is then validated, which is the realistic attack.

**SBOM fixtures.** Everything signed here starts as ``testdata/sbom/sbom.json``. That tree
hangs off the same ``testdata/`` parent as the certificates, so the working directory
pinned for one resolves the other.

One case stands outside the grid: ``SbomVerifierCycloneDxExampleTest`` verifies
``testdata/sbom/cyclonedx.signed.example.json``, the signed example published by the
CycloneDX project. Every other test verifies material this suite signed moments earlier,
which is a closed loop -- a verifier that agreed with a broken signer would pass
throughout. That case breaks the loop against material this codebase did not produce. It
uses ``from_embedded_key`` only, is not parameterised by ``HashAlgorithm`` (the algorithm
is fixed by the published file), and expects ``UNTRUSTED_VALIDATION_SUCCESS``.

**Unusable input** -- must raise ``cxone_sbom.crypto.KeyLoadException``: a nonexistent
path, an ``io.TextIOBase`` where binary is required, and an ``int``. Each accepted
parameter is driven bad in turn while the others stay valid, so a factory that validates
only its positional argument is caught.

Path arguments are deliberately *relative* to ``.``, so the working directory is pinned to
the directory holding ``testdata/`` for the duration of each class, exactly as in the
signer suite.
"""

import copy
import dataclasses
import io
import json
import os
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, Optional

from cxone_sbom.crypto import (
    HashAlgorithm,
    KeyLoadException,
    RepositoryInfo,
    SbomSigner,
    SbomVerifier,
    ValidationResult,
)

#: Common anchor for both certificate trees; used to locate the project root.
CERTS_DIR = Path("testdata") / "certs"

#: The certificate tree this suite signs with. Every combination here is expected to hold
#: supported, loadable material: the signer suite owns the unsupported-key behaviour, so
#: nothing in this file signs with anything it expects to be rejected.
SIMPLE_CERTS_DIR = CERTS_DIR / "simple"

#: The password protecting every encrypted private key.
BUNDLE_PASSWORD = "password"

#: Accepted password representations for an *encrypted* key. The declared type is
#: ``str | bytes | None``, and ``None`` is reserved for unencrypted keys, so these two are
#: the whole accepted set here.
#:
#: Builders rather than fixed values, matching ``_MATERIAL_FORM_BUILDERS``. Both remaining
#: forms are immutable so nothing can be scrubbed in place, but the shape is kept so adding
#: a mutable form later cannot silently reintroduce that hazard.
ENCRYPTED_PASSWORD_BUILDERS: dict[str, Callable[[], Any]] = {
    "str": lambda: BUNDLE_PASSWORD,
    "bytes": lambda: BUNDLE_PASSWORD.encode(),
}

#: How ``None`` reaches an unencrypted key: spelled out, or by leaving the keyword off.
#: Both must behave identically, since a default of ``None`` makes them the same call.
UNENCRYPTED_PASSWORD_FORMS = ("omitted", "explicit_none")

#: Values that are neither ``str`` nor ``bytes`` and so must be rejected.
#:
#: ``bytearray`` and ``memoryview`` sit here rather than among the accepted forms: the type
#: is ``str | bytes``, not ``ByteString``. Both carry the *correct* password bytes, so a
#: factory that duck-typed its buffer argument would unlock the key and pass -- which is
#: exactly the looseness these two cases exist to catch.
#:
#: ``bool`` is listed separately from ``int`` although it is a subclass of it: an
#: ``isinstance(value, int)`` guard catches both, but a guard written as ``type(value) is
#: int`` would let ``True`` through, and a truthy password that silently means something
#: else is worth pinning down.
#:
#: ``None`` is deliberately absent -- it is a *valid* value, restricted to unencrypted
#: keys. ``test_none_password_on_encrypted_key_raises`` covers the misuse.
INVALID_PASSWORD_VALUES: tuple[tuple[str, Any], ...] = (
    ("bytearray", bytearray(BUNDLE_PASSWORD.encode())),
    ("memoryview", memoryview(BUNDLE_PASSWORD.encode())),
    ("int-zero", 0),
    ("int-one", 1),
    ("int", 42),
    ("int-negative", -1),
    ("bool-true", True),
    ("bool-false", False),
    ("float", 1.0),
    ("list", ["password"]),
    ("tuple", ("password",)),
    ("dict", {"password": "password"}),
    ("object", object()),
)

#: Paths guaranteed not to resolve.
MISSING_PATH = "/foo/bar.pem"

#: Integers must not be mistaken for file descriptors -- 0 and 1 are stdin/stdout.
NON_KEY_INTEGERS = (0, 1, 42)

#: The two sets present in every combination directory: unencrypted and encrypted.
UNENCRYPTED, ENCRYPTED = "", ".encrypt"

#: Both tags, so every outcome is proven against encrypted and unencrypted material alike.
ALL_TAGS = (UNENCRYPTED, ENCRYPTED)

#: SBOM fixtures. These hang off the same ``testdata/`` parent as the certificate trees,
#: so the working directory pinned for the certificates resolves these too.
SBOM_DIR = Path("testdata") / "sbom"

#: The unsigned SBOM that every signing fixture signs.
SAMPLE_SBOM_PATH = SBOM_DIR / "sbom.json"

#: An already-signed SBOM published by the CycloneDX project, used for one sanity check.
#: It is signed by neither this suite nor this codebase.
CYCLONEDX_SIGNED_PATH = SBOM_DIR / "cyclonedx.signed.example.json"

#: The field the tamper cases mutate.
TAMPER_KEY = "version"

#: Dummy provenance values. Both URL values are the same string and both VCS values are the
#: same string, so a transposed field cannot be caught by inspecting values -- see
#: ``test_provenance_fields`` for the guard that keeps the *names* honest.
DUMMY_URL = "https://scan.foo.com"
DUMMY_REF = "foo"

#: The keyword names on ``sign_sbom``. ``scanUrl`` is a plain string; the remaining three
#: fields travel together inside a ``RepositoryInfo`` passed as ``repository``.
SCAN_URL_KEYWORD = "scanUrl"
REPOSITORY_KEYWORD = "repository"

#: The fields ``RepositoryInfo`` is expected to carry. ``cloneUrl`` is required and the other
#: two are optional; both halves of that are asserted against the dataclass itself by
#: ``test_provenance_fields`` rather than trusted.
REPOSITORY_REQUIRED_FIELDS = ("cloneUrl",)
REPOSITORY_OPTIONAL_FIELDS = ("commit", "branch")
REPOSITORY_FIELDS = REPOSITORY_REQUIRED_FIELDS + REPOSITORY_OPTIONAL_FIELDS


def _repository_info(cloneUrl: str = DUMMY_URL, **optional: Any) -> RepositoryInfo:
    """Build a ``RepositoryInfo``, leaving unnamed optional fields at their defaults.

    ``cloneUrl`` is required by the dataclass, so it is a positional parameter here with a
    dummy default rather than something a caller can omit -- there is no such thing as a
    ``RepositoryInfo`` without it, and no variation in this file tries to build one.
    """
    return RepositoryInfo(cloneUrl=cloneUrl, **optional)


#: Provenance arguments passed to ``sign_sbom``, keyed by the name that appears in the
#: generated method. Builders rather than fixed values, so a signer that mutated a
#: ``RepositoryInfo`` in place could not corrupt a later variation.
#:
#: Because ``cloneUrl`` is required, every variation that supplies a repository supplies
#: that field too -- the axis being swept is which *optional* fields accompany it. The
#: selection covers no provenance at all, ``scanUrl`` alone, the bare required minimum, each
#: optional field added singly, the container full, one mixed case, and everything. The
#: singles exist so an unsupported optional field pins itself to one failing method.
#:
#: ``none`` duplicates what the per-hash sweep already does. It is kept so the
#: no-provenance case is explicitly named and selectable alongside the others.
SIGN_PROVENANCE_BUILDERS: dict[str, Callable[[], dict[str, Any]]] = {
    "none": lambda: {},
    "scan_url": lambda: {SCAN_URL_KEYWORD: DUMMY_URL},
    "repo_minimal": lambda: {REPOSITORY_KEYWORD: _repository_info()},
    "repo_commit": lambda: {REPOSITORY_KEYWORD: _repository_info(commit=DUMMY_REF)},
    "repo_branch": lambda: {REPOSITORY_KEYWORD: _repository_info(branch=DUMMY_REF)},
    "repo_full": lambda: {
        REPOSITORY_KEYWORD: _repository_info(commit=DUMMY_REF, branch=DUMMY_REF)
    },
    "scan_url_and_repo_minimal": lambda: {
        SCAN_URL_KEYWORD: DUMMY_URL,
        REPOSITORY_KEYWORD: _repository_info(),
    },
    "all": lambda: {
        SCAN_URL_KEYWORD: DUMMY_URL,
        REPOSITORY_KEYWORD: _repository_info(commit=DUMMY_REF, branch=DUMMY_REF),
    },
}

#: The no-provenance variation, used by every test that is not sweeping provenance.
NO_PROVENANCE = "none"

#: Marks a combination directory as RSA. Matched case-insensitively against the directory
#: name -- the path element immediately above the certificate and bundle files.
RSA_PATH_MARKER = "rsa"

#: Trust-bundle combinations, named for the keyword arguments they populate.
#:
#: A CA bundle is a trust root and can anchor a chain by itself. An intermediate bundle
#: only extends a chain *toward* a root, so supplying one without a CA anchors nothing.
#: ``INTERMEDIATE_ONLY`` still has two outcomes: untrusted success when the signature
#: verifies, and outright failure when it does not.
NO_BUNDLES: tuple[str, ...] = ()
CA_ONLY: tuple[str, ...] = ("ca",)
INTERMEDIATE_ONLY: tuple[str, ...] = ("intermediate",)
CA_AND_INTERMEDIATE: tuple[str, ...] = ("ca", "intermediate")


def _is_rsa_combo(combo: Path) -> bool:
    """True when the directory holding the certificate names RSA.

    RSA signatures leave the digest a free choice, so those combinations are swept across
    every ``HashAlgorithm`` member. Other key types fix or constrain the digest -- an EC
    P-256 key pairs with SHA-256 -- so sweeping them would assert pairings the algorithm
    does not offer, and a failure would say more about the fixture than about the
    verifier.
    """
    return RSA_PATH_MARKER in combo.name.casefold()


# --- Fixture location -------------------------------------------------------------


def _locate_certs_parent() -> Path:
    """Return the directory that ``testdata/certs`` hangs off of.

    Searches the cwd first, then walks upward from this file, matching the signer suite so
    both files run from the same working directory.
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


def _bundle_path(combo: Path, tag: str) -> Path:
    """The combined certificate-and-key PEM used to build the signer."""
    return combo / f"bundle{tag}.pem"


def _cert_path(combo: Path, tag: str) -> Path:
    """The certificate-only PEM.

    Used both as the ``from_cert_file`` positional argument and as the trust anchor. The
    certificate-only file is used rather than the bundle so no private key is ever handed
    to a parameter that has no business holding one.
    """
    return combo / f"cert{tag}.pem"


# --- Argument form iterators ------------------------------------------------------


#: Builders for each accepted representation of a PEM file, covering the
#: ``str | PathLike[str] | BinaryIO | ByteString`` set shared by the certificate and
#: trust-bundle parameters.
#:
#: These are builders rather than fixed values because a single call can populate more
#: than one PEM parameter -- ``ca_bundle_pem`` and ``intermediate_bundle_pem`` together --
#: and a stream is readable exactly once. Handing the same ``BinaryIO`` to both leaves the
#: second parameter reading an exhausted handle, so every parameter mints its own value.
#: Each builder registers whatever it opens with the caller's ``ExitStack``.
_MATERIAL_FORM_BUILDERS: tuple[tuple[str, Callable[[Path, ExitStack], Any]], ...] = (
    ("str", lambda path, stack: str(path)),
    ("Path", lambda path, stack: Path(path)),
    ("BinaryIO", lambda path, stack: stack.enter_context(path.open("rb"))),
    ("bytes", lambda path, stack: path.read_bytes()),
)


def _iter_material_forms(path: Path) -> Iterator[tuple[str, Any]]:
    """Yield ``(label, value)`` for each accepted representation of a PEM file.

    For the single-parameter case. Where one call populates several PEM parameters, use
    ``_MATERIAL_FORM_BUILDERS`` directly so each parameter gets its own instance.
    """
    for label, build in _MATERIAL_FORM_BUILDERS:
        with ExitStack() as stack:
            yield label, build(path, stack)


def _iter_sbom_forms(sbom: Dict[str, Any]) -> Iterator[tuple[str, Any]]:
    """Yield ``(label, value)`` for each accepted representation of an SBOM.

    Covers the ``Dict | PathLike[str] | BinaryIO`` set. There is deliberately no ``str``
    form -- ``str`` is not ``os.PathLike`` and the signature does not admit it -- and no
    ``bytes`` form. The ``Dict`` is deep-copied so a factory that mutates its argument
    cannot corrupt a later iteration step.

    The temporary directory outlives both file-backed steps and is removed when the
    generator is exhausted or closed.
    """
    yield "Dict", copy.deepcopy(sbom)
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "signed-sbom.json"
        path.write_text(json.dumps(sbom), encoding="utf-8")
        yield "Path", path
        with path.open("rb") as handle:
            yield "BinaryIO", handle


def _iter_text_stream_forms(path: Path) -> Iterator[tuple[str, Any]]:
    """Yield ``(label, value)`` as text streams, which must all be rejected."""
    yield "io.StringIO", io.StringIO(path.read_text(encoding="utf-8"))
    with path.open("r", encoding="utf-8") as handle:
        yield "io.TextIOWrapper", handle


# --- Signing fixtures -------------------------------------------------------------


#: SBOM fixtures are parsed once and handed out as copies, so a factory that mutates its
#: argument cannot corrupt a later test.
_SBOM_CACHE: dict[str, Dict[str, Any]] = {}


def _load_sbom(path: Path) -> Dict[str, Any]:
    """Parse an SBOM fixture from disk, cached by path."""
    key = str(path)
    if key not in _SBOM_CACHE:
        with path.open("rb") as handle:
            _SBOM_CACHE[key] = json.load(handle)
    return copy.deepcopy(_SBOM_CACHE[key])


def _sign(
    signer: SbomSigner, sbom: Dict[str, Any], provenance: dict[str, Any]
) -> Dict[str, Any]:
    """Produce a signed SBOM.

    The single point of contact with the signing API, kept as one function so a change to
    ``SbomSigner.sign_sbom`` lands in exactly one place. ``provenance`` carries the optional
    ``scanUrl`` and ``RepositoryInfo`` arguments; an empty dict calls ``sign_sbom`` with the
    SBOM alone.

    The SBOM is copied on the way in because the caller's dict is cached and reused: a
    signer that mutated its argument would otherwise poison every later fixture.
    """
    return signer.sign_sbom(copy.deepcopy(sbom), **provenance)


#: Signed SBOMs are reused across tests, keyed by ``(combo, tag, hash, provenance,
#: password_form)``. Signing is the expensive step and its inputs are fully determined by
#: that tuple, so signing once and handing out copies keeps the per-hash and per-provenance
#: expansions affordable -- the sweeps add cached signings, not one per test.
_SIGNED_CACHE: dict[tuple[str, str, str, str, str], Dict[str, Any]] = {}


def _signed_sbom(
    combo: Path,
    tag: str,
    hash_alg: Optional[HashAlgorithm],
    provenance: str = NO_PROVENANCE,
    password_form: Optional[str] = None,
) -> Dict[str, Any]:
    """Return a freshly copied ``sbom.json`` signed by ``combo``'s material.

    ``hash_alg`` of ``None`` omits the keyword entirely, letting the signer select the
    digest appropriate to the key. That is the path taken for every non-RSA combination,
    where the digest is not a free choice.

    ``provenance`` names a key of ``SIGN_PROVENANCE_BUILDERS``, whose arguments go to
    ``sign_sbom`` rather than to the factory. These are expected to change what the signed
    document records without changing whether it verifies.

    ``password_form`` names a key of ``ENCRYPTED_PASSWORD_BUILDERS`` for the encrypted tag,
    or one of ``UNENCRYPTED_PASSWORD_FORMS`` otherwise; it defaults per tag, since the
    accepted values differ. An unencrypted key takes only ``None``, spelled either way.

    The signer is always built from the bundle, since the signer suite already proves the
    bundle and separate-file factories agree.
    """
    if password_form is None:
        password_form = "str" if tag == ENCRYPTED else "omitted"
    key = (
        str(combo),
        tag,
        hash_alg.name if hash_alg is not None else "default",
        provenance,
        password_form,
    )
    if key not in _SIGNED_CACHE:
        kwargs: dict[str, Any] = {}
        if hash_alg is not None:
            kwargs["hash"] = hash_alg
        if tag == ENCRYPTED:
            kwargs["password"] = ENCRYPTED_PASSWORD_BUILDERS[password_form]()
        elif password_form == "explicit_none":
            kwargs["password"] = None
        elif password_form != "omitted":
            raise AssertionError(
                f"password form {password_form!r} is not valid for an unencrypted key"
            )
        signer = SbomSigner.from_cert_bundle(_bundle_path(combo, tag), **kwargs)
        _SIGNED_CACHE[key] = _sign(
            signer, _load_sbom(SAMPLE_SBOM_PATH), SIGN_PROVENANCE_BUILDERS[provenance]()
        )
    return copy.deepcopy(_SIGNED_CACHE[key])


def _tamper(sbom: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of ``sbom`` with ``version`` altered, invalidating the signature."""
    tampered = copy.deepcopy(sbom)
    tampered[TAMPER_KEY] = int(tampered[TAMPER_KEY]) + 1
    return tampered


# --- Loader variations ------------------------------------------------------------


class _CertFileLoader:
    """Call shapes for ``SbomVerifier.from_cert_file``: the certificate supplied directly."""

    #: Human-readable name of the factory variation, used in generated docstrings.
    variation = "a certificate file"

    #: ``ca_bundle_pem`` and ``intermediate_bundle_pem`` are accepted.
    supports_trust = True

    @staticmethod
    def call(positional: Any, **kwargs: Any) -> Any:
        return SbomVerifier.from_cert_file(positional, **kwargs)

    @staticmethod
    def positional_forms(
        combo: Path, tag: str, sbom: Dict[str, Any]
    ) -> Iterator[tuple[str, Any]]:
        """The certificate, in every form. The SBOM plays no part in construction."""
        return _iter_material_forms(_cert_path(combo, tag))

    @staticmethod
    def valid_positional(combo: Path, tag: str, sbom: Dict[str, Any]) -> Any:
        return _cert_path(combo, tag)

    @staticmethod
    def positional_text_stream_source(combo: Path, tag: str) -> Optional[Path]:
        return _cert_path(combo, tag)


class _EmbeddedCertLoader:
    """Call shapes for ``SbomVerifier.from_embedded_cert``: certificate read from the SBOM."""

    #: Human-readable name of the factory variation, used in generated docstrings.
    variation = "a certificate embedded in the SBOM"

    #: ``ca_bundle_pem`` and ``intermediate_bundle_pem`` are accepted.
    supports_trust = True

    @staticmethod
    def call(positional: Any, **kwargs: Any) -> Any:
        return SbomVerifier.from_embedded_cert(positional, **kwargs)

    @staticmethod
    def positional_forms(
        combo: Path, tag: str, sbom: Dict[str, Any]
    ) -> Iterator[tuple[str, Any]]:
        """The SBOM itself, in every form -- tampered too, when the payload is tampered."""
        return _iter_sbom_forms(sbom)

    @staticmethod
    def valid_positional(combo: Path, tag: str, sbom: Dict[str, Any]) -> Any:
        return copy.deepcopy(sbom)

    @staticmethod
    def positional_text_stream_source(combo: Path, tag: str) -> Optional[Path]:
        return _cert_path(combo, tag)


class _EmbeddedKeyLoader:
    """Call shapes for ``SbomVerifier.from_embedded_key``: public key read from the SBOM."""

    #: Human-readable name of the factory variation, used in generated docstrings.
    variation = "a public key embedded in the SBOM"

    #: No trust bundles: a bare public key can anchor no chain.
    supports_trust = False

    @staticmethod
    def call(positional: Any, **kwargs: Any) -> Any:
        return SbomVerifier.from_embedded_key(positional, **kwargs)

    @staticmethod
    def positional_forms(
        combo: Path, tag: str, sbom: Dict[str, Any]
    ) -> Iterator[tuple[str, Any]]:
        return _iter_sbom_forms(sbom)

    @staticmethod
    def valid_positional(combo: Path, tag: str, sbom: Dict[str, Any]) -> Any:
        return copy.deepcopy(sbom)

    @staticmethod
    def positional_text_stream_source(combo: Path, tag: str) -> Optional[Path]:
        return _cert_path(combo, tag)


# --- Shared fixture ---------------------------------------------------------------


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

    def _rsa_combos(self) -> list[Path]:
        """Combinations whose directory names RSA, so the digest is a free choice.

        An empty result is a failure: the per-hash methods are generated unconditionally,
        and an RSA-less tree would leave every one of them sweeping nothing while still
        reporting green.
        """
        combos = [c for c in self._combos(SIMPLE_CERTS_DIR) if _is_rsa_combo(c)]
        self.assertTrue(
            combos,
            f"no combination under {SIMPLE_CERTS_DIR} has {RSA_PATH_MARKER!r} in its "
            f"directory name, so the per-hash tests would sweep nothing",
        )
        return combos

    def _non_rsa_combos(self) -> list[Path]:
        """Combinations whose digest is fixed by the key type.

        Unlike ``_rsa_combos`` an empty result is a skip rather than a failure: a tree
        that ships only RSA material is a legitimate configuration, not a missing
        fixture, and the RSA sweep still covers the verifier fully.
        """
        combos = [c for c in self._combos(SIMPLE_CERTS_DIR) if not _is_rsa_combo(c)]
        if not combos:
            self.skipTest(f"no non-RSA combinations under {SIMPLE_CERTS_DIR}")
        return combos

    def _require(self, path: Path) -> Path:
        """Assert a fixture file is present before it is used."""
        self.assertTrue(path.is_file(), f"missing fixture file {path}")
        return path

    def _trust_kwargs(
        self, combo: Path, tag: str, bundles: tuple[str, ...]
    ) -> dict[str, Any]:
        """Trust-anchor keyword arguments for this combination.

        Every named bundle is pointed at the signing certificate, which is its own anchor,
        so no CA fixtures beyond the existing tree are needed. The anchor is always paired
        with the ``tag`` that signed the SBOM: ``cert.encrypt.pem`` need not certify the
        same key as ``cert.pem``, and crossing them would produce a ``VALIDATION_FAIL``
        for the wrong reason -- a test that passes while proving nothing.
        """
        if not bundles:
            return {}
        anchor = self._require(_cert_path(combo, tag))
        # A fresh Path per parameter. Paths are stateless and re-openable, so sharing one
        # would be safe today -- but this helper can populate both bundle keywords at
        # once, and the moment a stream is substituted here a shared instance would leave
        # the second parameter reading an exhausted handle. See _MATERIAL_FORM_BUILDERS.
        return {f"{name}_bundle_pem": Path(anchor) for name in bundles}


# --- Behaviour: validation outcomes -----------------------------------------------


class _ValidationTests:
    """Drives sign-then-verify and asserts the exact ``ValidationResult`` member."""

    def _assert_outcome(
        self,
        hash_alg: Optional[HashAlgorithm],
        bundles: tuple[str, ...],
        tamper: bool,
        expected: ValidationResult,
        combos: list[Path],
        provenance: str = NO_PROVENANCE,
    ) -> None:
        if bundles and not self.supports_trust:
            self.fail(f"{type(self).__name__} does not accept trust bundles")
        self.assertIn(
            provenance,
            SIGN_PROVENANCE_BUILDERS,
            f"unknown provenance variation {provenance!r}",
        )
        hash_label = hash_alg.name if hash_alg is not None else "default"
        trust_label = "+".join(bundles) if bundles else "none"
        for combo in combos:
            for tag in ALL_TAGS:
                self._require(_bundle_path(combo, tag))
                self._require(SAMPLE_SBOM_PATH)
                signed = _signed_sbom(combo, tag, hash_alg, provenance)
                self.assertIn(
                    TAMPER_KEY,
                    signed,
                    f"signed SBOM has no {TAMPER_KEY!r} field for the tamper case to "
                    f"mutate; check {SAMPLE_SBOM_PATH}",
                )
                payload = _tamper(signed) if tamper else signed
                kwargs = self._trust_kwargs(combo, tag, bundles)
                for pos_form, positional in self.positional_forms(combo, tag, payload):
                    with self.subTest(
                        combo=str(combo),
                        hash=hash_label,
                        trust=trust_label,
                        provenance=provenance,
                        tag=tag or "unencrypted",
                        positional_form=pos_form,
                    ):
                        # Constructed once per positional form, outside the SBOM loop: a
                        # BinaryIO positional is readable exactly once, so building inside
                        # the loop would hand the factory an exhausted stream on every
                        # iteration after the first.
                        verifier = self.call(positional, **kwargs)
                        self.assertIsInstance(
                            verifier,
                            SbomVerifier,
                            f"factory returned {type(verifier).__name__}, "
                            f"expected SbomVerifier",
                        )
                    for sbom_form, sbom_arg in _iter_sbom_forms(payload):
                        with self.subTest(
                            combo=str(combo),
                            hash=hash_label,
                            trust=trust_label,
                            provenance=provenance,
                            tag=tag or "unencrypted",
                            positional_form=pos_form,
                            sbom_form=sbom_form,
                        ):
                            result = verifier.signature_validates(sbom_arg)
                            self.assertIs(
                                result,
                                expected,
                                f"expected {expected!r}, got {result!r}",
                            )

    def test_hash_algorithm_enum_is_populated(self) -> None:
        """Guard the generated methods: an empty enum would yield silent zero coverage."""
        self.assertTrue(
            list(HashAlgorithm),
            "HashAlgorithm has no members, so no per-hash tests were generated",
        )

    def test_rsa_combinations_present(self) -> None:
        """Guard the per-hash sweep: an RSA-less tree would leave it covering nothing."""
        self._rsa_combos()

    def test_provenance_fields(self) -> None:
        """Guard the provenance sweep: the dataclass fields and the table must agree.

        The dummy values collide deliberately -- both URLs share one string, both VCS
        fields share another -- so value inspection cannot tell the fields apart. This
        checks names against ``RepositoryInfo`` itself, so renaming a field there without
        updating the table is caught here rather than silently reducing coverage to a
        keyword nothing reads.
        """
        self.assertTrue(
            SIGN_PROVENANCE_BUILDERS,
            "SIGN_PROVENANCE_BUILDERS is empty, nothing is swept",
        )
        self.assertEqual(
            SIGN_PROVENANCE_BUILDERS[NO_PROVENANCE](),
            {},
            "the 'none' variation must pass no provenance arguments",
        )
        self.assertTrue(
            dataclasses.is_dataclass(RepositoryInfo),
            "RepositoryInfo is expected to be a dataclass",
        )
        declared = {f.name: f for f in dataclasses.fields(RepositoryInfo)}
        self.assertEqual(
            set(declared),
            set(REPOSITORY_FIELDS),
            f"RepositoryInfo declares {tuple(declared)!r}, but this suite drives "
            f"{REPOSITORY_FIELDS!r}",
        )

        def has_default(field: "dataclasses.Field[Any]") -> bool:
            return (
                field.default is not dataclasses.MISSING
                or field.default_factory is not dataclasses.MISSING
            )

        for name in REPOSITORY_REQUIRED_FIELDS:
            with self.subTest(field=name, expected="required"):
                self.assertFalse(
                    has_default(declared[name]),
                    f"{name} has a default, so it is optional -- this suite treats it as "
                    f"required and always supplies it, which would leave the "
                    f"omitted-{name} case uncovered",
                )
        for name in REPOSITORY_OPTIONAL_FIELDS:
            with self.subTest(field=name, expected="optional"):
                self.assertTrue(
                    has_default(declared[name]),
                    f"{name} has no default, so it is required -- the variations that omit "
                    f"it cannot be constructed and must be revised",
                )
        with self.subTest(check="cloneUrl cannot be omitted"):
            with self.assertRaises(TypeError):
                RepositoryInfo()  # type: ignore[call-arg]
        seen_repo_fields: set[str] = set()
        saw_scan_url = False
        for name, build in SIGN_PROVENANCE_BUILDERS.items():
            with self.subTest(provenance=name):
                kwargs = build()
                unknown = set(kwargs) - {SCAN_URL_KEYWORD, REPOSITORY_KEYWORD}
                self.assertFalse(unknown, f"unknown sign_sbom keyword(s) {unknown!r}")
                if SCAN_URL_KEYWORD in kwargs:
                    self.assertIsInstance(
                        kwargs[SCAN_URL_KEYWORD], str, "scanUrl must be a string"
                    )
                    saw_scan_url = True
                if REPOSITORY_KEYWORD in kwargs:
                    info = kwargs[REPOSITORY_KEYWORD]
                    self.assertIsInstance(
                        info,
                        RepositoryInfo,
                        "repository argument must be RepositoryInfo",
                    )
                    populated = {
                        f.name
                        for f in dataclasses.fields(info)
                        if getattr(info, f.name) is not None
                    }
                    self.assertTrue(
                        set(REPOSITORY_REQUIRED_FIELDS) <= populated,
                        f"variation {name!r} leaves a required field unpopulated; "
                        f"{REPOSITORY_REQUIRED_FIELDS!r} must always be present",
                    )
                    seen_repo_fields |= populated
        self.assertTrue(saw_scan_url, "no variation ever passes scanUrl")
        self.assertEqual(
            seen_repo_fields,
            set(REPOSITORY_FIELDS),
            "some RepositoryInfo field is never populated by any variation",
        )
        full = SIGN_PROVENANCE_BUILDERS["all"]()
        self.assertIn(SCAN_URL_KEYWORD, full, "the 'all' variation must pass scanUrl")
        self.assertEqual(
            {
                f.name
                for f in dataclasses.fields(full[REPOSITORY_KEYWORD])
                if getattr(full[REPOSITORY_KEYWORD], f.name) is not None
            },
            set(REPOSITORY_FIELDS),
            "the 'all' variation must populate every RepositoryInfo field",
        )


class _UntrustedValidationTests(_ValidationTests):
    """With no trust anchor, a good signature validates but remains untrusted."""


class _TrustBundleValidationTests(_ValidationTests):
    """Outcomes when trust bundles are supplied.

    Named for the *inputs*, not the outcome, because supplying a bundle does not imply
    trust: an intermediate without a CA anchors nothing and still validates as untrusted.

    Mixed into the two variations that accept trust bundles; ``from_embedded_key`` accepts
    none and so is excluded rather than skipped.
    """

    #: Argument-form coverage per bundle configuration, with the outcome each must produce.
    _ARGUMENT_FORM_CASES = (
        (CA_ONLY, ValidationResult.VALIDATION_SUCCESS),
        (INTERMEDIATE_ONLY, ValidationResult.UNTRUSTED_VALIDATION_SUCCESS),
        (CA_AND_INTERMEDIATE, ValidationResult.VALIDATION_SUCCESS),
    )

    def test_trust_bundle_argument_forms(self) -> None:
        """Both trust bundles accept every argument form, in every configuration.

        Driven once per variation rather than crossed with every outcome, which would
        multiply the case count without covering anything new. The expected result varies
        by configuration, so a loader that silently ignored ``ca_bundle_pem`` -- and
        thereby downgraded a trusted result -- is caught here as well.
        """
        combo = self._combos(SIMPLE_CERTS_DIR)[0]
        signed = _signed_sbom(combo, UNENCRYPTED, None)
        anchor = self._require(_cert_path(combo, UNENCRYPTED))
        positional = self.valid_positional(combo, UNENCRYPTED, signed)
        for bundles, expected in self._ARGUMENT_FORM_CASES:
            for form, build in _MATERIAL_FORM_BUILDERS:
                with self.subTest(bundles="+".join(bundles), arg_form=form):
                    with ExitStack() as stack:
                        # One build call per parameter, never one value reused across
                        # them: a BinaryIO is readable once, so sharing a handle would
                        # leave the second bundle reading an exhausted stream.
                        kwargs = {
                            f"{name}_bundle_pem": build(anchor, stack)
                            for name in bundles
                        }
                        # Checked on streams only. Immutable forms may legitimately be
                        # the same object -- Path caches its own __str__ -- and sharing
                        # those is harmless, since only a stream carries a read position.
                        streams = [v for v in kwargs.values() if hasattr(v, "read")]
                        self.assertEqual(
                            len({id(s) for s in streams}),
                            len(streams),
                            "each bundle parameter must receive its own stream",
                        )
                        verifier = self.call(positional, **kwargs)
                        result = verifier.signature_validates(copy.deepcopy(signed))
                    self.assertIs(
                        result,
                        expected,
                        f"expected {expected!r} for {'+'.join(bundles)}, got {result!r}",
                    )


# --- Behaviour: unusable input ----------------------------------------------------


class _InvalidInputTests:
    """Unusable input raises ``KeyLoadException``.

    ``assertRaises`` is deliberately narrow: any other exception type propagates and marks
    the case as an error, so a leaked ``TypeError``/``ValueError``/``FileNotFoundError`` is
    reported rather than silently accepted.

    Each accepted parameter is driven bad while the others stay valid, so a factory that
    validates only its positional argument is caught.
    """

    def _parameters(self) -> tuple[str, ...]:
        """The parameter names this variation accepts, positional first."""
        names = ("positional",)
        if self.supports_trust:
            names += ("ca_bundle_pem", "intermediate_bundle_pem")
        return names

    def _baseline(self, combo: Path, tag: str) -> tuple[Any, dict[str, Any]]:
        """A positional argument and keyword set that would otherwise construct cleanly.

        Signed with the default digest: these tests are about argument handling, and
        sweeping hashes here would repeat identical rejections.
        """
        signed = _signed_sbom(combo, tag, None)
        return self.valid_positional(combo, tag, signed), {}

    def _call_with_bad(self, combo: Path, tag: str, parameter: str, value: Any) -> None:
        positional, kwargs = self._baseline(combo, tag)
        if parameter == "positional":
            self.call(value, **kwargs)
        else:
            self.call(positional, **{**kwargs, parameter: value})

    def test_nonexistent_path_raises(self) -> None:
        """Paths that do not exist are rejected.

        The trust bundles accept ``str``; the ``sbom`` positional of the embedded
        variations does not, since ``str`` is not ``os.PathLike``, so only ``Path`` is
        driven through it.
        """
        combo = self._combos(SIMPLE_CERTS_DIR)[0]
        self.assertFalse(
            Path(MISSING_PATH).exists(), f"{MISSING_PATH} unexpectedly exists"
        )
        for parameter in self._parameters():
            forms: tuple[tuple[str, Any], ...] = (("Path", Path(MISSING_PATH)),)
            if parameter != "positional" or not self.positional_is_sbom:
                forms += (("str", MISSING_PATH),)
            for form, value in forms:
                with self.subTest(parameter=parameter, arg_form=form):
                    with self.assertRaises(KeyLoadException):
                        self._call_with_bad(combo, UNENCRYPTED, parameter, value)

    def test_text_stream_raises(self) -> None:
        """Text-mode streams are rejected; the factories need bytes, not str."""
        combo = self._combos(SIMPLE_CERTS_DIR)[0]
        source = self._require(self.positional_text_stream_source(combo, UNENCRYPTED))
        for parameter in self._parameters():
            for form, value in _iter_text_stream_forms(source):
                with self.subTest(parameter=parameter, arg_form=form):
                    self.assertIsInstance(value, io.TextIOBase)
                    with self.assertRaises(KeyLoadException):
                        self._call_with_bad(combo, UNENCRYPTED, parameter, value)

    def test_integer_raises(self) -> None:
        """Integers are rejected rather than treated as file descriptors."""
        combo = self._combos(SIMPLE_CERTS_DIR)[0]
        for parameter in self._parameters():
            for value in NON_KEY_INTEGERS:
                with self.subTest(parameter=parameter, value=value):
                    with self.assertRaises(KeyLoadException):
                        self._call_with_bad(combo, UNENCRYPTED, parameter, value)


# --- Per-hash test generation -----------------------------------------------------


def _add_per_hash_tests(cls: type) -> type:
    """Attach one validation test to ``cls`` for every ``HashAlgorithm`` member.

    The member is bound as a default argument rather than captured, so each generated
    method keeps its own value instead of sharing the loop variable. Which specs are
    attached depends on the mixed-in behaviour: the untrusted classes assert the
    no-anchor outcomes, the trusted classes assert the anchored ones.
    """
    if issubclass(cls, _TrustBundleValidationTests):
        specs = (
            (
                "test_ca_bundle",
                CA_ONLY,
                False,
                ValidationResult.VALIDATION_SUCCESS,
                "with the signing certificate as ca_bundle_pem",
            ),
            (
                "test_ca_and_intermediate_bundles",
                CA_AND_INTERMEDIATE,
                False,
                ValidationResult.VALIDATION_SUCCESS,
                "with the signing certificate as both ca_bundle_pem and "
                "intermediate_bundle_pem",
            ),
            (
                "test_intermediate_bundle_without_ca",
                INTERMEDIATE_ONLY,
                False,
                ValidationResult.UNTRUSTED_VALIDATION_SUCCESS,
                "with intermediate_bundle_pem but no ca_bundle_pem, which anchors "
                "nothing and so cannot confer trust",
            ),
            (
                "test_ca_bundle_tampered",
                CA_ONLY,
                True,
                ValidationResult.VALIDATION_FAIL,
                "with the signing certificate as ca_bundle_pem and a mutated version key",
            ),
            (
                "test_ca_and_intermediate_bundles_tampered",
                CA_AND_INTERMEDIATE,
                True,
                ValidationResult.VALIDATION_FAIL,
                "with both bundles supplied and a mutated version key",
            ),
            (
                "test_intermediate_bundle_without_ca_tampered",
                INTERMEDIATE_ONLY,
                True,
                ValidationResult.VALIDATION_FAIL,
                "with intermediate_bundle_pem but no ca_bundle_pem and a mutated "
                "version key",
            ),
        )
    else:
        specs = (
            (
                "test_untrusted_valid_signature",
                NO_BUNDLES,
                False,
                ValidationResult.UNTRUSTED_VALIDATION_SUCCESS,
                "with no trust anchor",
            ),
            (
                "test_untrusted_tampered_signature",
                NO_BUNDLES,
                True,
                ValidationResult.VALIDATION_FAIL,
                "with no trust anchor and a mutated version key",
            ),
        )

    for prefix, bundles, tamper, expected, suffix in specs:

        def default_method(
            self,
            bundles: tuple[str, ...] = bundles,
            tamper: bool = tamper,
            expected: ValidationResult = expected,
        ) -> None:
            self._assert_outcome(
                None, bundles, tamper, expected, self._non_rsa_combos()
            )

        name = f"{prefix}_default_hash"
        default_method.__name__ = name
        default_method.__qualname__ = f"{cls.__name__}.{name}"
        default_method.__doc__ = (
            f"Non-RSA material, digest chosen by the signer: verified through "
            f"{cls.variation} in every argument form, {suffix}, expecting "
            f"{expected.name}."
        )
        setattr(cls, name, default_method)

        for variation in SIGN_PROVENANCE_BUILDERS:

            def provenance_method(
                self,
                bundles: tuple[str, ...] = bundles,
                tamper: bool = tamper,
                expected: ValidationResult = expected,
                variation: str = variation,
            ) -> None:
                self._assert_outcome(
                    None,
                    bundles,
                    tamper,
                    expected,
                    self._combos(SIMPLE_CERTS_DIR),
                    provenance=variation,
                )

            name = f"{prefix}_provenance_{variation}"
            provenance_method.__name__ = name
            provenance_method.__qualname__ = f"{cls.__name__}.{name}"
            provenance_method.__doc__ = (
                f"sign_sbom given provenance variation {variation!r}: the SBOM still signs "
                f"and, verified through {cls.variation}, {suffix}, still yields "
                f"{expected.name}."
            )
            setattr(cls, name, provenance_method)

        for member in HashAlgorithm:

            def method(
                self,
                hash_alg: HashAlgorithm = member,
                bundles: tuple[str, ...] = bundles,
                tamper: bool = tamper,
                expected: ValidationResult = expected,
            ) -> None:
                self._assert_outcome(
                    hash_alg, bundles, tamper, expected, self._rsa_combos()
                )

            name = f"{prefix}_rsa_{member.name}"
            method.__name__ = name
            method.__qualname__ = f"{cls.__name__}.{name}"
            method.__doc__ = (
                f"RSA material signed with hash={member.name}: verified through "
                f"{cls.variation} in every argument form, {suffix}, expecting "
                f"{expected.name}."
            )
            setattr(cls, name, method)
    return cls


# --- Certificate file variation: SbomVerifier.from_cert_file ----------------------


@_add_per_hash_tests
class SbomVerifierCertFileUntrustedTest(
    _CertFileLoader, _UntrustedValidationTests, _CertFixture
):
    """``from_cert_file``: validation with no trust anchor supplied."""

    positional_is_sbom = False


@_add_per_hash_tests
class SbomVerifierCertFileTrustBundleTest(
    _CertFileLoader, _TrustBundleValidationTests, _CertFixture
):
    """``from_cert_file``: validation with trust bundles supplied."""

    positional_is_sbom = False


class SbomVerifierCertFileInvalidInputTest(
    _CertFileLoader, _InvalidInputTests, _CertFixture
):
    """``from_cert_file``: unusable input in place of the certificate or a trust bundle."""

    positional_is_sbom = False


# --- Embedded certificate variation: SbomVerifier.from_embedded_cert --------------


@_add_per_hash_tests
class SbomVerifierEmbeddedCertUntrustedTest(
    _EmbeddedCertLoader, _UntrustedValidationTests, _CertFixture
):
    """``from_embedded_cert``: validation with no trust anchor supplied."""

    positional_is_sbom = True


@_add_per_hash_tests
class SbomVerifierEmbeddedCertTrustBundleTest(
    _EmbeddedCertLoader, _TrustBundleValidationTests, _CertFixture
):
    """``from_embedded_cert``: validation with trust bundles supplied."""

    positional_is_sbom = True


class SbomVerifierEmbeddedCertInvalidInputTest(
    _EmbeddedCertLoader, _InvalidInputTests, _CertFixture
):
    """``from_embedded_cert``: unusable input in place of the SBOM or a trust bundle."""

    positional_is_sbom = True


# --- Embedded key variation: SbomVerifier.from_embedded_key -----------------------


@_add_per_hash_tests
class SbomVerifierEmbeddedKeyUntrustedTest(
    _EmbeddedKeyLoader, _UntrustedValidationTests, _CertFixture
):
    """``from_embedded_key``: a good signature is always untrusted-successful.

    There is no trust-bundle counterpart to this class: the factory accepts no bundles, so
    an embedded public key can never anchor a chain.
    """

    positional_is_sbom = True


class SbomVerifierEmbeddedKeyInvalidInputTest(
    _EmbeddedKeyLoader, _InvalidInputTests, _CertFixture
):
    """``from_embedded_key``: unusable input in place of the SBOM."""

    positional_is_sbom = True


# --- Password types on the signer that produces this suite's fixtures -------------


class SbomSignerPasswordTypeTest(_CertFixture):
    """Password types accepted and rejected by the signer factory.

    Strictly this is ``SbomSigner`` construction behaviour and would sit as naturally in
    ``test_sbom_signer.py``. It lives here because every encrypted fixture in this file is
    unlocked through that keyword: a password form this suite cannot pass is a password
    form whose signed output can never be verified, so the accepted set bounds what the
    rest of this module can cover.

    The declared type is ``str | bytes | None``, and the three values are not
    interchangeable:

        key state      accepted password              rejected
        ------------   ----------------------------   -----------------------------
        encrypted      str, bytes                     None, and every wrong type
        unencrypted    None, or the keyword omitted   (not asserted -- see below)

    ``KeyLoadException`` must come out of the factory itself, not from a later signing
    call, so each assertion wraps nothing but the factory. ``assertRaises`` stays narrow:
    a leaked ``TypeError`` or ``ValueError`` is reported as an error rather than accepted.

    Wrong types are driven against the encrypted tag only. An unencrypted bundle may never
    consult the password at all, so a rejection there would be an implementation choice
    rather than the documented contract.
    """

    def test_valid_password_forms_sign_and_verify(self) -> None:
        """``str`` and ``bytes`` both unlock the key and yield a verifiable SBOM.

        Asserting verification rather than mere construction: a password decoded the wrong
        way could still load a key that then signs unverifiably.
        """
        for combo in self._combos(SIMPLE_CERTS_DIR):
            self._require(_bundle_path(combo, ENCRYPTED))
            for form in ENCRYPTED_PASSWORD_BUILDERS:
                with self.subTest(combo=str(combo), password_form=form):
                    signed = _signed_sbom(
                        combo, ENCRYPTED, None, NO_PROVENANCE, password_form=form
                    )
                    verifier = SbomVerifier.from_cert_file(
                        self._require(_cert_path(combo, ENCRYPTED))
                    )
                    result = verifier.signature_validates(signed)
                    self.assertIs(
                        result,
                        ValidationResult.UNTRUSTED_VALIDATION_SUCCESS,
                        f"password as {form} produced an SBOM that did not verify: "
                        f"{result!r}",
                    )

    def test_password_forms_agree(self) -> None:
        """``str`` and ``bytes`` unlock the same key.

        A factory that mis-encoded one form might still load *a* key and sign with it. This
        pins both forms to the same certificate, so a divergence shows up as a trust
        mismatch rather than passing quietly.
        """
        combo = self._combos(SIMPLE_CERTS_DIR)[0]
        anchor = self._require(_cert_path(combo, ENCRYPTED))
        for form in ENCRYPTED_PASSWORD_BUILDERS:
            with self.subTest(combo=str(combo), password_form=form):
                signed = _signed_sbom(
                    combo, ENCRYPTED, None, NO_PROVENANCE, password_form=form
                )
                verifier = SbomVerifier.from_cert_file(
                    Path(anchor), ca_bundle_pem=Path(anchor)
                )
                self.assertIs(
                    verifier.signature_validates(signed),
                    ValidationResult.VALIDATION_SUCCESS,
                    f"password as {form} did not unlock the key certified by {anchor}",
                )

    def test_none_password_unlocks_unencrypted_key(self) -> None:
        """An unencrypted key takes ``None``, spelled explicitly or by omission.

        Both spellings are driven because they are only the same call if the parameter
        actually defaults to ``None``; a different default would make ``explicit_none``
        the odd one out.
        """
        for combo in self._combos(SIMPLE_CERTS_DIR):
            self._require(_bundle_path(combo, UNENCRYPTED))
            for form in UNENCRYPTED_PASSWORD_FORMS:
                with self.subTest(combo=str(combo), password_form=form):
                    signed = _signed_sbom(
                        combo, UNENCRYPTED, None, NO_PROVENANCE, password_form=form
                    )
                    verifier = SbomVerifier.from_cert_file(
                        self._require(_cert_path(combo, UNENCRYPTED))
                    )
                    result = verifier.signature_validates(signed)
                    self.assertIs(
                        result,
                        ValidationResult.UNTRUSTED_VALIDATION_SUCCESS,
                        f"password {form} on an unencrypted key produced an SBOM that "
                        f"did not verify: {result!r}",
                    )

    def test_none_password_on_encrypted_key_raises(self) -> None:
        """``None`` is a valid *type* but not a valid value for an encrypted key.

        Driven both ways, since a factory might reject an explicit ``None`` while treating
        an omitted keyword as some other default.
        """
        combo = self._combos(SIMPLE_CERTS_DIR)[0]
        bundle = self._require(_bundle_path(combo, ENCRYPTED))
        with self.subTest(password_form="explicit_none"):
            with self.assertRaises(KeyLoadException):
                SbomSigner.from_cert_bundle(Path(bundle), password=None)
        with self.subTest(password_form="omitted"):
            with self.assertRaises(KeyLoadException):
                SbomSigner.from_cert_bundle(Path(bundle))

    def test_integer_password_raises(self) -> None:
        """Integers are rejected rather than coerced or treated as a handle.

        Called out separately from the other wrong types because an integer is the form
        most likely to be silently accepted -- ``0`` and ``1`` are valid file descriptors,
        and ``True``/``False`` are integers that a loose truthiness check would admit.
        """
        combo = self._combos(SIMPLE_CERTS_DIR)[0]
        bundle = self._require(_bundle_path(combo, ENCRYPTED))
        for label, value in INVALID_PASSWORD_VALUES:
            if not isinstance(value, int):
                continue
            with self.subTest(kind=label, value=value):
                with self.assertRaises(KeyLoadException):
                    SbomSigner.from_cert_bundle(Path(bundle), password=value)

    def test_buffer_password_types_raise(self) -> None:
        """``bytearray`` and ``memoryview`` are rejected: the type is ``bytes``, not buffer.

        These carry the correct password bytes, so a factory that duck-typed its argument
        would unlock the key and pass. Separated from the other wrong types because they
        are the only cases where the *value* is right and only the container is wrong.
        """
        combo = self._combos(SIMPLE_CERTS_DIR)[0]
        bundle = self._require(_bundle_path(combo, ENCRYPTED))
        for label, value in INVALID_PASSWORD_VALUES:
            if not isinstance(value, (bytearray, memoryview)):
                continue
            with self.subTest(kind=label):
                self.assertNotIsInstance(value, (str, bytes), "not a buffer type")
                with self.assertRaises(KeyLoadException):
                    SbomSigner.from_cert_bundle(Path(bundle), password=value)

    def test_other_invalid_password_types_raise(self) -> None:
        """Every remaining non-``str``, non-``bytes`` value is rejected."""
        combo = self._combos(SIMPLE_CERTS_DIR)[0]
        bundle = self._require(_bundle_path(combo, ENCRYPTED))
        for label, value in INVALID_PASSWORD_VALUES:
            if isinstance(value, (int, bytearray, memoryview)):
                continue
            with self.subTest(kind=label, value=repr(value)):
                with self.assertRaises(KeyLoadException):
                    SbomSigner.from_cert_bundle(Path(bundle), password=value)

    def test_invalid_password_table_is_well_formed(self) -> None:
        """Guard the table: nothing in it may be an accepted type, and it must stay complete.

        A ``str`` or ``bytes`` entry creeping in would turn an assertion that the value is
        *rejected* into an assertion that a valid password fails -- failing for the right
        reason while documenting the wrong contract. The buffer and integer checks pin the
        two narrowings that are easiest to lose in a refactor.
        """
        self.assertTrue(INVALID_PASSWORD_VALUES, "no invalid password values to drive")
        kinds = {label for label, _ in INVALID_PASSWORD_VALUES}
        self.assertEqual(
            len(kinds), len(INVALID_PASSWORD_VALUES), "duplicate labels in the table"
        )
        self.assertTrue(
            any(isinstance(v, int) for _, v in INVALID_PASSWORD_VALUES),
            "no integer password case, which is the one explicitly required",
        )
        for buffer_type in (bytearray, memoryview):
            self.assertTrue(
                any(isinstance(v, buffer_type) for _, v in INVALID_PASSWORD_VALUES),
                f"{buffer_type.__name__} is not covered; the accepted type is bytes, "
                f"not ByteString, so it must be rejected",
            )
        for label, value in INVALID_PASSWORD_VALUES:
            with self.subTest(kind=label):
                self.assertNotIsInstance(
                    value, (str, bytes), f"{label} is a valid type"
                )
                self.assertIsNotNone(
                    value,
                    "None is a valid value restricted to unencrypted keys, not a wrong "
                    "type; it is covered by test_none_password_on_encrypted_key_raises",
                )


# --- Sanity check: independently produced signed material -------------------------


class SbomVerifierCycloneDxExampleTest(_CertFixture):
    """One case against an SBOM this codebase did not sign.

    Every other test in this file verifies material the suite signed moments earlier,
    which is a closed loop: a verifier that agreed with a broken signer would pass
    throughout, because both sides share the same mistake. This case breaks the loop by
    verifying the signed example published by the CycloneDX project.

    Only ``from_embedded_key`` applies. The example carries its verification key inline,
    and the fixture tree holds no trust anchor for whoever signed it, so
    ``UNTRUSTED_VALIDATION_SUCCESS`` is the only outcome available -- which is exactly
    what that factory returns for any good signature.

    Deliberately not parameterised by ``HashAlgorithm``: the algorithm is fixed by the
    published file, not chosen here. There is no tamper counterpart either, since the
    per-combination tests already own that behaviour; this case exists to prove
    interoperability, not detection.
    """

    def test_embedded_key_validates_cyclonedx_example(self) -> None:
        """The published example verifies through ``from_embedded_key``, in every form."""
        sbom = _load_sbom(self._require(CYCLONEDX_SIGNED_PATH))
        for pos_form, positional in _iter_sbom_forms(sbom):
            with self.subTest(positional_form=pos_form):
                # Built once per positional form, for the same reason as _assert_outcome:
                # a BinaryIO positional is readable exactly once.
                verifier = SbomVerifier.from_embedded_key(positional)
                self.assertIsInstance(
                    verifier,
                    SbomVerifier,
                    f"factory returned {type(verifier).__name__}, expected SbomVerifier",
                )
            for sbom_form, sbom_arg in _iter_sbom_forms(sbom):
                with self.subTest(positional_form=pos_form, sbom_form=sbom_form):
                    result = verifier.signature_validates(sbom_arg)
                    self.assertIs(
                        result,
                        ValidationResult.UNTRUSTED_VALIDATION_SUCCESS,
                        f"expected UNTRUSTED_VALIDATION_SUCCESS for the CycloneDX "
                        f"example, got {result!r}",
                    )


if __name__ == "__main__":
    unittest.main()
