"""Unit tests for :class:`cxone_sbom.crypto.SupportedAlgorithms`.

Assumptions about the API under test:

1. Lookup is by *value*, i.e. ``SupportedAlgorithms("ES256")`` resolves to a
   member, and an unsupported string raises ``UnsupportedAlgorithm``
   (presumably via an ``Enum._missing_`` hook) rather than ``ValueError``.
2. The supported EC curve identifiers ("P-256", "P-384", "P-521") are aliases
   that resolve to the corresponding ECDSA member, so they are accepted as
   lookup input but are not members in their own right.
3. HMAC algorithm strings (HS256/HS384/HS512) are rejected, since they are MAC
   algorithms rather than key-pair algorithms.
"""

import unittest

from cxone_sbom.crypto import SupportedAlgorithms, UnsupportedAlgorithm

# --- expected vocabulary ---------------------------------------------------

# JSF / CycloneDX signature algorithms that use a key pair.
RSA_PKCS1_ALGORITHMS = ["RS256", "RS384", "RS512"]
RSA_PSS_ALGORITHMS = ["PS256", "PS384", "PS512"]
ECDSA_ALGORITHMS = ["ES256", "ES384", "ES512"]
EDDSA_ALGORITHMS = ["Ed25519", "Ed448"]

KEY_PAIR_ALGORITHMS = (
    RSA_PKCS1_ALGORITHMS + RSA_PSS_ALGORITHMS + ECDSA_ALGORITHMS + EDDSA_ALGORITHMS
)

# Supported EC curve identifier -> the ECDSA algorithm it resolves to.
# Note the deliberate asymmetry: P-521 pairs with ES512, not "ES521".
CURVE_TO_ALGORITHM = {
    "P-256": "ES256",
    "P-384": "ES384",
    "P-521": "ES512",
}

HMAC_ALGORITHMS = ["HS256", "HS384", "HS512"]


class LookupTestCase(unittest.TestCase):
    """Shared assertions for values the enum is expected to accept."""

    def assert_resolves(self, value):
        member = SupportedAlgorithms(value)
        self.assertIsInstance(member, SupportedAlgorithms)
        return member

    def assert_idempotent(self, value):
        member = SupportedAlgorithms(value)
        self.assertIs(SupportedAlgorithms(member), member)
        self.assertIs(SupportedAlgorithms(member.value), member)


# --- supported key pair algorithms -----------------------------------------


class TestSupportedKeyPairAlgorithms(LookupTestCase):
    def test_lookup_returns_member(self):
        for algorithm in KEY_PAIR_ALGORITHMS:
            with self.subTest(algorithm=algorithm):
                self.assert_resolves(algorithm)

    def test_value_round_trips(self):
        for algorithm in KEY_PAIR_ALGORITHMS:
            with self.subTest(algorithm=algorithm):
                self.assertEqual(SupportedAlgorithms(algorithm).value, algorithm)

    def test_lookup_is_idempotent(self):
        for algorithm in KEY_PAIR_ALGORITHMS:
            with self.subTest(algorithm=algorithm):
                self.assert_idempotent(algorithm)

    def test_algorithms_are_distinct_members(self):
        members = {SupportedAlgorithms(alg) for alg in KEY_PAIR_ALGORITHMS}
        self.assertEqual(len(members), len(KEY_PAIR_ALGORITHMS))


# --- EC curve aliases ------------------------------------------------------


class TestEcCurveAliases(LookupTestCase):
    def test_curve_resolves_to_member(self):
        for curve in CURVE_TO_ALGORITHM:
            with self.subTest(curve=curve):
                self.assert_resolves(curve)

    def test_curve_yields_corresponding_ecdsa_algorithm(self):
        for curve, algorithm in CURVE_TO_ALGORITHM.items():
            with self.subTest(curve=curve):
                self.assertIs(
                    SupportedAlgorithms(curve), SupportedAlgorithms(algorithm)
                )

    def test_curve_lookup_reports_the_algorithm_value(self):
        for curve, algorithm in CURVE_TO_ALGORITHM.items():
            with self.subTest(curve=curve):
                self.assertEqual(SupportedAlgorithms(curve).value, algorithm)

    def test_p521_maps_to_es512(self):
        """Guards the one pairing where the numbers do not line up."""
        self.assertIs(SupportedAlgorithms("P-521"), SupportedAlgorithms("ES512"))

    def test_curve_lookup_is_idempotent(self):
        for curve in CURVE_TO_ALGORITHM:
            with self.subTest(curve=curve):
                self.assert_idempotent(curve)

    def test_every_ecdsa_algorithm_is_reachable_by_curve(self):
        via_curve = {SupportedAlgorithms(c) for c in CURVE_TO_ALGORITHM}
        direct = {SupportedAlgorithms(a) for a in ECDSA_ALGORITHMS}
        self.assertSetEqual(via_curve, direct)

    def test_curves_are_not_separate_members(self):
        declared = {member.value for member in SupportedAlgorithms}
        for curve in CURVE_TO_ALGORITHM:
            with self.subTest(curve=curve):
                self.assertNotIn(curve, declared)

    def test_curves_do_not_resolve_to_non_ecdsa_algorithms(self):
        non_ecdsa = {
            SupportedAlgorithms(a)
            for a in RSA_PKCS1_ALGORITHMS + RSA_PSS_ALGORITHMS + EDDSA_ALGORITHMS
        }
        for curve in CURVE_TO_ALGORITHM:
            with self.subTest(curve=curve):
                self.assertNotIn(SupportedAlgorithms(curve), non_ecdsa)

    def test_unsupported_curve_spellings_are_rejected(self):
        # "P-512" is a common slip; 521 is the correct bit length.
        for value in ["P-512", "P-224", "P256", "p-256", "secp256r1", "prime256v1"]:
            with self.subTest(value=value):
                with self.assertRaises(UnsupportedAlgorithm):
                    SupportedAlgorithms(value)


# --- enum shape ------------------------------------------------------------


class TestEnumShape(unittest.TestCase):
    def test_member_values_are_unique(self):
        values = [member.value for member in SupportedAlgorithms]
        self.assertCountEqual(values, set(values))

    def test_all_expected_algorithms_are_members(self):
        declared = {member.value for member in SupportedAlgorithms}
        self.assertLessEqual(set(KEY_PAIR_ALGORITHMS), declared)

    def test_no_unexpected_members(self):
        declared = {member.value for member in SupportedAlgorithms}
        self.assertSetEqual(declared, set(KEY_PAIR_ALGORITHMS))


# --- rejected algorithms ---------------------------------------------------


class TestUnsupportedAlgorithms(unittest.TestCase):
    def test_hmac_algorithms_are_rejected(self):
        for algorithm in HMAC_ALGORITHMS:
            with self.subTest(algorithm=algorithm):
                with self.assertRaises(UnsupportedAlgorithm):
                    SupportedAlgorithms(algorithm)

    def test_foo_is_rejected(self):
        with self.assertRaises(UnsupportedAlgorithm):
            SupportedAlgorithms("foo")

    def test_other_invalid_strings_are_rejected(self):
        for value in ["", " ", "es256", "ES-256", "RS255", "None"]:
            with self.subTest(value=value):
                with self.assertRaises(UnsupportedAlgorithm):
                    SupportedAlgorithms(value)

    def test_non_string_values_are_rejected(self):
        for value in [None, 256, 1.5, b"ES256", ["ES256"]]:
            with self.subTest(value=value):
                with self.assertRaises(UnsupportedAlgorithm):
                    SupportedAlgorithms(value)

    def test_rejected_value_is_not_a_member(self):
        declared = {member.value for member in SupportedAlgorithms}
        for algorithm in HMAC_ALGORITHMS + ["foo"]:
            with self.subTest(algorithm=algorithm):
                self.assertNotIn(algorithm, declared)

    def test_exception_identifies_the_offending_value(self):
        for algorithm in HMAC_ALGORITHMS + ["foo"]:
            with self.subTest(algorithm=algorithm):
                with self.assertRaises(UnsupportedAlgorithm) as ctx:
                    SupportedAlgorithms(algorithm)
                self.assertIn(algorithm, str(ctx.exception))

    def test_rejection_does_not_leak_raw_enum_value_error(self):
        """Enum lookup raises ValueError natively; ensure it is translated."""
        try:
            SupportedAlgorithms("foo")
        except UnsupportedAlgorithm:
            pass
        except ValueError as err:
            self.fail(f"expected UnsupportedAlgorithm, got {err!r}")
        else:
            self.fail("expected UnsupportedAlgorithm, no exception raised")


class TestUnsupportedAlgorithmException(unittest.TestCase):
    def test_is_an_exception(self):
        self.assertTrue(issubclass(UnsupportedAlgorithm, Exception))

    def test_can_be_raised_and_caught_directly(self):
        with self.assertRaises(UnsupportedAlgorithm):
            raise UnsupportedAlgorithm("foo")


if __name__ == "__main__":
    unittest.main()
