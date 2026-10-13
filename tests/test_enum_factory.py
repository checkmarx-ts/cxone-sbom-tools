import unittest

from cryptography.hazmat.primitives import hashes

from cxone_sbom.crypto import HashAlgorithm


def _digest(algorithm, chunks):
    """Hash the given byte chunks with the given algorithm instance."""
    digest = hashes.Hash(algorithm)
    for chunk in chunks:
        digest.update(chunk)
    return digest.finalize()


class TestHashAlgorithm(unittest.TestCase):

    INPUT_CHUNKS = (b"The quick brown fox ", b"jumps over ", b"the lazy dog")

    def test_factory_returns_matching_hashes_class(self):
        for member in HashAlgorithm:
            with self.subTest(member=member.name):
                algorithm = HashAlgorithm.factory(member)
                self.assertEqual(type(algorithm), getattr(hashes, member.name))

    def test_factory_algorithm_produces_same_hash(self):
        for member in HashAlgorithm:
            with self.subTest(member=member.name):
                expected = _digest(getattr(hashes, member.name)(), self.INPUT_CHUNKS)
                actual = _digest(HashAlgorithm.factory(member), self.INPUT_CHUNKS)
                self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()
