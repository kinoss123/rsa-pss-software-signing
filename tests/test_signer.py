"""Functional tests matching Section 3.4 of the report, plus CLI checks."""
import tempfile
import unittest
from pathlib import Path

from signer import generate_key_pair, main, public_key_fingerprint, sign, verify

SAMPLE = b"Example software release for RSA-PSS integrity verification.\n"


class TestReportCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key, cls.public_key = generate_key_pair()
        cls.signature = sign(SAMPLE, cls.private_key)

    def test_1_original_file_valid(self):
        self.assertTrue(verify(SAMPLE, self.signature, self.public_key))

    def test_2_modified_file_invalid(self):
        self.assertFalse(verify(SAMPLE + b"[modified]", self.signature, self.public_key))

    def test_3_wrong_public_key_invalid(self):
        _, other_public = generate_key_pair()
        self.assertFalse(verify(SAMPLE, self.signature, other_public))

    def test_4_corrupted_signature_invalid(self):
        bad = bytearray(self.signature)
        bad[0] ^= 0x01
        self.assertFalse(verify(SAMPLE, bytes(bad), self.public_key))

    def test_parameters(self):
        self.assertEqual(self.private_key.key_size, 2048)
        self.assertEqual(self.public_key.public_numbers().e, 65537)
        self.assertEqual(len(self.signature), 256)

    def test_pss_is_randomized(self):
        second = sign(SAMPLE, self.private_key)
        self.assertNotEqual(self.signature, second)
        self.assertTrue(verify(SAMPLE, second, self.public_key))


class TestCli(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.file = self.dir / "app.bin"
        self.file.write_bytes(SAMPLE)
        keys = self.dir / "keys"
        self.assertEqual(main(["keygen", "--out-dir", str(keys)]), 0)
        self.private = keys / "private.pem"
        self.public = keys / "public.pem"

    def tearDown(self):
        self._tmp.cleanup()

    def test_sign_then_verify(self):
        self.assertEqual(main(["sign", str(self.file), "--key", str(self.private)]), 0)
        self.assertTrue((self.dir / "app.bin.sig").is_file())
        self.assertEqual(main(["verify", str(self.file), "--key", str(self.public)]), 0)

    def test_verify_fails_after_tampering(self):
        main(["sign", str(self.file), "--key", str(self.private)])
        self.file.write_bytes(SAMPLE + b"x")
        self.assertEqual(main(["verify", str(self.file), "--key", str(self.public)]), 1)

    def test_fingerprint_check(self):
        main(["sign", str(self.file), "--key", str(self.private)])
        from signer import load_public_key

        good = public_key_fingerprint(load_public_key(self.public))
        self.assertEqual(
            main(["verify", str(self.file), "--key", str(self.public), "--fingerprint", good]),
            0,
        )
        self.assertEqual(
            main(["verify", str(self.file), "--key", str(self.public), "--fingerprint", "00" * 32]),
            1,
        )

    def test_keygen_refuses_overwrite(self):
        self.assertEqual(main(["keygen", "--out-dir", str(self.private.parent)]), 2)


if __name__ == "__main__":
    unittest.main()
