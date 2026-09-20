"""Offline checks for the independent HashModuloSink oracle."""

import base64
import hashlib
import importlib.util
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location(
    "ca_oracle", Path(__file__).with_name("ca-oracle.py")
)
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)


class OracleTest(unittest.TestCase):
    def evidence(self, nar, ca_preimage):
        info = {
            "narHash": "sha256-" + base64.b64encode(
                hashlib.sha256(nar).digest()).decode(),
            "narSize": len(nar),
            "ca": {"method": "nar", "hash": "sha256-" + base64.b64encode(
                hashlib.sha256(ca_preimage).digest()).decode()},
        }
        probe = {
            "path": "/nix/store/" + "a" * 32 + "-probe",
            "nar_hash": hashlib.sha256(nar).hexdigest(), "nar_size": len(nar),
            "castore_entry": "entry", "native_castore_entry": "entry",
        }
        return info, probe

    def test_zero_masking_alone_is_not_agreement(self):
        nar = b"x" + b"a" * 32 + b"--" + b"a" * 32
        masked = b"x" + bytes(32) + b"--" + bytes(32)
        for suffix, agrees in ((b"", False), (b"|1|35", True)):
            info, probe = self.evidence(nar, masked + suffix)
            result = oracle.analyze(probe["path"], nar, info, probe, 2)
            self.assertEqual(result["self_positions"], [1, 35])
            self.assertEqual(result["checks"]["native_ca_with_positions"], agrees)
            self.assertEqual(all(result["checks"].values()), agrees)

    def test_partially_zeroed_self_reference_has_different_preimage(self):
        nar = b"x" + bytes(32) + b"--" + b"a" * 32
        masked = b"x" + bytes(32) + b"--" + bytes(32)
        info, probe = self.evidence(nar, masked + b"|35")
        result = oracle.analyze(probe["path"], nar, info, probe, 1)
        self.assertEqual(result["self_positions"], [35])
        self.assertTrue(all(result["checks"].values()))

    def test_no_self_reference_control_and_each_identity_layer(self):
        nar = b"plain"
        info, probe = self.evidence(nar, nar)
        result = oracle.analyze(probe["path"], nar, info, probe, 0)
        self.assertTrue(all(result["checks"].values()))
        for key in ("path", "nar_hash", "nar_size", "castore_entry"):
            with self.subTest(key=key):
                changed = {**probe, key: "different"}
                result = oracle.analyze(probe["path"], nar, info, changed, 0)
                self.assertFalse(all(result["checks"].values()))


if __name__ == "__main__":
    unittest.main()
