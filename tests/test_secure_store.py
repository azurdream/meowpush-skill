"""Storage tests use only temporary directories and fake values."""

import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from secure_store import LOCK_NAME, SecureStore, StoreError


class SecureStoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name) / "store"
        self.store = SecureStore(self.directory)

    def test_missing_file_and_unicode_round_trip(self):
        self.assertIsNone(self.store.read_json("credentials.json"))
        data = {"version": 1, "profiles": {"example": {"push_key": "FAKE-secret"}}, "text": "caf\u00e9"}
        with self.store.lock():
            self.store.write_json("credentials.json", data)
        self.assertEqual(self.store.read_json("credentials.json"), data)
        self.assertFalse((self.directory / LOCK_NAME).exists())

    def test_reject_path_traversal(self):
        for name in ("../outside", "folder/name", "folder\\name", "", ".", "..", "file:stream", "file.", "file "):
            with self.subTest(name=name), self.assertRaises(StoreError) as raised:
                self.store.read_json(name)
            self.assertEqual(raised.exception.code, "invalid_filename")

    def test_writer_lock_is_exclusive_and_exception_safe(self):
        with self.store.lock():
            with self.assertRaises(StoreError) as raised:
                with SecureStore(self.directory).lock():
                    self.fail("A second lock was acquired")
            self.assertEqual(raised.exception.code, "store_busy")
        with self.assertRaisesRegex(RuntimeError, "deliberate"):
            with self.store.lock():
                raise RuntimeError("deliberate")
        with self.store.lock():
            self.store.write_json("works.json", {"ok": True})

    def test_lock_excludes_an_independent_process(self):
        script_dir = str(Path(__file__).resolve().parents[1] / "scripts")
        program = (
            "import sys; from pathlib import Path; "
            "sys.path.insert(0, sys.argv[1]); "
            "from secure_store import SecureStore; "
            "s=SecureStore(Path(sys.argv[2])); "
            "ctx=s.lock(); ctx.__enter__()"
        )
        with self.store.lock():
            result = subprocess.run([sys.executable, "-c", program, script_dir, str(self.directory)],
                                    capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("credential lock", result.stderr)

    def test_atomic_replacement_failure_keeps_previous_file(self):
        self.store.write_json("credentials.json", {"version": 1})
        with mock.patch("secure_store.os.replace", side_effect=OSError("FAKE-private-value")):
            with self.assertRaises(StoreError) as raised:
                self.store.write_json("credentials.json", {"version": 2})
        self.assertNotIn("FAKE-private-value", str(raised.exception))
        self.assertEqual(self.store.read_json("credentials.json"), {"version": 1})
        self.assertEqual(sorted(path.name for path in self.directory.iterdir()), ["credentials.json"])

    def test_remove_is_idempotent(self):
        self.store.write_json("state.json", {"status": "pending"})
        self.store.remove("state.json")
        self.store.remove("state.json")
        self.assertIsNone(self.store.read_json("state.json"))

    @unittest.skipIf(os.name == "nt", "POSIX permission assertions")
    def test_permissions_and_staging_restrictions(self):
        original_replace = os.replace
        observed = []

        def inspect_replace(source, destination, **kwargs):
            info = os.stat(source, dir_fd=kwargs["src_dir_fd"], follow_symlinks=False)
            observed.append(stat.S_IMODE(info.st_mode))
            return original_replace(source, destination, **kwargs)

        with mock.patch("secure_store.os.replace", side_effect=inspect_replace):
            self.store.write_json("credentials.json", {"fake": "value"})
        self.assertEqual(observed, [0o600])
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.directory / "credentials.json").stat().st_mode), 0o600)

    @unittest.skipIf(os.name == "nt", "POSIX permission assertions")
    def test_reject_unsafe_directory_without_repair(self):
        self.directory.mkdir(mode=0o755)
        self.directory.chmod(0o755)
        with self.assertRaises(StoreError):
            self.store.ensure()
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o755)

    @unittest.skipIf(os.name == "nt", "POSIX permission assertions")
    def test_reject_unsafe_file_without_read_write_or_remove(self):
        self.store.write_json("credentials.json", {"fake": "value"})
        target = self.directory / "credentials.json"
        target.chmod(0o644)
        for operation in (lambda: self.store.read_json("credentials.json"),
                          lambda: self.store.write_json("credentials.json", {"changed": True}),
                          lambda: self.store.remove("credentials.json")):
            with self.assertRaises(StoreError):
                operation()
        self.assertEqual(json.loads(target.read_text()), {"fake": "value"})
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o644)

    @unittest.skipIf(os.name == "nt", "POSIX link and inode assertions")
    def test_reject_file_and_directory_symlinks(self):
        outside = Path(self.temporary.name) / "outside.json"
        outside.write_text('{"fake":"outside"}')
        outside.chmod(0o600)
        self.store.ensure()
        (self.directory / "linked.json").symlink_to(outside)
        for operation in (lambda: self.store.read_json("linked.json"),
                          lambda: self.store.write_json("linked.json", {}),
                          lambda: self.store.remove("linked.json")):
            with self.assertRaises(StoreError):
                operation()
        self.assertEqual(json.loads(outside.read_text()), {"fake": "outside"})
        alias = Path(self.temporary.name) / "alias"
        alias.symlink_to(self.directory, target_is_directory=True)
        with self.assertRaises(StoreError):
            SecureStore(alias).ensure()

    @unittest.skipIf(os.name == "nt", "POSIX link and inode assertions")
    def test_reject_hardlinked_file(self):
        self.store.write_json("credentials.json", {"fake": "value"})
        os.link(self.directory / "credentials.json", self.directory / "alias.json")
        with self.assertRaises(StoreError):
            self.store.read_json("credentials.json")

    @unittest.skipIf(os.name == "nt", "POSIX descriptor verification hook")
    def test_atomic_replacement_during_read_preserves_valid_snapshot(self):
        self.store.write_json("credentials.json", {"version": 1})
        writer = SecureStore(self.directory)
        original_verify = self.store._verify_posix
        replaced = False

        def replace_after_open(fd, directory=False):
            nonlocal replaced
            if not directory and not replaced:
                replaced = True
                with writer.lock():
                    writer.write_json("credentials.json", {"version": 2})
                self.assertEqual(os.fstat(fd).st_nlink, 0)
            return original_verify(fd, directory)

        with mock.patch.object(self.store, "_verify_posix", side_effect=replace_after_open):
            snapshot = self.store.read_json("credentials.json")
        self.assertTrue(replaced)
        self.assertEqual(snapshot, {"version": 1})
        self.assertEqual(self.store.read_json("credentials.json"), {"version": 2})

    @unittest.skipIf(os.name == "nt", "POSIX FIFO assertions")
    def test_reject_fifo_without_blocking(self):
        self.store.ensure()
        os.mkfifo(self.directory / "pipe", mode=0o600)
        with self.assertRaises(StoreError):
            self.store.read_json("pipe")

    def test_reject_malformed_duplicate_and_non_object_json(self):
        self.store.ensure()
        for raw in (b"broken FAKE-private-value", b"[]", b'{"a":1,"a":2}', b'{"a":NaN}', b"\xff"):
            self.store.write_json("invalid.json", {})
            (self.directory / "invalid.json").write_bytes(raw)
            with self.subTest(raw=raw), self.assertRaises(StoreError) as raised:
                self.store.read_json("invalid.json")
            self.assertEqual(raised.exception.code, "invalid_store")
            self.assertNotIn("FAKE-private-value", str(raised.exception))

    def test_invalid_write_preserves_existing_file(self):
        self.store.write_json("credentials.json", {"valid": True})
        for data in ([], {"value": float("nan")}, {"value": object()}):
            with self.assertRaises(StoreError):
                self.store.write_json("credentials.json", data)
            self.assertEqual(self.store.read_json("credentials.json"), {"valid": True})

    @unittest.skipUnless(os.name == "nt", "Requires native Windows ACL execution")
    def test_native_windows_protected_creation(self):
        self.store.ensure()
        with self.store.lock():
            self.store.write_json("credentials.json", {"fake": "value"})
        self.assertEqual(self.store.read_json("credentials.json"), {"fake": "value"})
        self.store.remove("credentials.json")


if __name__ == "__main__":
    unittest.main()
