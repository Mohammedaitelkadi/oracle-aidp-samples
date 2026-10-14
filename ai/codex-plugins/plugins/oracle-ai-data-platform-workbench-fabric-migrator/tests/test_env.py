import io
import os
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from fabric_aidp._env import load_dotenv


class DotenvTests(unittest.TestCase):
    def _load(self, body):
        with TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {}, clear=True):
            path = Path(tmp) / ".env"
            path.write_text(body, encoding="utf-8")
            load_dotenv(path)
            return dict(os.environ)

    def test_the_tools_own_keys_are_loaded(self):
        env = self._load("OCI_NAMESPACE=ns\nAIDP_WORKSPACE_KEY='ws'\n")
        self.assertEqual((env["OCI_NAMESPACE"], env["AIDP_WORKSPACE_KEY"]), ("ns", "ws"))

    def test_other_keys_are_ignored(self):
        # NODE_OPTIONS=--require ./x.js would run code inside the M parser.
        env = self._load("NODE_OPTIONS=--require ./x.js\nPATH=/tmp\nOCI_NAMESPACE=ns\n")
        self.assertNotIn("NODE_OPTIONS", env)
        self.assertNotIn("PATH", env)

    def test_a_bom_does_not_eat_the_first_key(self):
        with TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {}, clear=True):
            path = Path(tmp) / ".env"
            path.write_bytes(b"\xef\xbb\xbfOCI_NAMESPACE=ns\n")
            load_dotenv(path)
            self.assertEqual(os.environ.get("OCI_NAMESPACE"), "ns")


class UntrustedDotenvTests(unittest.TestCase):
    """A .env is read from wherever the CLI runs -- an export someone sent,
    a shared work root -- so it is untrusted input. Flagged, unfixed, in the
    oracle-samples security review (#146): the loader took any AIDP_/OCI_/
    FABRIC_ key, and those values also reach the `aidp` CLI `publish` runs."""

    def _load(self, body, *, mode=0o600, shell=None):
        with TemporaryDirectory() as tmp, mock.patch.dict(os.environ, shell or {}, clear=True):
            path = Path(tmp) / ".env"
            path.write_text(body, encoding="utf-8")
            path.chmod(mode)
            with redirect_stderr(io.StringIO()) as err:
                load_dotenv(path)
            return dict(os.environ), err.getvalue()

    def test_keys_that_redirect_requests_or_credentials_are_not_taken(self):
        env, err = self._load("AIDP_ENDPOINT=https://evil.example\n"
                              "OCI_CONFIG_FILE=/tmp/their-key\n"
                              "AIDP_SECRET_TOKEN=s3cret\nOCI_NAMESPACE=ns\n")
        for key in ("AIDP_ENDPOINT", "OCI_CONFIG_FILE", "AIDP_SECRET_TOKEN"):
            with self.subTest(key=key):
                self.assertNotIn(key, env)
                self.assertIn(key, err)
        self.assertEqual(env["OCI_NAMESPACE"], "ns")

    def test_the_warning_names_keys_never_values(self):
        _, err = self._load("AIDP_SECRET_TOKEN=s3cret-value\nAIDP_ENDPOINT=https://evil.example\n")
        self.assertNotIn("s3cret-value", err)
        self.assertNotIn("evil.example", err)

    def test_every_allowed_key_is_taken(self):
        from fabric_aidp._env import ALLOWED_KEYS
        env, err = self._load("".join(f"{k}=v\n" for k in sorted(ALLOWED_KEYS)))
        self.assertEqual({k: env.get(k) for k in ALLOWED_KEYS}, {k: "v" for k in ALLOWED_KEYS})
        self.assertEqual(err, "")

    def test_a_shell_value_is_never_overridden(self):
        env, _ = self._load("OCI_NAMESPACE=from-file\n", shell={"OCI_NAMESPACE": "from-shell"})
        self.assertEqual(env["OCI_NAMESPACE"], "from-shell")

    def test_a_stray_unrelated_key_is_ignored_silently(self):
        env, err = self._load("NODE_OPTIONS=--require ./x.js\nOCI_NAMESPACE=ns\n")
        self.assertNotIn("NODE_OPTIONS", env)
        self.assertEqual(err, "")

    def test_a_file_others_can_write_is_not_read_at_all(self):
        """On Windows st_mode carries no ACL bits, so the check is skipped by
        design and the file IS read -- asserted, not skipped, so this test
        says something true on every platform."""
        for mode in (0o620, 0o602, 0o666):
            with self.subTest(mode=oct(mode)):
                env, err = self._load("OCI_NAMESPACE=ns\n", mode=mode)
                if os.name == "nt":
                    self.assertEqual(env.get("OCI_NAMESPACE"), "ns")
                    continue
                self.assertNotIn("OCI_NAMESPACE", env)
                self.assertIn("other users can write", err)

    def test_a_file_another_user_owns_is_not_read_at_all(self):
        if not hasattr(os, "getuid"):  # Windows: no owner check, file is read
            env, _ = self._load("OCI_NAMESPACE=ns\n")
            self.assertEqual(env.get("OCI_NAMESPACE"), "ns")
            return
        with mock.patch("os.getuid", return_value=os.getuid() + 1):
            env, err = self._load("OCI_NAMESPACE=ns\n")
        self.assertNotIn("OCI_NAMESPACE", env)
        self.assertIn("owned by another user", err)

    def test_a_readable_private_file_is_read(self):
        env, err = self._load("OCI_NAMESPACE=ns\n", mode=0o644)
        self.assertEqual(env.get("OCI_NAMESPACE"), "ns")
        self.assertEqual(err, "")


if __name__ == "__main__":
    unittest.main()
