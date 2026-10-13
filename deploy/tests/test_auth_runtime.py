import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


DEPLOY = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("install_auth_runtime", DEPLOY / "install-auth-runtime.py")
INSTALLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSTALLER)


class AuthRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name)
        self.build = self.home / "checkout/target/release"
        self.build.mkdir(parents=True)
        self.binary = self.build / "volta-auth-server"
        self.binary.write_text("#!/bin/sh\nprintf 'auth-runtime-ok'\n")
        self.binary.chmod(0o755)

    def test_survives_removal_of_build_and_source_tree(self):
        destination = INSTALLER.install(self.binary, self.home, True)
        shutil.rmtree(self.home / "checkout")
        result = subprocess.run([str(destination)], check=True, capture_output=True, text=True)
        self.assertEqual(result.stdout, "auth-runtime-ok")
        unit = (self.home / ".config/systemd/user/volta-auth-rust.service").read_text()
        self.assertIn("ExecStart=%h/.local/lib/volta-auth/bin/volta-auth-server", unit)
        self.assertIn("WorkingDirectory=%h/.local/lib/volta-auth", unit)
        self.assertNotIn("target/release", unit)

    def test_preserves_socket_env_and_fence_and_does_not_enable(self):
        units = self.home / ".config/systemd/user"
        dropin = units / "volta-auth-rust.service.d/fence.conf"
        dropin.parent.mkdir(parents=True)
        dropin.write_text("fence")
        socket = units / "volta-auth-rust.socket"
        socket.write_text("ListenStream=127.0.0.1:7072")
        environment = self.home / ".config/volta-auth-rust.env"
        environment.write_text("unchanged")
        INSTALLER.install(self.binary, self.home, True)
        self.assertEqual(socket.read_text(), "ListenStream=127.0.0.1:7072")
        self.assertEqual(dropin.read_text(), "fence")
        self.assertEqual(environment.read_text(), "unchanged")
        self.assertFalse((units / "default.target.wants").exists())

    def test_upgrade_keeps_previous_binary(self):
        destination = INSTALLER.install(self.binary, self.home)
        previous = destination.read_bytes()
        self.binary.write_text("#!/bin/sh\nprintf 'new'\n")
        INSTALLER.install(self.binary, self.home)
        self.assertEqual(destination.with_name(destination.name + ".previous").read_bytes(), previous)
        self.assertEqual(destination.read_bytes(), self.binary.read_bytes())

    def test_invalid_source_does_not_replace_runtime(self):
        destination = INSTALLER.install(self.binary, self.home)
        previous = destination.read_bytes()
        self.binary.chmod(0o644)
        with self.assertRaises(ValueError):
            INSTALLER.install(self.binary, self.home, True)
        self.assertEqual(destination.read_bytes(), previous)


if __name__ == "__main__":
    unittest.main()
