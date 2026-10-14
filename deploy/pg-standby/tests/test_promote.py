import fcntl
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "promote.sh"
IDENTITY = "a" * 64
DOCKER = '''#!/usr/bin/env python3
import os, pathlib, sys
arguments = sys.argv[1:]
root = pathlib.Path(os.environ["MOCK_ROOT"])
with (root / "calls").open("a") as stream:
    stream.write(repr(arguments) + "\\n")
if "inspect" in arguments:
    print(os.environ["OBSERVED_ID"] + " true")
elif "exec" in arguments:
    query = arguments[-1]
    if "pg_promote" in query:
        (root / "promoted").touch()
        print("t")
    elif "pg_last_wal_replay_lsn" in query:
        print("f" if os.environ.get("LAG") else "t")
    elif "pg_is_in_recovery" in query:
        print("f" if (root / "promoted").exists() or os.environ.get("PRIMARY") else "t")
    else:
        sys.exit(3)
else:
    sys.exit(4)
'''


class PromotionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        executable = self.root / "docker"
        executable.write_text(DOCKER)
        executable.chmod(0o700)
        self.environment = dict(os.environ, PATH=f"{self.root}:{os.environ['PATH']}",
                                MOCK_ROOT=str(self.root), OBSERVED_ID=IDENTITY,
                                DOCKER_HOST="unix:///run/user/1000/docker.sock",
                                EXPECTED_CONTAINER_ID=IDENTITY, MIN_REPLAY_LSN="8/1234",
                                PROMOTION_STATE_ROOT=str(self.root / "state"))

    def run_script(self, *arguments, **changes):
        return subprocess.run(["sh", str(SCRIPT), *arguments], env=dict(self.environment, **changes),
                              capture_output=True, text=True, timeout=15)

    def test_dry_run_is_read_only(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.root / "promoted").exists())
        self.assertNotIn("pg_promote", (self.root / "calls").read_text())

    def test_confirm_promotes_only_in_place(self):
        result = self.run_script("--confirm-source-fenced", "--confirm")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.root / "promoted").exists())
        calls = (self.root / "calls").read_text()
        self.assertNotIn("'rm'", calls)
        self.assertNotIn("'run'", calls)
        self.assertNotIn("'pull'", calls)
        self.assertNotIn("'update'", calls)
        self.assertIn("--host", calls)
        self.assertEqual(self.run_script("--confirm-source-fenced", "--confirm").returncode, 1)

    def test_invalid_input_and_unacknowledged_fence_never_touch_docker(self):
        for changes in ({"DOCKER_HOST": "tcp://server:2375"}, {"EXPECTED_CONTAINER_ID": "short"},
                        {"MIN_REPLAY_LSN": "8/1234';SELECT 1;--"}):
            self.assertNotEqual(self.run_script(**changes).returncode, 0)
        self.assertNotEqual(self.run_script("--confirm").returncode, 0)
        self.assertFalse((self.root / "calls").exists())

    def test_target_drift_lag_and_primary_fail_closed(self):
        for changes in ({"OBSERVED_ID": "b" * 64}, {"LAG": "1"}, {"PRIMARY": "1"}):
            self.assertNotEqual(self.run_script("--confirm-source-fenced", "--confirm", **changes).returncode, 0)
        self.assertFalse((self.root / "promoted").exists())

    def test_parallel_promotion_is_refused(self):
        state = self.root / "state"
        state.mkdir(mode=0o700)
        with (state / "promotion.lock").open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertNotEqual(self.run_script("--confirm-source-fenced", "--confirm").returncode, 0)
        self.assertFalse((self.root / "calls").exists())


if __name__ == "__main__":
    unittest.main()
