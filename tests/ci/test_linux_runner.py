#!/usr/bin/env python3
# Himmelcloak native Keycloak authentication
# Copyright (C) 2026 Damon Bun, Joshua Conklin, Kevin Torrecampo,
# Aidan Garske, Harrison Barrett, and Harman Samra
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline tests for the disposable Linux test system runner (HC-45).

A fake container engine stands in for Docker or Podman. It records every call
and tracks whether the one test container still exists, so these tests check
that tests/linux/run.sh always tears the system down and reports the checks'
own status, without building or starting anything.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "tests" / "linux" / "run.sh"

FAKE_ENGINE = r"""#!/usr/bin/env bash
# Behavior comes from FAKE_* variables; every call is appended to $FAKE_DIR/calls.
printf '%s\n' "$*" >> "$FAKE_DIR/calls"
state="$FAKE_DIR/container"
case "$1" in
    image)
        [[ "${FAKE_IMAGE:-present}" == present ]] || exit 1
        echo linux/amd64 ;;
    build) exit "${FAKE_BUILD_STATUS:-0}" ;;
    run)
        shift
        while [[ "$1" == --* ]]; do
            case "$1" in
                --name) echo "$2" > "$state"; shift ;;
                --platform) shift ;;
            esac
            shift
        done
        echo fake-container-id ;;
    exec)
        [[ -s "$state" ]] || exit 1
        shift
        while [[ "$1" == --* ]]; do shift; done
        shift
        if [[ "$1" == test ]]; then
            [[ "${FAKE_SSHD:-up}" == up ]]
            exit
        fi
        exit "${FAKE_CHECK_STATUS:-0}" ;;
    rm) rm -f "$state" ;;
    container) [[ -s "$state" ]] ;;
    logs) echo "fake sshd log" ;;
    *) exit 64 ;;
esac
"""


class LinuxRunnerTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="himmelcloak-runner-test."))
        self.engine = self.dir / "fake-engine"
        self.engine.write_text(FAKE_ENGINE)
        self.engine.chmod(0o755)

    def tearDown(self):
        for path in self.dir.iterdir():
            path.unlink()
        self.dir.rmdir()

    def run_runner(self, mode="test", **fake):
        env = {
            key: value
            for key, value in os.environ.items()
            if key not in ("DISTRO", "TESTER_IMAGE")
        }
        env.update(
            CONTAINER=str(self.engine),
            FAKE_DIR=str(self.dir),
            LINUX_BOOT_TIMEOUT="2",
            **{f"FAKE_{name.upper()}": str(value) for name, value in fake.items()},
        )
        result = subprocess.run(
            ["bash", str(RUNNER), mode],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        return result

    def calls(self):
        path = self.dir / "calls"
        return path.read_text().splitlines() if path.exists() else []

    def assert_torn_down(self, result):
        calls = self.calls()
        removals = [i for i, call in enumerate(calls) if call.startswith("rm --force")]
        inspections = [i for i, call in enumerate(calls) if call.startswith("container inspect")]
        self.assertTrue(removals, calls)
        self.assertFalse((self.dir / "container").exists(), "container left behind")
        if inspections:
            self.assertGreater(inspections[-1], removals[0], "absence checked before removal")

    def test_passing_checks_tear_down_and_succeed(self):
        result = self.run_runner()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_torn_down(result)
        self.assertIn("Teardown: PASS", result.stdout)

    def test_failing_checks_still_tear_down_and_keep_their_status(self):
        result = self.run_runner(check_status=3)
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assert_torn_down(result)
        self.assertIn("Teardown: PASS", result.stdout)
        self.assertTrue(any(call.startswith("container inspect") for call in self.calls()))

    def test_sshd_that_never_starts_fails_and_is_removed(self):
        result = self.run_runner(sshd="down")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("sshd did not start", result.stderr)
        self.assert_torn_down(result)

    def test_build_failure_starts_nothing(self):
        result = self.run_runner(build_status=1)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(call.startswith("run ") for call in self.calls()))

    def test_both_stages_and_the_container_use_the_tester_platform(self):
        self.run_runner()
        build = next(call for call in self.calls() if call.startswith("build "))
        run = next(call for call in self.calls() if call.startswith("run "))
        self.assertIn("--platform linux/amd64", build)
        self.assertIn("TESTER_IMAGE=himmelcloak-tester:ci", build)
        self.assertIn("--platform linux/amd64", run)

    def test_shell_mode_uses_a_tty_and_preserves_failure_status(self):
        result = self.run_runner(mode="shell", check_status=3)
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assert_torn_down(result)
        self.assertTrue(
            any(call.startswith("exec --interactive --tty ") for call in self.calls()),
            self.calls(),
        )
        self.assertFalse(
            any("check-system.sh" in call for call in self.calls()),
            "shell mode must not run the checks",
        )

    def test_missing_tester_image_stops_before_building(self):
        result = self.run_runner(image="missing")
        self.assertEqual(result.returncode, 1)
        self.assertIn("make image", result.stderr)
        self.assertFalse(any(call.startswith("build ") for call in self.calls()))

    def test_distro_is_refused_before_any_engine_call(self):
        env_distro = dict(os.environ, DISTRO="fedora", CONTAINER=str(self.engine), FAKE_DIR=str(self.dir))
        result = subprocess.run(
            ["bash", str(RUNNER), "test"], env=env_distro, capture_output=True, text=True, timeout=30, check=False
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("always Debian 12", result.stderr)
        self.assertEqual(self.calls(), [])

    def test_unknown_mode_is_a_usage_error(self):
        result = self.run_runner(mode="deploy")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.calls(), [])


if __name__ == "__main__":
    unittest.main()
