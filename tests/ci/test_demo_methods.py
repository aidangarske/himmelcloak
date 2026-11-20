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
"""make demo METHOD= selection and its authenticator-app QR links, without Docker or Keycloak."""
import json
import os
import pathlib
import subprocess
import unittest
from urllib.parse import quote

REPO = pathlib.Path(__file__).resolve().parents[2]
DEMO = REPO / "tests/keycloak/demo.sh"
REALM = REPO / "tests/keycloak/realm-export.json"


def demo(method):
    env = dict(os.environ, METHOD=method)
    return subprocess.run(["bash", str(DEMO)], env=env, capture_output=True, text=True)


def realm_otpauth(username):
    realm = json.loads(REALM.read_text())
    user = next(u for u in realm["users"] if u["username"] == username)
    for credential in user["credentials"]:
        data = json.loads(credential.get("credentialData", "{}"))
        if credential["type"] == "otp" and data["subType"] == "totp":
            secret = json.loads(credential["secretData"])["value"].rstrip("=")
            return (
                f"otpauth://totp/{quote(f'Himmelcloak:{username}')}?secret={secret}&issuer=Himmelcloak"
                f"&algorithm={data['algorithm'].removeprefix('Hmac')}&digits={data['digits']}&period={data['period']}"
            )
    return None


class DemoMethodTest(unittest.TestCase):
    def test_list_names_every_method(self):
        result = demo("list")
        self.assertEqual(result.returncode, 0, result.stderr)
        for method in ("password", "totp", "totp-devices"):
            self.assertIn(method, result.stdout)

    def test_an_unknown_method_exits_before_starting_anything(self):
        result = demo("sms")
        self.assertEqual(result.returncode, 2)
        self.assertIn("unknown METHOD=sms", result.stderr)

    def test_qr_links_match_the_realm_fixture(self):
        script = DEMO.read_text()
        for username in ("bob", "carol"):
            link = realm_otpauth(username)
            self.assertIn(f"otpauth='{link}'", script, username)

    def test_bob_qr_carries_the_fixture_totp_policy(self):
        self.assertEqual(
            realm_otpauth("bob"),
            "otpauth://totp/Himmelcloak%3Abob?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
            "&issuer=Himmelcloak&algorithm=SHA1&digits=6&period=30",
        )

    def test_carol_qr_uses_her_sha256_eight_digit_app(self):
        self.assertIn("algorithm=SHA256&digits=8", realm_otpauth("carol"))

    def test_a_password_only_user_has_no_qr(self):
        self.assertIsNone(realm_otpauth("alice"))


if __name__ == "__main__":
    unittest.main()
