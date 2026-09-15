import base64
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from deliver import package
from deploy import Deployment, atomic_json
from panel import ensure_inbound
from mtg_diagnostics import check_mtg_diagnostics
from settings import APP_FIELDS, StackError, dump_env, parse_env, validate
from stack import run


def sample_values():
    return {
        "PANEL_HOST": "192.0.2.1",
        "INITIAL_PANEL_USERNAME": "operator",
        "INITIAL_PANEL_PASSWORD": "literal $HOME # value with 'quotes'",
        "INITIAL_VLESS_UUID": "11111111-1111-4111-8111-111111111111",
        "INITIAL_REALITY_PRIVATE_KEY": base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("="),
        "INITIAL_REALITY_PUBLIC_KEY": base64.urlsafe_b64encode(bytes(range(32, 64))).decode().rstrip("="),
        "INITIAL_REALITY_SHORT_ID": "0123456789abcdef",
        "MTG_SECRET": "ee" + "42" * 16 + "www.microsoft.com".encode().hex(),
    }


class SettingsContract(unittest.TestCase):
    def test_literal_secrets_roundtrip_with_crlf_and_quotes(self):
        values = sample_values()
        values["INITIAL_PANEL_PASSWORD"] = "a $HOME ${USER} # $(touch x) `date` \\ ' end"
        self.assertEqual(values, validate(parse_env(dump_env(values).replace("\n", "\r\n"))))

    def test_fail_closed_without_echoing_invalid_values(self):
        payload = "do-not-print-me"
        for text in (f"A={payload}\nA=second", f"BAD-KEY={payload}", f"A='{payload}", f"A=\"{payload}\""):
            with self.subTest(text=text):
                with self.assertRaises(StackError) as error:
                    parse_env(text)
                self.assertNotIn(payload, str(error.exception))
        for field, value in (("MTG_SECRET", payload), ("INITIAL_VLESS_UUID", payload),
                             ("PANEL_HOST", payload + ";curl"), ("INITIAL_REALITY_PRIVATE_KEY", payload),
                             ("PANEL_HOST", "{$ENV}"), ("PANEL_HOST", "192.0.2.1:9443"),
                             ("PANEL_HOST", "https://192.0.2.1")):
            values = sample_values()
            values[field] = value
            with self.assertRaises(StackError) as error:
                validate(values)
            self.assertNotIn(payload, str(error.exception))

    def test_missing_unknown_and_invalid_base64(self):
        values = sample_values()
        del values["MTG_SECRET"]
        with self.assertRaisesRegex(StackError, "Missing required"):
            validate(values)
        values = sample_values() | {"COMPOSE_FILE": "untrusted.yaml"}
        with self.assertRaisesRegex(StackError, "Unknown"):
            validate(values)
        values = sample_values() | {"SSH_HOST": "192.0.2.1", "SSH_USER": "root",
                                    "SSH_PRIVATE_KEY_B64": "bad!", "SSH_KNOWN_HOSTS_B64": "bad!"}
        with self.assertRaisesRegex(StackError, "Base64"):
            validate(values, ssh=True)

    def test_archive_excludes_ssh_credentials_and_has_private_env(self):
        root = Path(__file__).resolve().parents[1]
        values = sample_values() | {"SSH_PRIVATE_KEY_B64": "secret-marker", "SSH_HOST": "192.0.2.1"}
        archive = tarfile.open(fileobj=io.BytesIO(base64.b64decode(package(root, values))))
        with archive:
            member = archive.getmember(".env")
            self.assertEqual(member.mode, 0o600)
            text = archive.extractfile(member).read().decode()
            self.assertNotIn("SSH_", text)
            self.assertEqual(set(parse_env(text)), APP_FIELDS)
            self.assertFalse(any(".work" in member.name for member in archive.getmembers()))

    def test_upstream_error_output_is_not_exposed(self):
        with self.assertRaises(StackError) as error:
            run([sys.executable, "-c", "import sys;sys.stderr.write('sensitive-config');sys.exit(7)"], label="Test")
        self.assertNotIn("sensitive-config", str(error.exception))
        self.assertIn("exit 7", str(error.exception))

    def test_stdin_preserves_lf_without_windows_crlf_translation(self):
        run([sys.executable, "-c", "import sys; assert sys.stdin.buffer.read() == b'operator\\n$literal # password\\n'"],
            label="Literal stdin", data="operator\n$literal # password\n")


class MTProtoDiagnosticsContract(unittest.TestCase):
    REPORT = """Deprecated options
  ✅ All good
Time skewness
  ✅ Time drift is 1ms, but tolerate-time-skewness is 3s
Validate native network connectivity
  ✅ DC 1
  ✅ DC 2
  ✅ DC 3
  ✅ DC 4
  ✅ DC 5
  ✅ DC 203
Validate fronting domain connectivity
  ✅ www.microsoft.com:443 is reachable
Validate SNI-DNS match
  ✅ IP address 192.0.2.1 matches secret hostname www.microsoft.com
"""

    def test_healthy_report_and_documented_advisories(self):
        check_mtg_diagnostics(self.REPORT)
        advisory = self.REPORT.replace(
            "✅ Time drift is 1ms, but tolerate-time-skewness is 3s",
            "⚠️ Time drift is 1s, but tolerate-time-skewness is 3s. Please check ntp.")
        advisory = advisory.replace(
            "✅ IP address 192.0.2.1 matches secret hostname www.microsoft.com",
            "❌ Hostname www.microsoft.com is resolved to [192.0.2.2] addresses, not 192.0.2.1")
        with redirect_stdout(io.StringIO()) as output:
            check_mtg_diagnostics(advisory)
        self.assertNotIn("192.0.2.1", output.getvalue())
        self.assertNotIn("www.microsoft.com", output.getvalue())

    def test_connectivity_clock_dns_and_unknown_failures_block_deploy(self):
        reports = (
            self.REPORT.replace("✅ DC 2", "❌ DC 2: sensitive-error-value"),
            self.REPORT.replace("✅ Time drift is", "❌ Time drift is"),
            self.REPORT.replace("✅ Time drift is 1ms, but tolerate-time-skewness is 3s",
                                "‼️ cannot access ntp pool: sensitive-error-value"),
            self.REPORT.replace("✅ www.microsoft.com:443 is reachable", "❌ sensitive-error-value"),
            self.REPORT.replace("✅ IP address 192.0.2.1 matches secret hostname www.microsoft.com",
                                "❌ Hostname sensitive-error-value cannot be resolved to any host"),
            self.REPORT.replace("  ✅ DC 2\n", ""),
            "cannot init config: sensitive-error-value",
            self.REPORT + "unknown diagnostic: sensitive-error-value\n",
        )
        for index, report in enumerate(reports):
            with self.subTest(index=index), self.assertRaises(StackError) as error:
                check_mtg_diagnostics(report)
            self.assertNotIn("sensitive-error-value", str(error.exception))


class BootstrapContract(unittest.TestCase):
    def test_interrupted_create_is_resumed_without_duplicate_or_overwrite(self):
        expected = {"remark": "initial-vless", "port": 443, "protocol": "vless", "enable": True,
                    "settings": {"clients": [{"id": "user-id"}]},
                    "streamSettings": {"realitySettings": {"privateKey": "key", "shortIds": ["id"]}}}
        class API:
            def __init__(self):
                self.items, self.creates = [], 0
            def request(self, path, data=None):
                if data is None:
                    return self.items
                self.items.append(data)
                self.creates += 1
        api = API()
        ensure_inbound(api, expected)
        ensure_inbound(api, expected)
        self.assertEqual(api.creates, 1)
        api.items[0] = expected | {"protocol": "trojan"}
        with self.assertRaises(StackError):
            ensure_inbound(api, expected)
        self.assertEqual(api.creates, 1)


class RollbackContract(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.state = self.root / "state" / "xui"
        self.state.mkdir(parents=True)
        (self.state / "x-ui.db").write_bytes(b"old-db-schema-and-users")
        (self.state / "bootstrap-complete.json").write_text('{"version":1}')
        for name in ("old", "new"):
            (self.root / "releases" / name).mkdir(parents=True)
        self.events = []
        self.fail_start, self.fail_preflight = False, False
        outer = self
        class FakeStack:
            def __init__(self, release, _state):
                self.name = release.name
            def prepare_directories(self):
                pass
            def preflight(self):
                if outer.fail_preflight:
                    raise StackError("Bad candidate config")
            def command(self, *args, **_kwargs):
                outer.events.append((self.name, args))
            def bootstrap(self):
                if self.name == "new":
                    (outer.state / "x-ui.db").write_bytes(b"new-incompatible-schema")
            def start(self):
                outer.events.append((self.name, "start"))
                if self.name == "new" and outer.fail_start:
                    raise StackError("New image cannot start")
        self.deployment = Deployment(self.root, FakeStack)
        atomic_json(self.deployment.current, {"release": "old"})

    def test_preflight_failure_does_not_stop_live_services(self):
        self.fail_preflight = True
        with self.assertRaises(StackError):
            self.deployment.apply("new")
        self.assertEqual(self.events, [])
        self.assertEqual((self.state / "x-ui.db").read_bytes(), b"old-db-schema-and-users")

    def test_failed_upgrade_restores_database_and_old_image(self):
        self.fail_start = True
        with self.assertRaises(StackError):
            self.deployment.apply("new")
        self.assertEqual((self.state / "x-ui.db").read_bytes(), b"old-db-schema-and-users")
        self.assertTrue((self.state / "bootstrap-complete.json").exists())
        self.assertEqual(self.deployment.current_name(), "old")
        self.assertIn(("old", "start"), self.events)
        self.assertFalse(self.deployment.transaction.exists())

    def test_manual_rollback_restores_consistent_snapshot(self):
        self.deployment.apply("new")
        self.assertEqual(self.deployment.current_name(), "new")
        self.deployment.rollback()
        self.assertEqual(self.deployment.current_name(), "old")
        self.assertEqual((self.state / "x-ui.db").read_bytes(), b"old-db-schema-and-users")

    def test_next_deploy_recovers_interrupted_migration(self):
        snapshot = self.root / "backups" / "new"
        snapshot.mkdir(parents=True)
        shutil.copytree(self.state, snapshot / "xui")
        atomic_json(self.deployment.transaction, {"candidate": "new", "previous": "old", "snapshot_ready": True})
        (self.state / "x-ui.db").write_bytes(b"half-migrated")
        self.deployment.recover()
        self.assertEqual((self.state / "x-ui.db").read_bytes(), b"old-db-schema-and-users")

    def test_paths_cannot_escape_release_root(self):
        for name in ("../outside", "/root", "..", "a/b"):
            with self.subTest(name=name), self.assertRaises(StackError):
                self.deployment.release(name)


if __name__ == "__main__":
    unittest.main()
