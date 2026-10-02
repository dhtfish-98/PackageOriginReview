import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

from package_origin_review import (
    Limits,
    Policy,
    InputError,
    read_regular_file,
    review_bytes,
)
from package_origin_review.cli import main


def lock(entries=None, version=3):
    return json.dumps(
        {
            "lockfileVersion": version,
            "packages": {
                "": {"name": "fixture"},
                **(
                    entries
                    if entries is not None
                    else {
                        "node_modules/pkg": {
                            "resolved": "https://registry.npmjs.org/pkg/-/pkg-1.0.tgz"
                        }
                    }
                ),
            },
        }
    ).encode()


class OriginTests(unittest.TestCase):
    def report(self, url, name="pkg", **kwargs):
        return review_bytes(lock({"node_modules/" + name: {"resolved": url}}), **kwargs)

    def expect(self, status, code, url, name="pkg", **kwargs):
        report = self.report(url, name, **kwargs)
        self.assertEqual(report["status"], status, report)
        self.assertEqual(report["findings"][0]["code"], code)
        return report

    def test_valid_v2_v3_and_scoped(self):
        for version in (2, 3):
            for name in ("pkg", "@scope/pkg"):
                report = review_bytes(
                    lock(
                        {
                            "node_modules/" + name: {
                                "resolved": "https://registry.npmjs.org/"
                                + name
                                + "/-/pkg-1.0.tgz"
                            }
                        },
                        version,
                    )
                )
                self.assertEqual(report["status"], "PASS", report)
                self.assertTrue(report["complete"])
                self.assertEqual(report["passed_entries"], 1)

    def test_nested_installation(self):
        data = lock(
            {
                "node_modules/@scope/parent/node_modules/pkg": {
                    "resolved": "https://registry.npmjs.org/pkg/-/pkg-2.tgz"
                }
            }
        )
        self.assertEqual(review_bytes(data)["status"], "PASS")

    def test_exact_host_not_suffix(self):
        for host in (
            "registry.npmjs.org.evil.test",
            "registry-npmjs.org",
            "npmjs.org",
            "registry.npmjs.org.",
        ):
            self.expect(
                "FAIL", "host_not_allowed", "https://" + host + "/pkg/-/pkg-1.tgz"
            )

    def test_case_and_explicit_default_port(self):
        for host in ("REGISTRY.NPMJS.ORG", "registry.npmjs.org:443"):
            self.assertEqual(
                self.report("https://" + host + "/pkg/-/pkg-1.tgz")["status"], "PASS"
            )

    def test_ports_and_authority(self):
        for authority in (
            "registry.npmjs.org:80",
            "registry.npmjs.org:0443",
            "registry.npmjs.org:bad",
            "registry.npmjs.org:",
        ):
            self.expect(
                "FAIL",
                "port_or_authority_not_allowed",
                "https://" + authority + "/pkg/-/pkg-1.tgz",
            )

    def test_userinfo_not_echoed(self):
        report = self.expect(
            "FAIL",
            "userinfo_forbidden",
            "https://private_user:private_token@registry.npmjs.org/pkg/-/pkg-1.tgz",
        )
        self.assertNotIn("private_user", json.dumps(report))
        self.assertNotIn("private_token", json.dumps(report))

    def test_query_fragment_even_empty(self):
        for tail in ("?secret=private_value", "#private_value", "?", "#"):
            report = self.expect(
                "FAIL",
                "query_or_fragment_forbidden",
                "https://registry.npmjs.org/pkg/-/pkg-1.tgz" + tail,
            )
            self.assertNotIn("private_value", json.dumps(report))

    def test_https_required(self):
        for scheme in ("http", "ftp"):
            self.expect(
                "FAIL",
                "https_required",
                scheme + "://registry.npmjs.org/pkg/-/pkg-1.tgz",
            )

    def test_missing_relative_or_nonregistry_stays_open(self):
        for value in (
            None,
            "",
            4,
            "/pkg/-/pkg-1.tgz",
            "pkg/-/pkg-1.tgz",
            "git+https://example.test/pkg",
            "git:pkg",
            "file:pkg",
            "link:pkg",
            "npm:pkg",
            "data:text/plain,fixture",
        ):
            self.assertEqual(self.report(value)["status"], "OPEN")

    def test_url_control_and_backslash_ambiguity(self):
        for value in (
            "https://registry.npmjs.org\n/pkg/-/pkg-1.tgz",
            "https:\\registry.npmjs.org/pkg/-/pkg-1.tgz",
            "https://registry.npmjs.org/日本/-/pkg-1.tgz",
        ):
            self.expect("FAIL", "ambiguous_url_characters", value)

    def test_malformed_url(self):
        self.expect(
            "OPEN", "malformed_resolved_url", "https://[invalid/pkg/-/pkg-1.tgz"
        )

    def test_path_name_binding(self):
        for path in (
            "other/-/other-1.tgz",
            "pkg-extra/-/pkg-1.tgz",
            "pkg/sub/-/pkg-1.tgz",
            "prefix/pkg/-/pkg-1.tgz",
        ):
            self.expect(
                "FAIL", "package_route_mismatch", "https://registry.npmjs.org/" + path
            )

    def test_encoded_name_is_decoded_per_segment(self):
        self.assertEqual(
            self.report("https://registry.npmjs.org/%70kg/-/pkg-1.tgz")["status"],
            "PASS",
        )
        self.assertEqual(
            self.report(
                "https://registry.npmjs.org/%40scope/pkg/-/pkg-1.tgz", "@scope/pkg"
            )["status"],
            "PASS",
        )

    def test_encoded_path_ambiguities(self):
        for path in (
            "pkg/../pkg/-/pkg-1.tgz",
            "pkg/%2e%2e/pkg/-/pkg-1.tgz",
            "pkg%2fother/-/pkg-1.tgz",
            "pkg%5cother/-/pkg-1.tgz",
            "pkg/%252f/pkg-1.tgz",
            "pkg//-/pkg-1.tgz",
            "pkg/-/pkg-%00.tgz",
        ):
            self.expect(
                "FAIL", "ambiguous_registry_path", "https://registry.npmjs.org/" + path
            )

    def test_invalid_percent_encoding(self):
        self.expect(
            "FAIL",
            "invalid_registry_path",
            "https://registry.npmjs.org/pk%G0/-/pkg-1.tgz",
        )

    def test_tarball_leaf_policy_not_pin_check(self):
        for leaf in ("other-1.tgz", "pkg-.tgz", "pkg-1.zip", "pkg-1(2).tgz"):
            self.expect(
                "FAIL",
                "tarball_filename_policy",
                "https://registry.npmjs.org/pkg/-/" + leaf,
            )
        data = lock(
            {
                "node_modules/pkg": {
                    "version": "9.0",
                    "integrity": "opaque",
                    "resolved": "https://registry.npmjs.org/pkg/-/pkg-1.tgz",
                }
            }
        )
        self.assertEqual(review_bytes(data)["status"], "PASS")
        self.assertFalse(review_bytes(data)["integrity_or_version_pin_checked"])

    def test_alias_link_and_workspace_are_unknown(self):
        examples = [
            {
                "node_modules/alias": {
                    "name": "pkg",
                    "resolved": "https://registry.npmjs.org/pkg/-/pkg-1.tgz",
                }
            },
            {"node_modules/pkg": {"link": True, "resolved": "packages/pkg"}},
            {"packages/pkg": {"name": "pkg"}},
            {
                "node_modules/.store/pkg/node_modules/pkg": {
                    "resolved": "https://registry.npmjs.org/pkg/-/pkg-1.tgz"
                }
            },
            {
                "node_modules/pkg": {
                    "link": "false",
                    "resolved": "https://registry.npmjs.org/pkg/-/pkg-1.tgz",
                }
            },
        ]
        for entries in examples:
            self.assertEqual(review_bytes(lock(entries))["status"], "OPEN")

    def test_malformed_entry_and_paths(self):
        for entries in (
            {"node_modules/pkg": []},
            {"node_modules/../pkg": {}},
            {"/node_modules/pkg": {}},
            {"node_modules/Pkg": {}},
            {"node_modules/@scope": {}},
            {"private_value": {}},
        ):
            report = review_bytes(lock(entries))
            self.assertEqual(report["status"], "OPEN")
            self.assertNotIn("private_value", json.dumps(report))

    def test_invalid_schema_and_root(self):
        for data in (
            b"[]",
            b"null",
            b"{}",
            b'{"lockfileVersion":true,"packages":{}}',
            b'{"lockfileVersion":3,"packages":[]}',
            b'{"lockfileVersion":3,"packages":{"":false}}',
            lock(version=1),
            lock(version=4),
        ):
            self.assertEqual(review_bytes(data)["status"], "OPEN")

    def test_strict_json_duplicates_invalid_encoding_nonfinite(self):
        cases = [
            b'{"lockfileVersion":3,"packages":{},"packages":{}}',
            b'{"lockfileVersion":3,"packages":{"node_modules/pkg":{"resolved":"a","resolved":"b"}}}',
            b"\xff",
            b"{",
            b"{} trailing",
            b'{"lockfileVersion":3,"packages":{},"x":NaN}',
            b'{"lockfileVersion":3,"packages":{},"x":1e999}',
        ]
        for data in cases:
            self.assertEqual(review_bytes(data)["status"], "OPEN")

    def test_budgets_never_silently_clean(self):
        data = lock()
        self.assertEqual(
            review_bytes(data, limits=Limits(input_bytes=len(data) - 1))["status"],
            "OPEN",
        )
        deep = (
            b'{"lockfileVersion":3,"packages":{},"x":'
            + b"[" * 65
            + b"0"
            + b"]" * 65
            + b"}"
        )
        self.assertEqual(review_bytes(deep)["status"], "OPEN")
        self.assertEqual(
            self.report(
                "https://registry.npmjs.org/pkg/-/pkg-1.tgz",
                limits=Limits(url_chars=10),
            )["status"],
            "OPEN",
        )
        entries = {"node_modules/a": {}, "node_modules/b": {}}
        report = review_bytes(lock(entries), limits=Limits(findings=1))
        self.assertEqual(report["errors"], [{"code": "finding_limit"}])
        report = review_bytes(lock(entries), limits=Limits(entries=1))
        self.assertEqual(report["status"], "OPEN")

    def test_empty_and_hidden_maps(self):
        for packages in ({}, {"": {}}):
            report = review_bytes(
                json.dumps({"lockfileVersion": 3, "packages": packages}).encode()
            )
            self.assertEqual(report["status"], "PASS")
            self.assertEqual(report["entries_checked"], 0)
        data = b'{"lockfileVersion":3,"packages":{"node_modules/pkg":{"resolved":"https://registry.npmjs.org/pkg/-/pkg-1.tgz"}}}'
        self.assertEqual(review_bytes(data)["status"], "PASS")

    def test_policy_host_validation_and_replacement(self):
        for host in (
            "*.example.test",
            "https://registry.example.test",
            "registry.example.test:443",
            "192.0.2.1",
            "0177.0.0.1",
            "127.0.0.0x1",
            "0x7f.0x0.0x0.0x1",
            "example.0XFF",
            "localhost",
            "example.test.",
            "日本.test",
            "a..test",
        ):
            with self.assertRaises(ValueError):
                Policy((host,))
        policy = Policy(("REGISTRY.EXAMPLE.TEST", "registry.example.test"))
        self.assertEqual(policy.allowed_hosts, ("registry.example.test",))
        self.assertEqual(
            self.report("https://registry.example.test/pkg/-/pkg-1.tgz", policy=policy)[
                "status"
            ],
            "PASS",
        )
        self.assertEqual(
            self.report("https://registry.npmjs.org/pkg/-/pkg-1.tgz", policy=policy)[
                "status"
            ],
            "FAIL",
        )

    def test_fail_and_open_coexist(self):
        data = lock(
            {
                "node_modules/a": {"resolved": "http://registry.npmjs.org/a/-/a-1.tgz"},
                "node_modules/b": {},
            }
        )
        report = review_bytes(data)
        self.assertEqual(report["status"], "FAIL")
        self.assertFalse(report["complete"])
        self.assertEqual((report["failed_entries"], report["open_entries"]), (1, 1))

    def test_actual_download_authenticity_always_unknown(self):
        report = review_bytes(lock())
        self.assertEqual(report["actual_fetch_origin"], "OPEN")
        self.assertEqual(report["package_authenticity"], "OPEN")

    def test_input_hash_and_no_runtime_network(self):
        data = lock()
        with patch.object(
            socket, "socket", side_effect=AssertionError("network forbidden")
        ):
            report = review_bytes(data)
        self.assertEqual(report["input_sha256"], hashlib.sha256(data).hexdigest())

    def test_api_types_and_invalid_limits(self):
        for kwargs in ({"policy": False}, {"limits": 0}):
            with self.assertRaises(TypeError):
                review_bytes(lock(), **kwargs)
        for value in (True, 0, -1, 65, 2.0):
            with self.assertRaises(ValueError):
                Limits(json_depth=value)


@unittest.skipUnless(os.name == "posix", "no-follow reader is POSIX only")
class InputAndCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.file = self.root / "package-lock.json"

    def tearDown(self):
        self.tmp.cleanup()

    def test_ordinary_read_preserves_bytes_and_limit(self):
        data = lock()
        self.file.write_bytes(data)
        self.assertEqual(read_regular_file(self.file, len(data)), data)
        self.assertEqual(self.file.read_bytes(), data)
        with self.assertRaises(InputError):
            read_regular_file(self.file, len(data) - 1)

    def test_unsupported_reader_is_open(self):
        self.file.write_bytes(lock())
        output = io.StringIO()
        with patch.object(os, "supports_dir_fd", set()):
            with contextlib.redirect_stdout(output):
                code = main([str(self.file)])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue())["status"], "OPEN")

    def test_symlinks_parent_segments_and_special_files(self):
        self.file.write_bytes(lock())
        (self.root / "link").symlink_to(self.file)
        (self.root / "dirlink").symlink_to(self.root, target_is_directory=True)
        os.mkfifo(self.root / "pipe")
        for path in (
            self.root / "link",
            self.root / "dirlink" / self.file.name,
            self.root,
            self.root / "pipe",
            str(self.root) + "/../missing",
        ):
            with self.assertRaises(InputError):
                read_regular_file(path, 4096)

    def test_cli_statuses_private_errors_and_input_unchanged(self):
        for data, expected in (
            (lock(), 0),
            (
                lock(
                    {
                        "node_modules/pkg": {
                            "resolved": "http://registry.npmjs.org/pkg/-/pkg-1.tgz"
                        }
                    }
                ),
                1,
            ),
            (b"private_invalid_json", 2),
        ):
            self.file.write_bytes(data)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main([str(self.file)])
            self.assertEqual(code, expected)
            self.assertEqual(self.file.read_bytes(), data)
            self.assertTrue(output.getvalue().isascii())
            self.assertNotIn("private_invalid_json", output.getvalue())
            self.assertIn("status", json.loads(output.getvalue()))

    def test_cli_missing_and_invalid_arguments_are_json_open(self):
        for arguments in (
            [],
            [str(self.root / "private_missing")],
            ["private_argument", "--bad"],
            [str(self.file), "--allow-host", "https://example.test"],
        ):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(arguments)
            self.assertEqual(code, 2)
            report = json.loads(output.getvalue())
            self.assertEqual(report["status"], "OPEN")
            self.assertEqual(report["actual_fetch_origin"], "OPEN")
            self.assertEqual(report["package_authenticity"], "OPEN")
            self.assertFalse(report["integrity_or_version_pin_checked"])
            self.assertNotIn("private_", output.getvalue())


if __name__ == "__main__":
    unittest.main()
