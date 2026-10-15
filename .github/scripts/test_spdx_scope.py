#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Unit tests for spdx_scope.py (classifier and applier of SPDX identifiers)."""

import importlib.util
import os
import stat
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
MODULE_PATH = os.path.join(HERE, "spdx_scope.py")

_spec = importlib.util.spec_from_file_location("spdx_scope", MODULE_PATH)
spdx = importlib.util.module_from_spec(_spec)
sys.modules["spdx_scope"] = spdx
_spec.loader.exec_module(spdx)

AGPL = "AGPL-3.0-or-later"
DUAL = "GPL-2.0-only OR AGPL-3.0-or-later"

ENGINE_CPP = "src/engine/source/x/x.cpp"
DUAL_H = "src/shared_modules/utils/stringHelper.h"


def line(comment, ident):
    return "{} SPDX-License-Identifier: {}\n".format(comment, ident).encode()


class ClassifyTest(unittest.TestCase):
    def test_engine_scope_is_agpl(self):
        self.assertEqual(spdx.classify(ENGINE_CPP, b"int x;\n"), (AGPL, "//"))

    def test_dual_scope_dirs(self):
        for d in ("utils", "manager_config", "keystore", "indexer_connector", "common"):
            p = "src/shared_modules/%s/sub/f.hpp" % d
            self.assertEqual(spdx.classify(p, b"int x;\n"), (DUAL, "//"), p)

    def test_out_of_scope(self):
        for p in ("src/shared_modules/metrics/m.cpp", "src/remoted/a.c",
                  "src/wazuh_modules/x/y.cpp", "README.md", ".github/scripts/a.py"):
            self.assertIsNone(spdx.classify(p, b"int x;\n"), p)

    def test_slash_comment_extensions(self):
        for ext in (".cpp", ".cc", ".c", ".hpp", ".h", ".proto", ".go", ".fbs"):
            self.assertEqual(spdx.classify("src/engine/a" + ext, b"x\n"), (AGPL, "//"), ext)

    def test_hash_comment_extensions(self):
        for ext in (".py", ".sh", ".cmake", ".pl"):
            self.assertEqual(spdx.classify("src/engine/a" + ext, b"x\n"), (AGPL, "#"), ext)

    def test_exact_names_hash(self):
        for p in ("src/engine/CMakeLists.txt", "src/engine/source/b/CMakeLists.txt",
                  "src/engine/internal_packages/debs/Dockerfile"):
            self.assertEqual(spdx.classify(p, b"x\n"), (AGPL, "#"), p)

    def test_deb_maintainer_scripts_by_path(self):
        base = "src/engine/internal_packages/debs/SPECS/"
        for n in ("postinst", "preinst", "prerm", "postrm", "rules"):
            self.assertEqual(spdx.classify(base + n, b"#!/bin/sh\n"), (AGPL, "#"), n)

    def test_data_extensions_out(self):
        for ext in (".json", ".yml", ".yaml", ".md", ".txt", ".toml", ".cfg", ".in",
                    ".spec", ".feature"):
            self.assertIsNone(spdx.classify("src/engine/a" + ext, b"x\n"), ext)

    def test_license_files_out(self):
        self.assertIsNone(spdx.classify("src/engine/LICENSE-engine", b"x\n"))
        self.assertIsNone(spdx.classify("src/engine/COPYING-engine", b"x\n"))

    def test_empty_and_whitespace_out(self):
        self.assertIsNone(spdx.classify("src/engine/pkg/__init__.py", b""))
        self.assertIsNone(spdx.classify("src/engine/a.cpp", b" \n\t\r\n  "))

    def test_generated_out(self):
        for p in ("src/engine/a.pb.h", "src/engine/a.pb.cc", "src/engine/a.pb.go",
                  "src/engine/a_pb2.py", "src/engine/a_pb2.pyi",
                  "src/engine/a_pb2_grpc.py", "src/engine/a_generated.h"):
            self.assertIsNone(spdx.classify(p, b"x\n"), p)

    def test_pb2_pyi_out(self):
        self.assertIsNone(spdx.classify("src/engine/tools/api/x_pb2.pyi", b"x: int\n"))

    def test_fixtures_out(self):
        for d in ("data", "fixtures", "test_data", "testdata"):
            p = "src/engine/test/integration/%s/sample.py" % d
            self.assertIsNone(spdx.classify(p, b"x = 1\n"), p)
            p = "src/engine/test/a/b/%s/deep/sample.cpp" % d
            self.assertIsNone(spdx.classify(p, b"int x;\n"), p)

    def test_data_dir_outside_test_is_in_scope(self):
        self.assertEqual(spdx.classify("src/engine/source/data/x.cpp", b"x\n"), (AGPL, "//"))

    def test_test_file_not_under_data_dir_is_in_scope(self):
        self.assertEqual(spdx.classify("src/engine/test/unit/t.cpp", b"x\n"), (AGPL, "//"))

    def test_third_party_out(self):
        base = "src/engine/tools/engine-bench/src/engine_bench/scripts/"
        self.assertIsNone(spdx.classify(base + "flamegraph.pl", b"#!/usr/bin/perl\n"))
        self.assertIsNone(spdx.classify(base + "stackcollapse-perf.pl", b"#!/usr/bin/perl\n"))
        self.assertIsNone(spdx.classify("src/shared_modules/utils/makeUnique.h", b"x\n"))

    def test_other_pl_in_scope(self):
        self.assertEqual(spdx.classify("src/engine/tools/generateTestDB.pl", b"#!/usr/bin/perl\n"),
                         (AGPL, "#"))


class FindIdentifierTest(unittest.TestCase):
    def test_none(self):
        self.assertIsNone(spdx.find_identifier(b"int x;\n"))

    def test_plain(self):
        self.assertEqual(spdx.find_identifier(line("//", AGPL) + b"x\n"), AGPL)

    def test_in_block_comment_stripped(self):
        c = b"/*\n * SPDX-License-Identifier: " + DUAL.encode() + b" */\nint x;\n"
        self.assertEqual(spdx.find_identifier(c), DUAL)

    def test_block_star_line(self):
        c = b"/*\n * Copyright\n * SPDX-License-Identifier: " + AGPL.encode() + b"\n */\n"
        self.assertEqual(spdx.find_identifier(c), AGPL)

    def test_within_first_30_lines(self):
        c = b"// c\n" * 29 + line("//", AGPL)  # line 30
        self.assertEqual(spdx.find_identifier(c), AGPL)

    def test_beyond_30_lines_ignored(self):
        c = b"// c\n" * 30 + line("//", AGPL)  # line 31
        self.assertIsNone(spdx.find_identifier(c))


class ApplyToBytesTest(unittest.TestCase):
    def test_insert_line1_cpp(self):
        out = spdx.apply_to_bytes(ENGINE_CPP, b"#include <a>\n")
        self.assertEqual(out, line("//", AGPL) + b"#include <a>\n")

    def test_insert_hash_sh_without_shebang(self):
        out = spdx.apply_to_bytes("src/engine/a.sh", b"echo hi\n")
        self.assertEqual(out, line("#", AGPL) + b"echo hi\n")

    def test_dual_identifier_used(self):
        out = spdx.apply_to_bytes(DUAL_H, b"int x;\n")
        self.assertEqual(out, line("//", DUAL) + b"int x;\n")

    def test_shebang_goes_to_line2(self):
        out = spdx.apply_to_bytes("src/engine/a.sh", b"#!/bin/bash\nset -e\n")
        self.assertEqual(out, b"#!/bin/bash\n" + line("#", AGPL) + b"set -e\n")

    def test_python_coding_line1(self):
        out = spdx.apply_to_bytes("src/engine/a.py", b"# -*- coding: utf-8 -*-\nx = 1\n")
        self.assertEqual(out, b"# -*- coding: utf-8 -*-\n" + line("#", AGPL) + b"x = 1\n")

    def test_python_coding_equals_form(self):
        out = spdx.apply_to_bytes("src/engine/a.py", b"# coding=latin-1\nx = 1\n")
        self.assertEqual(out, b"# coding=latin-1\n" + line("#", AGPL) + b"x = 1\n")

    def test_python_shebang_then_coding(self):
        src = b"#!/usr/bin/env python3\n# vim: set fileencoding=utf-8 coding: utf-8\nx = 1\n"
        out = spdx.apply_to_bytes("src/engine/a.py", src)
        lines = out.split(b"\n")
        self.assertEqual(lines[0], b"#!/usr/bin/env python3")
        self.assertEqual(lines[1], b"# vim: set fileencoding=utf-8 coding: utf-8")
        self.assertEqual(lines[2], line("#", AGPL).rstrip(b"\n"))
        self.assertEqual(lines[3], b"x = 1")

    def test_python_shebang_without_coding(self):
        out = spdx.apply_to_bytes("src/engine/a.py", b"#!/usr/bin/env python3\nx = 1\n")
        self.assertEqual(out, b"#!/usr/bin/env python3\n" + line("#", AGPL) + b"x = 1\n")

    def test_go_adds_blank_line(self):
        out = spdx.apply_to_bytes("src/engine/tools/http_bypass.go", b"package main\n")
        self.assertEqual(out, line("//", AGPL) + b"\npackage main\n")

    def test_idempotent(self):
        once = spdx.apply_to_bytes(ENGINE_CPP, b"int x;\n")
        twice = spdx.apply_to_bytes(ENGINE_CPP, once)
        self.assertEqual(once, twice)

    def test_idempotent_shebang_and_go(self):
        for p, c in (("src/engine/a.sh", b"#!/bin/sh\nx\n"),
                     ("src/engine/a.go", b"package main\n"),
                     ("src/engine/a.py", b"# coding: utf-8\nx = 1\n")):
            once = spdx.apply_to_bytes(p, c)
            self.assertEqual(spdx.apply_to_bytes(p, once), once, p)

    def test_different_identifier_raises(self):
        c = line("//", "GPL-2.0-only") + b"int x;\n"
        with self.assertRaises(spdx.SpdxError):
            spdx.apply_to_bytes(ENGINE_CPP, c)

    def test_dual_path_with_agpl_only_raises(self):
        with self.assertRaises(spdx.SpdxError):
            spdx.apply_to_bytes(DUAL_H, line("//", AGPL) + b"int x;\n")

    def test_identifier_in_block_line_11_is_noop(self):
        c = b"/*\n" + b" * filler\n" * 9 + b" * SPDX-License-Identifier: " + DUAL.encode() + b"\n */\nint x;\n"
        self.assertEqual(c.split(b"\n")[10].split(b": ")[0], b" * SPDX-License-Identifier")
        self.assertEqual(spdx.apply_to_bytes(DUAL_H, c), c)

    def test_identifier_in_block_line_11_wrong_raises(self):
        c = b"/*\n" + b" * filler\n" * 9 + b" * SPDX-License-Identifier: MIT\n */\nint x;\n"
        with self.assertRaises(spdx.SpdxError):
            spdx.apply_to_bytes(DUAL_H, c)

    def test_shebang_with_identifier_line2_is_noop(self):
        c = b"#!/usr/bin/env python3\n" + line("#", AGPL) + b"import os\n"
        self.assertEqual(spdx.apply_to_bytes("src/engine/tools/third-party-notices/generate.py", c), c)

    def test_crlf_preserved(self):
        c = b"#include <a>\r\nint x;\r\n"
        out = spdx.apply_to_bytes(ENGINE_CPP, c)
        self.assertTrue(out.endswith(c))
        self.assertEqual(out[:-len(c)], line("//", AGPL))
        self.assertEqual(out.count(b"\r\n"), 2)

    def test_crlf_shebang_other_bytes_untouched(self):
        c = b"#!/bin/sh\r\necho hi\r\n"
        out = spdx.apply_to_bytes("src/engine/a.sh", c)
        self.assertTrue(out.startswith(b"#!/bin/sh\r\n"))
        self.assertTrue(out.endswith(b"echo hi\r\n"))

    def test_no_trailing_newline_preserved(self):
        c = b"int x;"
        out = spdx.apply_to_bytes(ENGINE_CPP, c)
        self.assertTrue(out.endswith(b"int x;"))
        self.assertFalse(out.endswith(b"\n"))
        self.assertEqual(out, line("//", AGPL) + c)

    def test_non_utf8_bytes_preserved(self):
        c = b"// caf\xe9\nint x;\n"
        out = spdx.apply_to_bytes(ENGINE_CPP, c)
        self.assertTrue(out.endswith(c))

    def test_identifier_token_inside_string_is_not_an_identifier(self):
        c = b'X = "SPDX-License-Identifier: MIT"\n'
        self.assertEqual(spdx.apply_to_bytes("src/engine/a.py", c), line("#", AGPL) + c)

    def test_correct_identifier_after_line_30_raises(self):
        c = b"// c\n" * 30 + line("//", AGPL)  # line 31
        with self.assertRaises(spdx.SpdxError):
            spdx.apply_to_bytes(ENGINE_CPP, c)

    def test_python_coding_on_line2_after_comment_goes_to_line3(self):
        c = b"# header\n# -*- coding: latin-1 -*-\nx = 1\n"
        out = spdx.apply_to_bytes("src/engine/a.py", c)
        self.assertEqual(out, b"# header\n# -*- coding: latin-1 -*-\n" + line("#", AGPL) + b"x = 1\n")

    def test_out_of_scope_not_modified(self):
        # Excluded files must never receive a line; either unchanged bytes or an
        # error is acceptable, a modified output is not.
        for p, c in (("src/engine/a_pb2.pyi", b"x: int\n"),
                     ("src/engine/pkg/__init__.py", b""),
                     ("src/shared_modules/utils/makeUnique.h", b"// N3656\n"),
                     ("src/engine/test/x/data/f.py", b"x = 1\n")):
            try:
                out = spdx.apply_to_bytes(p, c)
            except Exception:
                continue
            self.assertEqual(out, c, p)


def git(repo, *args):
    return subprocess.run(["git", "-C", repo] + list(args), check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class CliTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.repo = self._tmp.name
        git(self.repo, "init", "-q")

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, rel, content, mode=None):
        p = os.path.join(self.repo, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(content)
        if mode is not None:
            os.chmod(p, mode)
        git(self.repo, "add", "-f", rel)
        return p

    def read(self, rel):
        with open(os.path.join(self.repo, rel), "rb") as f:
            return f.read()

    def run_cli(self, *args):
        r = subprocess.run([sys.executable, MODULE_PATH, "--repo", self.repo] + list(args),
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return r.returncode, r.stdout.decode(), r.stderr.decode()

    def populate_clean(self):
        self.write("src/engine/a.cpp", b"int a;\n")
        self.write("src/engine/tool.sh", b"#!/bin/sh\necho\n", mode=0o755)
        self.write("src/shared_modules/utils/u.h", b"int u;\n")
        self.write("src/other/o.cpp", b"int o;\n")
        self.write("src/engine/README.md", b"doc\n")

    def test_classify_cli(self):
        rc, out, _ = self.run_cli("classify", ENGINE_CPP, DUAL_H, "src/other/o.cpp",
                                  "src/engine/tools/s.py")
        self.assertEqual(rc, 0)
        rows = [l.split("\t") for l in out.splitlines()]
        self.assertEqual(rows[0], [ENGINE_CPP, AGPL, "//"])
        self.assertEqual(rows[1], [DUAL_H, DUAL, "//"])
        self.assertEqual(rows[2], ["src/other/o.cpp", "none"])
        self.assertEqual(rows[3], ["src/engine/tools/s.py", AGPL, "#"])

    def test_list_scopes(self):
        self.populate_clean()
        rc, out, _ = self.run_cli("list")
        self.assertEqual(rc, 0)
        self.assertEqual(set(out.split()),
                         {"src/engine/a.cpp", "src/engine/tool.sh", "src/shared_modules/utils/u.h"})
        rc, out, _ = self.run_cli("list", "--scope", "agpl")
        self.assertEqual(set(out.split()), {"src/engine/a.cpp", "src/engine/tool.sh"})
        rc, out, _ = self.run_cli("list", "--scope", "dual")
        self.assertEqual(set(out.split()), {"src/shared_modules/utils/u.h"})

    def test_list_ignores_untracked_and_symlinks(self):
        self.populate_clean()
        with open(os.path.join(self.repo, "src/engine/untracked.cpp"), "wb") as f:
            f.write(b"int z;\n")
        os.symlink("a.cpp", os.path.join(self.repo, "src/engine/link.cpp"))
        git(self.repo, "add", "-f", "src/engine/link.cpp")
        rc, out, _ = self.run_cli("list", "--scope", "agpl")
        self.assertNotIn("src/engine/untracked.cpp", out.split())
        self.assertNotIn("src/engine/link.cpp", out.split())
        self.assertIn("src/engine/a.cpp", out.split())

    def test_census_missing_rc1_then_apply_then_rc0(self):
        self.populate_clean()
        rc, out, _ = self.run_cli("census")
        self.assertEqual(rc, 1)
        self.assertIn("missing:", out)
        self.assertIn("src/engine/a.cpp", out)
        rc, out, _ = self.run_cli("apply")
        self.assertEqual(rc, 0)
        self.assertIn("applied 3, unchanged 0", out)
        rc, out, _ = self.run_cli("census")
        self.assertEqual(rc, 0, out)
        rc, out, _ = self.run_cli("apply")
        self.assertEqual(rc, 0)
        self.assertIn("applied 0, unchanged 3", out)
        self.assertEqual(self.read("src/engine/a.cpp"), line("//", AGPL) + b"int a;\n")
        self.assertEqual(self.read("src/engine/tool.sh"),
                         b"#!/bin/sh\n" + line("#", AGPL) + b"echo\n")
        self.assertEqual(self.read("src/shared_modules/utils/u.h"),
                         line("//", DUAL) + b"int u;\n")
        self.assertEqual(self.read("src/other/o.cpp"), b"int o;\n")

    def test_apply_scope_limits(self):
        self.populate_clean()
        rc, out, _ = self.run_cli("apply", "--scope", "dual")
        self.assertEqual(rc, 0)
        self.assertEqual(self.read("src/engine/a.cpp"), b"int a;\n")
        self.assertTrue(self.read("src/shared_modules/utils/u.h").startswith(b"// SPDX"))

    def test_apply_preserves_mode(self):
        self.populate_clean()
        self.run_cli("apply")
        mode = stat.S_IMODE(os.stat(os.path.join(self.repo, "src/engine/tool.sh")).st_mode)
        self.assertEqual(mode, 0o755)

    def test_apply_preserves_crlf_and_missing_final_newline(self):
        self.write("src/engine/crlf.cpp", b"int a;\r\nint b;\r\n")
        self.write("src/engine/nonl.cpp", b"int a;")
        rc, _, _ = self.run_cli("apply")
        self.assertEqual(rc, 0)
        self.assertEqual(self.read("src/engine/crlf.cpp"), line("//", AGPL) + b"int a;\r\nint b;\r\n")
        self.assertEqual(self.read("src/engine/nonl.cpp"), line("//", AGPL) + b"int a;")

    def test_apply_wrong_identifier_rc1_names_file_and_leaves_it(self):
        wrong = line("//", "GPL-2.0-only") + b"int w;\n"
        self.write("src/engine/wrong.cpp", wrong)
        self.write("src/engine/ok.cpp", b"int ok;\n")
        rc, out, err = self.run_cli("apply")
        self.assertEqual(rc, 1)
        self.assertIn("src/engine/wrong.cpp", out + err)
        self.assertEqual(self.read("src/engine/wrong.cpp"), wrong)

    def test_census_wrong_rc1(self):
        self.write("src/engine/wrong.cpp", line("//", "MIT") + b"int w;\n")
        rc, out, _ = self.run_cli("census")
        self.assertEqual(rc, 1)
        self.assertIn("wrong:", out)
        self.assertIn("src/engine/wrong.cpp", out)

    def test_census_excluded_with_identifier_rc1(self):
        self.write("src/engine/a.cpp", line("//", AGPL) + b"int a;\n")
        self.write("src/engine/gen/x.pb.h", line("//", AGPL) + b"int g;\n")
        self.write("src/shared_modules/utils/makeUnique.h", line("//", DUAL) + b"int m;\n")
        rc, out, _ = self.run_cli("census")
        self.assertEqual(rc, 1)
        self.assertIn("excluded-with-identifier:", out)
        self.assertIn("src/engine/gen/x.pb.h", out)
        self.assertIn("src/shared_modules/utils/makeUnique.h", out)

    def test_census_mutation_detects_both(self):
        self.populate_clean()
        self.write("src/engine/gen/x.pb.h", b"int g;\n")
        self.run_cli("apply")
        rc, _, _ = self.run_cli("census")
        self.assertEqual(rc, 0)
        self.write("src/engine/a.cpp", b"int a;\n")  # remove the line
        self.write("src/engine/gen/x.pb.h", line("//", AGPL) + b"int g;\n")  # add to generated
        rc, out, _ = self.run_cli("census")
        self.assertEqual(rc, 1)
        self.assertIn("src/engine/a.cpp", out)
        self.assertIn("src/engine/gen/x.pb.h", out)

    def test_census_clean_with_excluded_files_rc0(self):
        self.write("src/engine/a.cpp", line("//", AGPL) + b"int a;\n")
        self.write("src/engine/gen/x.pb.h", b"int g;\n")
        self.write("src/engine/pkg/__init__.py", b"")
        self.write("src/engine/test/t/data/f.py", b"x = 1\n")
        rc, out, _ = self.run_cli("census")
        self.assertEqual(rc, 0, out)

    def test_census_unlisted_code_is_informative(self):
        self.write("src/engine/a.cpp", line("//", AGPL) + b"int a;\n")
        self.write("src/engine/web/app.js", b"var a;\n")
        self.write("src/engine/bin/runner", b"#!/bin/sh\necho\n")
        rc, out, _ = self.run_cli("census")
        self.assertEqual(rc, 0, out)
        self.assertIn("unlisted-code:", out)
        self.assertIn("src/engine/web/app.js", out)
        self.assertIn("src/engine/bin/runner", out)

    def test_census_scope_dual(self):
        self.write("src/engine/a.cpp", b"int a;\n")  # missing, but agpl scope
        self.write("src/shared_modules/utils/u.h", line("//", DUAL) + b"int u;\n")
        rc, out, _ = self.run_cli("census", "--scope", "dual")
        self.assertEqual(rc, 0, out)
        self.write("src/shared_modules/keystore/k.cpp", b"int k;\n")
        rc, out, _ = self.run_cli("census", "--scope", "dual")
        self.assertEqual(rc, 1)
        self.assertIn("src/shared_modules/keystore/k.cpp", out)


    def classify_rows(self, *paths):
        rc, out, _ = self.run_cli("classify", *paths)
        self.assertEqual(rc, 0)
        return [l.split("\t") for l in out.splitlines()]

    def test_classify_cli_normalizes_dot_slash_and_dotdot(self):
        for r in self.classify_rows("./src/engine/x.cpp", "src/engine/../engine/x.cpp"):
            self.assertEqual(r[1:], [AGPL, "//"], r)

    def test_classify_cli_absolute_path_inside_repo(self):
        rows = self.classify_rows(os.path.join(self.repo, "src/engine/x.cpp"))
        self.assertEqual(rows[0][1:], [AGPL, "//"], rows)

    def test_classify_cli_nonexistent_path_classified_by_path(self):
        self.assertFalse(os.path.exists(os.path.join(self.repo, "src/engine/ghost.cpp")))
        rows = self.classify_rows("src/engine/ghost.cpp", "src/other/ghost.cpp")
        self.assertEqual(rows[0], ["src/engine/ghost.cpp", AGPL, "//"])
        self.assertEqual(rows[1], ["src/other/ghost.cpp", "none"])

    def test_census_dual_copying_with_identifier_is_not_listed(self):
        self.write("src/shared_modules/utils/u.h", line("//", DUAL) + b"int u;\n")
        self.write("src/shared_modules/utils/COPYING",
                   b"Dual licensed.\nSPDX-License-Identifier: " + DUAL.encode() + b"\n")
        rc, out, _ = self.run_cli("census", "--scope", "dual")
        self.assertEqual(rc, 0, out)
        self.assertNotIn("COPYING", out)

    def test_census_identifier_after_line_30_is_wrong_or_rc1(self):
        self.write("src/engine/late.cpp", b"// c\n" * 30 + line("//", AGPL) + b"int a;\n")
        rc, out, _ = self.run_cli("census")
        self.assertEqual(rc, 1, out)
        self.assertIn("src/engine/late.cpp", out)


if __name__ == "__main__":
    unittest.main()
