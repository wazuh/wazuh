#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Unit tests for spdx_scope.py (classifier and applier of SPDX identifiers)."""

import importlib.util
import os
import shutil
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


    def test_new_slash_and_hash_extensions(self):
        for ext in (".js", ".ts", ".rs", ".java", ".kt", ".c++", ".cxx", ".hh", ".hxx", ".ipp", ".tcc"):
            self.assertEqual(spdx.classify("src/engine/a" + ext, b"x\n"), (AGPL, "//"), ext)
        for ext in (".rb", ".bash", ".zsh", ".ps1"):
            self.assertEqual(spdx.classify("src/engine/a" + ext, b"x\n"), (AGPL, "#"), ext)

    def test_shebang_supported_interpreters_are_hash(self):
        for sb in (b"#!/bin/bash\n", b"#!/usr/bin/env python3\n", b"#!/usr/bin/env -S python3 -u\n",
                   b"#!/usr/bin/python3.11\n", b"#! /bin/sh\r\n", b"#!/usr/bin/make -f\n",
                   b"#!/usr/bin/awk -f\n", b"#!/usr/bin/env perl\n"):
            self.assertEqual(spdx.classify("src/engine/tool", sb + b"x\n"), (AGPL, "#"), sb)

    def test_deb_rules_unchanged(self):
        p = "src/engine/internal_packages/debs/SPECS/rules"
        self.assertEqual(spdx.classify(p, b"#!/usr/bin/make -f\n"), (AGPL, "#"))
        # HASH_PATHS wins over the shebang: an unsupported interpreter or no content keeps the `#` style
        self.assertEqual(spdx.classify(p, b"#!/usr/bin/env node\n"), (AGPL, "#"))
        self.assertEqual(spdx.classify(p, None), (AGPL, "#"))

    def test_lua_and_node_shebang_are_unsupported(self):
        self.assertIs(spdx.classify("src/engine/x.lua", b"x = 1\n"), spdx.UNSUPPORTED)
        self.assertIs(spdx.classify("src/engine/tool", b"#!/usr/bin/env node\n"), spdx.UNSUPPORTED)
        self.assertIs(spdx.classify("src/shared_modules/utils/x.bat", b"@echo off\n"), spdx.UNSUPPORTED)

    def test_unsupported_only_in_scope_and_code(self):
        self.assertIsNone(spdx.classify("docs/x.lua", b"x = 1\n"))
        self.assertIsNone(spdx.classify("src/wazuh_modules/x.lua", b"x = 1\n"))
        self.assertIsNone(spdx.classify("src/engine/tool", b"plain text\n"))
        self.assertIsNone(spdx.classify("src/engine/tool", None))
        # The shebang is consulted only for files without an extension
        self.assertIsNone(spdx.classify("src/engine/run.in", b"#!/bin/sh\n"))
        self.assertIsNone(spdx.classify("src/engine/notes.txt", b"#!/usr/bin/env node\n"))

    def test_unsupported_after_exclusions(self):
        self.assertIsNone(spdx.classify("src/engine/x.lua", b""))
        self.assertIsNone(spdx.classify("src/engine/x.lua", b" \n"))
        self.assertIsNone(spdx.classify("src/engine/test/t/fixtures/x.lua", b"x = 1\n"))
        self.assertIsNone(spdx.classify("src/engine/test/t/data/tool", b"#!/usr/bin/env node\n"))

    def test_apply_to_bytes_rejects_unsupported(self):
        with self.assertRaises(spdx.SpdxError):
            spdx.apply_to_bytes("src/engine/x.lua", b"x = 1\n")


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

    def test_insert_after_shebang_without_extension(self):
        out = spdx.apply_to_bytes("src/engine/tool", b"#!/bin/bash\necho\n")
        self.assertEqual(out, b"#!/bin/bash\n" + line("#", AGPL) + b"echo\n")

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

    def test_python_shebang_then_coding_without_extension(self):
        src = b"#!/usr/bin/env python3\n# -*- coding: latin-1 -*-\nx = '\xe9'\n"
        out = spdx.apply_to_bytes("src/engine/tool", src)
        self.assertEqual(out.splitlines()[1], b"# -*- coding: latin-1 -*-")
        self.assertEqual(out.splitlines()[2], line("#", AGPL).rstrip(b"\n"))
        compile(out, "tool", "exec")  # the latin-1 byte is still decoded with the declared encoding

    def test_ruby_encoding_kept_on_line_2(self):
        for path, src in (("src/engine/x.rb", b"#!/usr/bin/env ruby\n# encoding: ISO-8859-1\nputs '\xe9'\n"),
                          ("src/engine/tool", b"#!/usr/bin/ruby\n# encoding: ISO-8859-1\nputs '\xe9'\n")):
            out = spdx.apply_to_bytes(path, src)
            self.assertEqual(out.splitlines()[1], b"# encoding: ISO-8859-1", path)
            self.assertEqual(out.splitlines()[2], line("#", AGPL).rstrip(b"\n"), path)

    def test_ruby_encoding_line_1_without_shebang(self):
        out = spdx.apply_to_bytes("src/engine/x.rb", b"# encoding: ISO-8859-1\nputs '\xe9'\n")
        self.assertEqual(out, b"# encoding: ISO-8859-1\n" + line("#", AGPL) + b"puts '\xe9'\n")

    def test_utf16_file_is_refused(self):
        src = "\ufeffWrite-Host 'x'\n".encode("utf-16-le")
        with self.assertRaises(spdx.SpdxError):
            spdx.apply_to_bytes("src/engine/x.ps1", src)
        with self.assertRaises(spdx.SpdxError):
            spdx.apply_to_bytes("src/engine/x.ps1", "\ufeffx\n".encode("utf-16-be"))

    def test_wide_encodings_with_identifier_pass(self):
        for codec in ("utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be"):
            src = ("\ufeff# SPDX-License-Identifier: AGPL-3.0-or-later\r\nWrite-Host 'x'\r\n").encode(codec)
            self.assertEqual(spdx.find_identifier(src), AGPL, codec)
            self.assertEqual(spdx.apply_to_bytes("src/engine/x.ps1", src), src, codec)  # unchanged, no error

    def test_utf8_bom_stays_first(self):
        out = spdx.apply_to_bytes(ENGINE_CPP, b"\xef\xbb\xbfint a;\n")
        self.assertEqual(out, b"\xef\xbb\xbf" + line("//", AGPL) + b"int a;\n")
        self.assertEqual(spdx.find_identifier(out), AGPL)
        self.assertEqual(spdx.apply_to_bytes(ENGINE_CPP, out), out)  # idempotent
        out = spdx.apply_to_bytes("src/engine/x.ps1", b"\xef\xbb\xbfWrite-Host x\n")
        self.assertEqual(out, b"\xef\xbb\xbf" + line("#", AGPL) + b"Write-Host x\n")

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
        self.write("src/engine/web/app.lua", b"local a\n")
        self.write("src/engine/bin/runner", b"#!/usr/bin/env node\nx\n")
        self.write("src/shared_modules/utils/x.bat", b"@echo off\n")
        rc, out, _ = self.run_cli("census")
        self.assertEqual(rc, 0, out)
        self.assertIn("unlisted-code:", out)
        self.assertIn("src/engine/web/app.lua", out)
        self.assertIn("src/engine/bin/runner", out)
        self.assertIn("src/shared_modules/utils/x.bat", out)
        self.assertIn("unlisted-code=3", out)

    def test_classify_list_apply_unsupported(self):
        self.write("src/engine/a.cpp", b"int a;\n")
        self.write("src/engine/x.lua", b"x = 1\n")
        rows = self.classify_rows("src/engine/x.lua", "src/engine/a.cpp")
        self.assertEqual(rows[0], ["src/engine/x.lua", "unsupported"])
        rc, out, _ = self.run_cli("list")
        self.assertEqual(rc, 0)
        self.assertEqual(out.split(), ["src/engine/a.cpp"])
        rc, out, err = self.run_cli("apply")
        self.assertEqual(rc, 1)
        self.assertIn("src/engine/x.lua: unsupported code type (.lua)", err)
        self.assertNotIn("Traceback", err)
        self.assertIn("applied 1, unchanged 0, unsupported 1", out)
        self.assertEqual(self.read("src/engine/x.lua"), b"x = 1\n")
        self.assertTrue(self.read("src/engine/a.cpp").startswith(b"// SPDX"))

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


CHECK_SH = os.path.join(HERE, "check_spdx.sh")
HINT = "spdx_scope.py apply"
GITENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
          "GIT_COMMITTER_EMAIL": "t@t", "GIT_CONFIG_GLOBAL": os.devnull,
          "GIT_CONFIG_SYSTEM": os.devnull}


class CheckTest(unittest.TestCase):
    """`spdx_scope.py check -` (NUL-separated paths on stdin) in a temp git repo."""

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
        return p

    def check(self, *paths):
        stdin = b"".join((x if isinstance(x, bytes) else x.encode()) + b"\0" for x in paths)
        r = subprocess.run([sys.executable, MODULE_PATH, "--repo", self.repo, "check", "-"],
                           cwd=self.repo, input=stdin,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return r.returncode, r.stdout.decode(errors="replace"), r.stderr.decode(errors="replace")

    def test_ok(self):
        self.write(ENGINE_CPP, line("//", AGPL) + b"int x;\n")
        self.write(DUAL_H, line("//", DUAL) + b"int u;\n")
        rc, out, err = self.check(ENGINE_CPP, DUAL_H)
        self.assertEqual(rc, 0, out + err)
        self.assertIn("checked 2, failed 0", out)
        self.assertNotIn(HINT, out + err)

    def test_missing(self):
        self.write(ENGINE_CPP, b"int x;\n")
        rc, out, err = self.check(ENGINE_CPP)
        self.assertEqual(rc, 1)
        self.assertIn("%s: missing %s" % (ENGINE_CPP, AGPL), out.splitlines())
        self.assertIn("checked 1, failed 1", out)

    def test_utf16_with_identifier_passes(self):
        path = "src/engine/tools/x.ps1"
        self.write(path, "\ufeff# SPDX-License-Identifier: AGPL-3.0-or-later\r\nWrite-Host 'x'\r\n".encode("utf-16-le"))
        rc, out, err = self.check(path)
        self.assertEqual(rc, 0, out + err)
        self.assertIn("checked 1, failed 0", out)

    def test_utf16_without_identifier_is_missing(self):
        path = "src/engine/tools/x.ps1"
        self.write(path, "\ufeffWrite-Host 'x'\r\n".encode("utf-16-le"))
        rc, out, _ = self.check(path)
        self.assertEqual(rc, 1)
        self.assertIn("%s: missing %s" % (path, AGPL), out.splitlines())

    def test_missing_dual_expects_dual_id(self):
        self.write(DUAL_H, b"int u;\n")
        rc, out, _ = self.check(DUAL_H)
        self.assertEqual(rc, 1)
        self.assertIn("%s: missing %s" % (DUAL_H, DUAL), out.splitlines())

    def test_wrong(self):
        self.write(ENGINE_CPP, line("//", "GPL-2.0-only") + b"int x;\n")
        self.write(DUAL_H, line("//", AGPL) + b"int u;\n")
        rc, out, _ = self.check(ENGINE_CPP, DUAL_H)
        self.assertEqual(rc, 1)
        lines = out.splitlines()
        self.assertIn("%s: wrong GPL-2.0-only (expected %s)" % (ENGINE_CPP, AGPL), lines)
        self.assertIn("%s: wrong %s (expected %s)" % (DUAL_H, AGPL, DUAL), lines)
        self.assertIn("checked 2, failed 2", out)

    def test_out_of_scope_ignored_and_not_counted(self):
        self.write("src/other/o.cpp", b"int o;\n")
        self.write("src/engine/README.md", b"doc\n")
        self.write(ENGINE_CPP, line("//", AGPL) + b"int x;\n")
        rc, out, _ = self.check("src/other/o.cpp", "src/engine/README.md", ENGINE_CPP)
        self.assertEqual(rc, 0, out)
        self.assertIn("checked 1, failed 0", out)
        self.assertNotIn("o.cpp", out)

    def test_nonexistent_ignored(self):
        rc, out, _ = self.check("src/engine/ghost.cpp")
        self.assertEqual(rc, 0, out)
        self.assertIn("checked 0, failed 0", out)
        self.assertNotIn("ghost", out)

    def test_symlink_ignored(self):
        self.write(ENGINE_CPP, line("//", AGPL) + b"int x;\n")
        os.symlink("x.cpp", os.path.join(self.repo, "src/engine/source/x/link.cpp"))
        rc, out, _ = self.check("src/engine/source/x/link.cpp")
        self.assertEqual(rc, 0, out)
        self.assertIn("checked 0, failed 0", out)

    def test_symlink_to_file_without_line_ignored(self):
        self.write("src/other/t.cpp", b"int t;\n")
        os.makedirs(os.path.join(self.repo, "src/engine"), exist_ok=True)
        os.symlink("../other/t.cpp", os.path.join(self.repo, "src/engine/l.cpp"))
        rc, out, _ = self.check("src/engine/l.cpp")
        self.assertEqual(rc, 0, out)
        self.assertIn("checked 0, failed 0", out)

    def test_gitlink_ignored(self):
        sha = "1" * 40
        git(self.repo, "update-index", "--add", "--cacheinfo", "160000,%s,src/engine/sub.cpp" % sha)
        # Also as an (empty) directory, as a checked-out submodule would be.
        os.makedirs(os.path.join(self.repo, "src/engine/sub.cpp"))
        rc, out, _ = self.check("src/engine/sub.cpp")
        self.assertEqual(rc, 0, out)
        self.assertIn("checked 0, failed 0", out)
        self.assertNotIn("sub.cpp", out)

    def test_gitlink_in_dual_dir_ignored(self):
        git(self.repo, "update-index", "--add", "--cacheinfo",
            "160000,%s,src/shared_modules/utils/mod" % ("2" * 40))
        rc, out, _ = self.check("src/shared_modules/utils/mod")
        self.assertEqual(rc, 0, out)
        self.assertIn("checked 0, failed 0", out)

    def test_non_utf8_filename_no_traceback(self):
        name = b"src/engine/bad\xff.cpp"
        os.makedirs(os.path.join(self.repo, "src/engine"), exist_ok=True)
        with open(os.path.join(os.fsencode(self.repo), name), "wb") as f:
            f.write(b"int x;\n")
        rc, out, err = self.check(name)
        self.assertEqual(rc, 1)
        self.assertNotIn("Traceback", err)
        self.assertIn("checked 1, failed 1", out)
        self.assertIn("missing " + AGPL, out)

    def test_non_utf8_filename_ok(self):
        name = b"src/engine/ok\xff.cpp"
        os.makedirs(os.path.join(self.repo, "src/engine"), exist_ok=True)
        with open(os.path.join(os.fsencode(self.repo), name), "wb") as f:
            f.write(line("//", AGPL) + b"int x;\n")
        rc, out, err = self.check(name)
        self.assertEqual(rc, 0, out + err)
        self.assertNotIn("Traceback", err)
        self.assertIn("checked 1, failed 0", out)

    def test_ts_without_identifier_fails(self):
        self.write("src/engine/web/x.ts", b"let a = 1;\n")
        rc, out, _ = self.check("src/engine/web/x.ts")
        self.assertEqual(rc, 1)
        self.assertIn("src/engine/web/x.ts: missing %s" % AGPL, out.splitlines())

    def test_ts_with_identifier_ok(self):
        self.write("src/engine/web/x.ts", line("//", AGPL) + b"let a = 1;\n")
        rc, out, err = self.check("src/engine/web/x.ts")
        self.assertEqual(rc, 0, out + err)
        self.assertIn("checked 1, failed 0", out)

    def test_rb_without_identifier_fails(self):
        self.write("src/engine/x.rb", b"puts 1\n")
        rc, out, _ = self.check("src/engine/x.rb")
        self.assertEqual(rc, 1)
        self.assertIn("src/engine/x.rb: missing %s" % AGPL, out.splitlines())

    def test_dual_rs_without_identifier_fails(self):
        self.write("src/shared_modules/utils/x.rs", b"fn main() {}\n")
        rc, out, _ = self.check("src/shared_modules/utils/x.rs")
        self.assertEqual(rc, 1)
        self.assertIn("src/shared_modules/utils/x.rs: missing %s" % DUAL, out.splitlines())

    def test_shebang_bash_without_identifier_fails(self):
        self.write("src/engine/tool", b"#!/bin/bash\necho\n")
        rc, out, _ = self.check("src/engine/tool")
        self.assertEqual(rc, 1)
        self.assertIn("src/engine/tool: missing %s" % AGPL, out.splitlines())

    def test_lua_is_unsupported(self):
        self.write("src/engine/x.lua", b"x = 1\n")
        rc, out, _ = self.check("src/engine/x.lua")
        self.assertEqual(rc, 1)
        self.assertIn("src/engine/x.lua: unsupported code type (.lua): add its comment style to "
                      ".github/scripts/spdx_scope.py or exclude the file", out.splitlines())
        self.assertIn("checked 1, failed 1", out)
        self.assertIn(HINT, out)

    def test_shebang_node_is_unsupported(self):
        self.write("src/engine/tool", b"#!/usr/bin/env node\nconsole.log(1)\n")
        rc, out, _ = self.check("src/engine/tool")
        self.assertEqual(rc, 1)
        self.assertIn("src/engine/tool: unsupported code type (#!node)", out)
        self.assertIn(HINT, out)

    def test_shebang_env_dash_s(self):
        self.write("src/engine/tool", b"#!/usr/bin/env -S python3 -u\nx = 1\n")
        rc, out, _ = self.check("src/engine/tool")
        self.assertEqual(rc, 1)
        self.assertIn("src/engine/tool: missing %s" % AGPL, out.splitlines())

    def test_shebang_versioned_python(self):
        self.write("src/engine/tool", b"#!/usr/bin/python3.11\nx = 1\n")
        rc, out, _ = self.check("src/engine/tool")
        self.assertEqual(rc, 1)
        self.assertIn("src/engine/tool: missing %s" % AGPL, out.splitlines())

    def test_shebang_space_crlf(self):
        self.write("src/engine/tool", b"#! /bin/sh\r\necho\r\n")
        rc, out, _ = self.check("src/engine/tool")
        self.assertEqual(rc, 1)
        self.assertIn("src/engine/tool: missing %s" % AGPL, out.splitlines())

    def test_deb_rules_unchanged(self):
        p = "src/engine/internal_packages/debs/SPECS/rules"
        self.write(p, b"#!/usr/bin/make -f\n")
        rc, out, _ = self.check(p)
        self.assertEqual(rc, 1)
        self.assertIn("%s: missing %s" % (p, AGPL), out.splitlines())

    def test_unlisted_out_of_scope_ignored(self):
        self.write("docs/x.ts", b"let a;\n")
        self.write("src/wazuh_modules/x.lua", b"x = 1\n")
        rc, out, _ = self.check("docs/x.ts", "src/wazuh_modules/x.lua")
        self.assertEqual(rc, 0, out)
        self.assertEqual(out.strip(), "checked 0, failed 0")

    def test_unsupported_excluded_files_ignored(self):
        self.write("src/engine/empty.lua", b"")
        self.write("src/engine/test/t/fixtures/x.lua", b"x = 1\n")
        rc, out, _ = self.check("src/engine/empty.lua", "src/engine/test/t/fixtures/x.lua")
        self.assertEqual(rc, 0, out)
        self.assertIn("checked 0, failed 0", out)

    def test_hint_only_when_failed(self):
        self.write(ENGINE_CPP, line("//", AGPL) + b"int x;\n")
        rc, out, err = self.check(ENGINE_CPP)
        self.assertEqual(rc, 0)
        self.assertNotIn(HINT, out + err)
        self.assertNotIn("THIRD_PARTY", out + err)
        self.write("src/engine/source/y.cpp", b"int y;\n")
        rc, out, err = self.check(ENGINE_CPP, "src/engine/source/y.cpp")
        self.assertEqual(rc, 1)
        self.assertIn(HINT, out + err)
        self.assertIn("THIRD_PARTY", out + err)
        self.assertIn("checked 2, failed 1", out)

    def test_empty_stdin(self):
        rc, out, _ = self.check()
        self.assertEqual(rc, 0)
        self.assertIn("checked 0, failed 0", out)

    def test_late_identifier_counts_as_missing(self):
        self.write(ENGINE_CPP, b"// filler\n" * 30 + line("//", AGPL) + b"int x;\n")
        rc, out, err = self.check(ENGINE_CPP)
        self.assertEqual(rc, 1, out + err)
        self.assertIn("%s: missing %s" % (ENGINE_CPP, AGPL), out.splitlines())

    def test_many_paths_via_stdin(self):
        paths = []
        for i in range(2000):
            rel = "src/engine/source/m/f%04d.cpp" % i
            self.write(rel, line("//", AGPL) + b"int x;\n")
            paths.append(rel)
        rc, out, err = self.check(*paths)
        self.assertEqual(rc, 0, out + err)
        self.assertIn("checked 2000, failed 0", out)


class CheckScriptTest(unittest.TestCase):
    """`check_spdx.sh [<base>]` end to end on a temp repo."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.repo = self._tmp.name
        self.env = dict(os.environ, **GITENV)
        self.git("init", "-q", "-b", "main")
        sd = os.path.join(self.repo, ".github/scripts")
        os.makedirs(sd)
        for n in ("check_spdx.sh", "spdx_scope.py"):
            shutil.copy(os.path.join(HERE, n), os.path.join(sd, n))
        self.commit("scripts")

    def tearDown(self):
        self._tmp.cleanup()

    def git(self, *args):
        return subprocess.run(["git", "-C", self.repo] + list(args), check=True, env=self.env,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.decode().strip()

    def write(self, rel, content, mode=None):
        p = os.path.join(self.repo, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(content)
        if mode is not None:
            os.chmod(p, mode)

    def commit(self, msg):
        self.git("add", "-A", "-f")
        self.git("commit", "-q", "--allow-empty", "-m", msg)
        return self.git("rev-parse", "HEAD")

    def run_script(self, *args, cwd=None):
        r = subprocess.run(["bash", os.path.join(self.repo, ".github/scripts/check_spdx.sh")]
                           + list(args), cwd=cwd or self.repo, env=self.env,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return r.returncode, r.stdout.decode(errors="replace"), r.stderr.decode(errors="replace")

    def test_base_range_rename_delete_mode_only(self):
        body = b"int u;\n" * 20  # keep the similarity high so git detects the rename
        self.write(DUAL_H, line("//", DUAL) + body)
        self.write("src/engine/gone.cpp", b"int gone;\n")  # no line, will be deleted
        self.write("src/engine/mode.sh", b"#!/bin/sh\n" + line("#", AGPL) + b"echo\n", mode=0o644)
        base = self.commit("base")
        os.makedirs(os.path.join(self.repo, "src/engine/source"), exist_ok=True)
        self.git("mv", DUAL_H, "src/engine/source/stringHelper.h")
        self.git("rm", "-q", "-f", "src/engine/gone.cpp")
        os.chmod(os.path.join(self.repo, "src/engine/mode.sh"), 0o755)
        self.commit("change")
        rc, out, err = self.run_script(base)
        new = "src/engine/source/stringHelper.h"
        self.assertEqual(rc, 1, out + err)
        self.assertIn("%s: wrong %s (expected %s)" % (new, DUAL, AGPL), out.splitlines())
        self.assertNotIn("gone.cpp", out + err)
        self.assertNotIn("mode.sh", out + err)
        self.assertIn("checked 2, failed 1", out)

    def test_no_in_scope_change_rc0(self):
        base = self.commit("empty")
        self.write("README.md", b"x\n")
        self.write("src/other/o.cpp", b"int o;\n")
        self.commit("noise")
        rc, out, err = self.run_script(base)
        self.assertEqual(rc, 0, out + err)
        self.assertIn("checked 0, failed 0", out)

    def test_fixed_file_passes_and_no_hint(self):
        base = self.commit("empty")
        self.write(ENGINE_CPP, line("//", AGPL) + b"int x;\n")
        self.commit("add")
        rc, out, err = self.run_script(base)
        self.assertEqual(rc, 0, out + err)
        self.assertIn("checked 1, failed 0", out)
        self.assertNotIn(HINT, out + err)

    def test_invalid_base_fails(self):
        self.commit("empty")
        rc, out, err = self.run_script("deadbeef")
        self.assertNotEqual(rc, 0, out + err)
        self.assertNotIn("checked 0, failed 0", out)

    def test_runs_from_subdirectory(self):
        base = self.commit("empty")
        self.write(ENGINE_CPP, b"int x;\n")
        self.commit("add")
        sub = os.path.join(self.repo, "src/engine")
        rc, out, err = self.run_script(base, cwd=sub)
        self.assertEqual(rc, 1, out + err)
        self.assertIn("%s: missing %s" % (ENGINE_CPP, AGPL), out.splitlines())
        self.assertIn("checked 1, failed 1", out)
        self.assertEqual((rc, out), self.run_script(base)[:2])

    def test_type_change_symlink_to_file_is_checked(self):
        link = "src/engine/source/link.cpp"
        os.makedirs(os.path.join(self.repo, "src/engine/source"), exist_ok=True)
        os.symlink("target.txt", os.path.join(self.repo, link))
        base = self.commit("symlink")
        self.assertTrue(self.git("ls-files", "-s", link).startswith("120000"))
        os.unlink(os.path.join(self.repo, link))
        self.write(link, b"int x;\n")
        self.commit("now a file")
        rc, out, err = self.run_script(base)
        self.assertEqual(rc, 1, out + err)
        self.assertIn("%s: missing %s" % (link, AGPL), out.splitlines())

    def test_no_argument_uses_first_parent_of_merge(self):
        self.write("README.md", b"base\n")
        self.commit("base")
        self.git("checkout", "-q", "-b", "feature")
        self.write(ENGINE_CPP, b"int x;\n")  # missing line, added on the feature branch
        self.commit("feature")
        self.git("checkout", "-q", "main")
        self.write("src/engine/source/onmain.cpp", b"int m;\n")  # also missing, but already in HEAD^1
        self.commit("main moves")
        self.git("merge", "--no-ff", "-q", "-m", "merge", "feature")
        self.assertEqual(len(self.git("rev-list", "--parents", "-n1", "HEAD").split()), 3)
        rc, out, err = self.run_script()
        self.assertEqual(rc, 1, out + err)
        self.assertIn("%s: missing %s" % (ENGINE_CPP, AGPL), out.splitlines())
        self.assertNotIn("onmain.cpp", out + err)
        self.assertIn("checked 1, failed 1", out)
        self.assertIn(HINT, out + err)
        # Same result with the explicit first parent.
        rc2, out2, _ = self.run_script(self.git("rev-parse", "HEAD^1"))
        self.assertEqual((rc2, out2), (rc, out))

    def test_no_argument_merge_with_fixed_file_rc0(self):
        self.write("README.md", b"base\n")
        self.commit("base")
        self.git("checkout", "-q", "-b", "feature")
        self.write(ENGINE_CPP, line("//", AGPL) + b"int x;\n")
        self.commit("feature")
        self.git("checkout", "-q", "main")
        self.write("other.txt", b"m\n")
        self.commit("main moves")
        self.git("merge", "--no-ff", "-q", "-m", "merge", "feature")
        rc, out, err = self.run_script()
        self.assertEqual(rc, 0, out + err)
        self.assertIn("checked 1, failed 0", out)


if __name__ == "__main__":
    unittest.main()
