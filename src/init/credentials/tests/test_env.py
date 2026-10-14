# Copyright (C) Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""The .env grammar and the value lookup order."""

import io
import os

import pytest

SECRET = "Sup3r.Secret-Value"


@pytest.mark.parametrize("text,expected", [
    ("A=plain", {"A": "plain"}),
    ('A="quoted value"', {"A": "quoted value"}),
    ("A='single'", {"A": "single"}),
    ("   A=spaced   ", {"A": "spaced"}),
    ("# a comment\nA=1", {"A": "1"}),
    ("\n\nA=1\n\n", {"A": "1"}),
    ("A=x=y=z", {"A": "x=y=z"}),
    ("A=", {"A": ""}),
    ("A=1\r\nB=2\r\n", {"A": "1", "B": "2"}),
    ('A=in"side', {"A": 'in"side'}),
])
def test_grammar_values(resolver, text, expected):
    parsed = resolver.parse_env(text.encode(), "/f")
    assert {name: value for name, (value, _) in parsed.items()} == expected


@pytest.mark.parametrize("text,line", [
    ("export A=1", 1),
    ("1A=1", 1),
    ("A", 1),
    ("A=1\nA=2", 2),
    ('A="unbalanced', 1),
    ("A=unbalanced'", 1),
    ('A="mismatch\'', 1),
    ("A = 1", 1),
    ("# ok\nA=1\nB 2", 3),
    ("A=\xff", 1),
])
def test_grammar_errors(resolver, text, line):
    data = text.encode("latin-1") if "\xff" in text else text.encode()
    with pytest.raises(resolver.EnvSyntaxError) as caught:
        resolver.parse_env(data, "/f")
    assert (caught.value.path, caught.value.line) == ("/f", line)
    assert str(caught.value) == f"/f:{line}"


def test_syntax_error_never_prints_the_value(resolver, sandbox):
    sandbox.write(os.path.join(sandbox.conf, "local.env"), f'WAZUH_MANAGER_API_PASSWORD="{SECRET}\n')
    out, err = io.StringIO(), io.StringIO()
    assert resolver.main(["--check"], paths=sandbox.paths, environ={}, out=out, err=err) == 1
    assert f"INVALID {sandbox.conf}/local.env:1: " in err.getvalue()
    assert SECRET not in out.getvalue() + err.getvalue()


def build(resolver, sandbox, environ, local=None, indexer=None):
    if local is not None:
        sandbox.write(os.path.join(sandbox.conf, "local.env"), local)
    if indexer is not None:
        sandbox.make_indexer_export(credentials=indexer)
    report = resolver.Report(quiet=True, out=io.StringIO(), err=io.StringIO())
    with resolver.open_top(sandbox.conf, resolver.conf_spec(sandbox.paths)) as conf:
        return resolver.build_lookup(sandbox.paths, conf, report, environ), report


def test_lookup_order(resolver, sandbox):
    lookup, report = build(resolver, sandbox, {"A": "env", "E": ""},
                           local="A=local\nB=local\nE=local\n",
                           indexer="A=idx\nB=idx\nC=idx\nWAZUH_INDEXER_MANAGER_PASSWORD=from-indexer\n")
    assert not report.has()
    assert lookup.get("A")[0] == "env"
    assert lookup.get("B")[0] == "local"
    assert lookup.get("C") is None                                   # the export serves one variable only
    assert lookup.get("E")[0] == "local"                             # an empty env value is unset
    assert lookup.get("E", empty_is_unset=False)[0] == ""            # unless the caller says otherwise
    value, source = lookup.get("WAZUH_INDEXER_MANAGER_PASSWORD")
    assert value == "from-indexer" and source.endswith("indexer-export/credentials.env:4")


def test_local_beats_indexer_export(resolver, sandbox):
    lookup, _ = build(resolver, sandbox, {}, local="WAZUH_INDEXER_MANAGER_PASSWORD=local\n",
                      indexer="WAZUH_INDEXER_MANAGER_PASSWORD=idx\n")
    assert lookup.get("WAZUH_INDEXER_MANAGER_PASSWORD") == ("local", f"{sandbox.conf}/local.env:1")


def test_unsafe_local_env_not_read(resolver, sandbox):
    sandbox.write(os.path.join(sandbox.conf, "local.env"), f"A={SECRET}\n", mode=0o620)
    lookup, report = build(resolver, sandbox, {})
    assert lookup.get("A") is None and not lookup.inputs_accepted
    assert report.problems == [("UNSAFE", f"{sandbox.conf}/local.env", "group-writable")]


def test_malformed_file_contributes_nothing(resolver, sandbox):
    lookup, report = build(resolver, sandbox, {}, local="A=1\nbroken\n")
    assert lookup.get("A") is None and not lookup.inputs_accepted
    assert report.problems == [("INVALID", f"{sandbox.conf}/local.env:2", "not a NAME=value line")]


def test_indexer_export_may_have_its_group_but_not_group_write(resolver, sandbox):
    sandbox.make_indexer_export(credentials="WAZUH_INDEXER_MANAGER_PASSWORD=x\n")
    os.chown(sandbox.indexer_export, 0, sandbox.account_gid)          # stands in for wazuh-indexer
    lookup, report = build(resolver, sandbox, {})
    assert not report.has() and lookup.get("WAZUH_INDEXER_MANAGER_PASSWORD")[0] == "x"
    os.chmod(sandbox.indexer_export, 0o770)
    lookup, report = build(resolver, sandbox, {})
    assert lookup.get("WAZUH_INDEXER_MANAGER_PASSWORD") is None
    assert report.problems == [("UNSAFE", sandbox.indexer_export, "group-writable")]


def test_rejected_local_does_not_fall_back_to_indexer(resolver, sandbox):
    lookup, report = build(resolver, sandbox, {}, local="broken\n",
                           indexer="WAZUH_INDEXER_MANAGER_PASSWORD=from-indexer\n")
    assert report.has(resolver.INVALID)
    assert not lookup.inputs_accepted
    assert lookup.get("WAZUH_INDEXER_MANAGER_PASSWORD") is None
