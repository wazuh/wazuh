# Copyright (C) Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""Passwords: the rules, the Server API step (publish, then seed; masters only) and the indexer password step.

The three Wazuh programs are the stubs of conftest.
"""

import io
import os
import stat

import pytest

API = "WAZUH_MANAGER_API_PASSWORD"
WUI = "WAZUH_MANAGER_WUI_PASSWORD"
IDX = "WAZUH_INDEXER_MANAGER_PASSWORD"
GOOD_API = "Api.Passw0rd-123"
GOOD_WUI = "Wui.Passw0rd-456"
GOOD_IDX = "Idx.Passw0rd-789"
# framework/wazuh/security.py:49-52, the Server API's own rule.


@pytest.fixture
def calls(resolver, monkeypatch):
    """Every argv the resolver hands to run_wazuh, with what it sent on stdin."""
    recorded = []
    real = resolver.run_wazuh

    def spy(paths, argv, stdin=None, want_stdout=False):
        # Every mode reads the configuration first (wazuh-manager-conf dump), which takes nothing on stdin and
        # sets nothing up; only what comes after is recorded.
        if argv[-1] != "dump":
            recorded.append((list(argv), stdin))
        return real(paths, argv, stdin=stdin, want_stdout=want_stdout)
    monkeypatch.setattr(resolver, "run_wazuh", spy)
    return recorded


def run(resolver, sandbox, *argv, environ=None):
    out, err = io.StringIO(), io.StringIO()
    code = resolver.main(list(argv), paths=sandbox.paths, environ=environ or {}, out=out, err=err)
    return code, out.getvalue(), err.getvalue()


def published(sandbox):
    path = os.path.join(sandbox.conf, "export", "credentials.env")
    if not os.path.exists(path):
        return None
    lines = open(path).read().splitlines()
    return lines[0], dict(line.split("=", 1) for line in lines[1:])


def assert_no_secret(texts, *secrets_):
    joined = "".join(texts)
    for secret in secrets_:
        assert secret not in joined


# ---------------------------------------------------------------- rules

def test_generated_shape(resolver):
    """A generated password: 32 characters, the alphabet only, all four classes."""
    drawn = {resolver.generate_password() for _ in range(200)}
    assert len(drawn) == 200
    for value in drawn:
        assert len(value) == 32 and set(value) <= set(resolver.PASSWORD_ALPHABET)
        assert resolver.password_problem(value) is None


@pytest.mark.parametrize("value,rule", [
    ("Aa1.Aa1.Aa1", "12 to 64"), ("Aa1." * 16 + "A", "12 to 64"),
    ("aa1.aa1.aa1.", "uppercase"), ("AA1.AA1.AA1.", "lowercase"), ("Aaa.Aaa.Aaa.", "digit"), ("Aa1aAa1aAa1a", "one of"),
    ("Aa1.Aa1.Aa1 ", "may only use"), ("Aa1.Aa1.Aa1!", "may only use"), ("Aa1.Aa1.Aa1$", "may only use"),
    ("Aa1.Aa1.Aa1#", "may only use"), ("Aa1.Aa1.Aa1ñ", "may only use"),
])
def test_rule(resolver, value, rule):
    """A supplied password needs all four classes, the alphabet only, and a length within bounds."""
    problem = resolver.password_problem(value)
    assert problem is not None and rule in problem and value not in problem


@pytest.mark.parametrize("value", ["Aa1.Aa1.Aa1.", "Aa1." * 16, GOOD_API])
def test_rule_accepts(resolver, value):
    assert resolver.password_problem(value) is None


# ---------------------------------------------------------------- Server API passwords

def test_fresh_install(resolver, sandbox, calls):
    """Nothing supplied: both generated, published, and seeded with the same pair."""
    code, out, err = run(resolver, sandbox, "--install", environ={IDX: GOOD_IDX})
    assert code == 0 and err == ""
    header, values = published(sandbox)
    assert header == "# Published by wazuh-manager. Read by the dashboard on this host. Do not edit."
    assert set(values) == {API, WUI} and all(resolver.password_problem(v) is None for v in values.values())
    st = os.lstat(os.path.join(sandbox.conf, "export", "credentials.env"))
    assert stat.S_IMODE(st.st_mode) == 0o600 and (st.st_uid, st.st_gid) == (0, 0)
    export = os.lstat(os.path.join(sandbox.conf, "export"))
    assert stat.S_IMODE(export.st_mode) == 0o700 and (export.st_uid, export.st_gid) == (0, 0)
    assert sandbox.seed_calls() == [{"wazuh": values[API], "wazuh-internal-client": values[WUI]}]
    assert_no_secret([out, err], *values.values())


def test_supplied_beats_generated(resolver, sandbox):
    """A supplied value is seeded and published; the other is generated."""
    sandbox.write(os.path.join(sandbox.conf, "local.env"), f"{API}={GOOD_API}\n")
    run(resolver, sandbox, "--install", environ={IDX: GOOD_IDX})
    _, values = published(sandbox)
    assert values[API] == GOOD_API and values[WUI] != GOOD_API
    assert sandbox.seed_calls()[0]["wazuh"] == GOOD_API


def test_env_beats_local(resolver, sandbox):
    sandbox.write(os.path.join(sandbox.conf, "local.env"), f"{API}={GOOD_WUI}\n")
    run(resolver, sandbox, "--install", environ={API: GOOD_API, IDX: GOOD_IDX})
    assert sandbox.seed_calls()[0]["wazuh"] == GOOD_API


@pytest.mark.parametrize("bad", ["short.A1", "NoDigits.Here", "with space A1.a"])
def test_invalid_supplied_no_fallback(resolver, sandbox, bad):
    """An invalid supplied value: install exits 0 but seeds and publishes nothing; prestart refuses."""
    code, out, err = run(resolver, sandbox, "--install", environ={API: bad, IDX: GOOD_IDX})
    assert code == 0 and f"INVALID {API}: " in err and "(set in the environment)" in err
    assert published(sandbox) is None and sandbox.seed_calls() == []
    code, out2, err2 = run(resolver, sandbox, "--prestart", environ={API: bad, IDX: GOOD_IDX})
    assert code == 1 and f"INVALID {API}: " in err2
    assert_no_secret([out, err, out2, err2], bad)


@pytest.mark.parametrize("mode,expected", [("--install", 0), ("--upgrade", 0), ("--prestart", 1)])
@pytest.mark.parametrize("bad_line", [b"broken", b"OTHER='unclosed", b"OTHER=\xff", API.encode() + b"=Duplicate.Passw0rd-1"])
def test_malformed_local_env_does_not_initialize(resolver, sandbox, monkeypatch, calls, mode, expected, bad_line):
    """Reject the entire input, then seed the requested passwords once the operator repairs it."""
    sandbox.stage_ca()
    local = os.path.join(sandbox.conf, "local.env")
    requested = f"{API}={GOOD_API}\n{WUI}={GOOD_WUI}\n{IDX}={GOOD_IDX}\n".encode()
    sandbox.write(local, requested + bad_line + b"\n")
    sandbox.make_indexer_export(credentials=f"{IDX}=Other.Passw0rd-123\n")
    before = sandbox.tree_state()

    def forbidden():
        raise AssertionError("a rejected input must not generate alternative passwords")

    with monkeypatch.context() as patch:
        patch.setattr(resolver, "generate_password", forbidden)
        code, out, err = run(resolver, sandbox, mode)
    assert code == expected and f"INVALID {local}:4: " in err, err
    assert sandbox.tree_state() == before
    assert published(sandbox) is None and sandbox.seed_calls() == [] and sandbox.keystore() == {}
    assert calls == []
    assert_no_secret([out, err], GOOD_API, GOOD_WUI, GOOD_IDX)

    sandbox.write(local, requested)
    code, _, err = run(resolver, sandbox, "--install")
    assert code == 0 and err == "", err
    assert published(sandbox)[1] == {API: GOOD_API, WUI: GOOD_WUI}
    assert sandbox.seed_calls() == [{"wazuh": GOOD_API, "wazuh-internal-client": GOOD_WUI}]
    assert sandbox.keystore()["indexer/password"] == GOOD_IDX


@pytest.mark.parametrize("source", ["local", "indexer"])
def test_rejected_env_does_not_seed_from_other_sources(resolver, sandbox, source):
    """An explicit environment or an earlier publication must not bypass rejected input files."""
    sandbox.stage_ca()
    sandbox.control(rbac_fail_times=1)
    run(resolver, sandbox, "--install", environ={API: GOOD_API, WUI: GOOD_WUI, IDX: GOOD_IDX})
    if source == "local":
        sandbox.write(os.path.join(sandbox.conf, "local.env"), "broken\n")
    else:
        sandbox.make_indexer_export(credentials="broken\n")
    before, seeds = sandbox.tree_state(), sandbox.seed_calls()
    code, _, err = run(resolver, sandbox, "--install", environ={API: GOOD_API, WUI: GOOD_WUI, IDX: GOOD_IDX})
    assert code == 0 and "INVALID " in err
    assert sandbox.tree_state() == before and sandbox.seed_calls() == seeds


@pytest.mark.parametrize("text", [None, "", "# No overrides\n"])
def test_absent_or_empty_local_env_allows_generation(resolver, sandbox, text):
    if text is not None:
        sandbox.write(os.path.join(sandbox.conf, "local.env"), text)
    code, _, err = run(resolver, sandbox, "--install", environ={IDX: GOOD_IDX})
    assert code == 0 and err == "", err
    assert len(sandbox.seed_calls()) == 1
    assert all(resolver.password_problem(value) is None for value in published(sandbox)[1].values())


def test_seeded_untouched(resolver, sandbox, calls):
    """A re-run over a seeded database changes nothing."""
    run(resolver, sandbox, "--install", environ={IDX: GOOD_IDX})
    before = sandbox.tree_state()
    calls.clear()
    code, out, _ = run(resolver, sandbox, "--prestart", environ={API: GOOD_API, IDX: GOOD_IDX})
    assert code == 0 and "already seeded" in out
    assert sandbox.tree_state() == before
    assert not [argv for argv, _ in calls if "rbac_control.py" in " ".join(argv)]


def test_empty_rbac_db_is_unseeded(resolver, sandbox):
    os.makedirs(os.path.dirname(sandbox.rbac_db))
    sandbox.write(sandbox.rbac_db, b"")
    run(resolver, sandbox, "--install", environ={IDX: GOOD_IDX})
    assert len(sandbox.seed_calls()) == 1


@pytest.mark.parametrize("role,dump_exit,seeded,invalid", [
    ("worker", 0, False, False), ("master", 0, True, False), ("", 0, True, False), ("", 1, False, True),
])
def test_worker(resolver, sandbox, calls, role, dump_exit, seeded, invalid):
    """The role comes from the configuration read once per run: a master, or a node with no cluster section (the
    schema's default is master), seeds; a worker does not; an unreadable configuration fails closed."""
    sandbox.stage_ca()
    sandbox.control(role=role, dump_exit=dump_exit)
    code, out, err = run(resolver, sandbox, "--prestart", environ={IDX: GOOD_IDX})
    assert (len(sandbox.seed_calls()) == 1) is seeded
    assert (published(sandbox) is not None) is seeded
    assert ("cannot read the TLS paths" in err) is invalid
    assert code == (1 if invalid else 0)
    if role == "worker":
        assert "cluster worker" in out
    assert sandbox.conf_calls() == []                       # no second reading of the role


def test_worker_probe_missing_binary(resolver, sandbox):
    os.unlink(os.path.join(sandbox.home, "bin", "wazuh-manager-conf"))
    code, _, err = run(resolver, sandbox, "--prestart", environ={IDX: GOOD_IDX})
    assert code == 1 and "cannot read the TLS paths" in err and sandbox.seed_calls() == []


def test_seed_failure_then_recovery(resolver, sandbox):
    """Publication comes first, so a seed that fails is retried with the same values."""
    sandbox.stage_ca()
    sandbox.control(rbac_fail_times=1)
    code, out, err = run(resolver, sandbox, "--prestart", environ={IDX: GOOD_IDX})
    assert code == 1 and f"MISSING {sandbox.rbac_db}: the Server API database could not be created" in err
    assert "rbac_control: Internal error" in err
    _, first = published(sandbox)
    code, _, _ = run(resolver, sandbox, "--prestart", environ={IDX: GOOD_IDX})
    assert code == 0
    assert published(sandbox)[1] == first
    calls = sandbox.seed_calls()
    assert calls[0] == calls[1] == {"wazuh": first[API], "wazuh-internal-client": first[WUI]}
    assert_no_secret([out, err], *first.values())


def test_supplied_replaces_published(resolver, sandbox):
    sandbox.control(rbac_fail_times=1)
    run(resolver, sandbox, "--install", environ={IDX: GOOD_IDX})
    run(resolver, sandbox, "--prestart", environ={API: GOOD_API, IDX: GOOD_IDX})
    assert published(sandbox)[1][API] == GOOD_API and sandbox.seed_calls()[-1]["wazuh"] == GOOD_API


def test_rbac_control_missing(resolver, sandbox):
    os.unlink(os.path.join(sandbox.home, "framework", "scripts", "rbac_control.py"))
    code, _, err = run(resolver, sandbox, "--prestart", environ={IDX: GOOD_IDX})
    assert code == 1 and f"MISSING {sandbox.rbac_db}: " in err and "rbac_control.py is missing" in err


def test_export_planted(resolver, sandbox):
    """export/ planted by the service account before publication: refused, nothing written there."""
    export = os.path.join(sandbox.conf, "export")
    os.mkdir(export, 0o770)
    os.chown(export, sandbox.account_uid, sandbox.account_gid)
    code, _, err = run(resolver, sandbox, "--install", environ={IDX: GOOD_IDX})
    assert code == 0 and f"UNSAFE {export}: owned by uid" in err
    assert os.listdir(export) == [] and sandbox.seed_calls() == []


# ---------------------------------------------------------------- indexer password

@pytest.mark.parametrize("source", ["environment", "local.env", "indexer export"])
def test_indexer_password_stored(resolver, sandbox, source):
    """The indexer password supplied later lets the start pass and lands in the keystore."""
    sandbox.stage_ca()
    environ = {}
    if source == "environment":
        environ[IDX] = GOOD_IDX
    elif source == "local.env":
        sandbox.write(os.path.join(sandbox.conf, "local.env"), f"{IDX}={GOOD_IDX}\n")
    else:
        sandbox.make_indexer_export(credentials=f"{IDX}={GOOD_IDX}\n")
    code, out, err = run(resolver, sandbox, "--prestart", environ=environ)
    assert code == 0, err
    assert sandbox.keystore() == {"indexer/password": GOOD_IDX, "indexer/username": "wazuh-manager"}
    assert_no_secret([out, err], GOOD_IDX)


def test_indexer_password_missing(resolver, sandbox):
    """No indexer password anywhere: the start names what to do."""
    code, _, err = run(resolver, sandbox, "--prestart")
    assert code == 1
    assert (f"MISSING {IDX}: set it in {sandbox.conf}/local.env (copy it from the indexer's "
            f"{sandbox.indexer_export}/credentials.env), or install wazuh-indexer on this host first\n") in err
    assert run(resolver, sandbox, "--install")[0] == 0             # the package install never fails


def test_indexer_password_kept(resolver, sandbox, calls):
    """A stored indexer password beats a supplied one."""
    run(resolver, sandbox, "--prestart", environ={IDX: GOOD_IDX})
    run(resolver, sandbox, "--prestart", environ={IDX: "Other.Passw0rd-1"})
    assert sandbox.keystore()["indexer/password"] == GOOD_IDX


def test_username_backfill(resolver, sandbox):
    """A stored password with no username gets wazuh-manager as its username."""
    sandbox.stage_ca()
    import json
    with open(os.path.join(sandbox.keystore_dir, "keystore.json"), "w") as handle:
        json.dump({"indexer/password": GOOD_IDX}, handle)
    assert run(resolver, sandbox, "--prestart")[0] == 0
    assert sandbox.keystore() == {"indexer/password": GOOD_IDX, "indexer/username": "wazuh-manager"}


def test_keystore_refuses(resolver, sandbox):
    sandbox.control(keystore_fail=True)
    code, _, err = run(resolver, sandbox, "--prestart", environ={IDX: GOOD_IDX})
    assert code == 1 and f"MISSING {IDX}: the keystore did not accept" in err


# ---------------------------------------------------------------- --check and process hygiene

def test_check_validates_supplied(resolver, sandbox, calls):
    """--check validates supplied values without a subprocess but the configuration reader, even over a seeded
    database."""
    run(resolver, sandbox, "--install", environ={IDX: GOOD_IDX})
    calls.clear()
    sandbox.write(os.path.join(sandbox.conf, "local.env"), f"{WUI}=too.Short1\n")
    code, _, err = run(resolver, sandbox, "--check")
    assert code == 1 and err == f"INVALID {WUI}: must be 12 to 64 characters (set in {sandbox.conf}/local.env:1)\n"
    assert calls == []


@pytest.mark.parametrize("mode", ["--install", "--upgrade", "--prestart", "--check"])
def test_only_wazuh_programs(resolver, sandbox, calls, mode):
    sandbox.write(os.path.join(sandbox.conf, "local.env"), f"{API}={GOOD_API}\n{IDX}={GOOD_IDX}\n")
    run(resolver, sandbox, mode)
    allowed = {sandbox.paths.keystore_bin, sandbox.paths.conf_bin, sandbox.paths.python_bin}
    for argv, stdin in calls:
        assert argv[0] in allowed
        assert all(secret not in arg for arg in argv for secret in (GOOD_API, GOOD_IDX))
        if argv[0] == sandbox.paths.python_bin:
            assert argv[1:] == ["-I", sandbox.paths.rbac_control_script, "seed", "--passwords-file", "-"]
            assert GOOD_API.encode() in stdin


# ---------------------------------------------------------------- the publication, judged once

@pytest.mark.parametrize("seeded", [False, True])
def test_malformed_publication_follows_the_seed(resolver, sandbox, seeded):
    """A malformed export/credentials.env is published again while rbac.db is not seeded, so --check lets the start
    go on; once seeded its passwords cannot be recovered and both --check and --prestart refuse it."""
    sandbox.stage_ca()
    export = os.path.join(sandbox.conf, "export")
    os.mkdir(export)
    os.chmod(export, 0o700)
    path = sandbox.write(os.path.join(export, "credentials.env"), "# header\nnot a pair\n", mode=0o600)
    if seeded:
        os.makedirs(os.path.dirname(sandbox.rbac_db), exist_ok=True)
        sandbox.write(sandbox.rbac_db, "seeded")
    code, _, err = run(resolver, sandbox, "--check", environ={IDX: GOOD_IDX})
    if seeded:
        assert code == 1 and f"INVALID {path}:2: not a NAME=value line" in err, err
    else:
        assert code == 0, err
        assert f"WARNING: ignoring {path} (line 2 is not NAME=value); it will be published again" in err
    code, _, err = run(resolver, sandbox, "--prestart", environ={IDX: GOOD_IDX})
    if seeded:
        assert code == 1 and f"INVALID {path}:2: not a NAME=value line" in err, err
    else:
        assert code == 0, err
        assert published(sandbox) is not None and len(sandbox.seed_calls()) == 1

