# Copyright (C) Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""The files the daemons are configured to serve are the files checked: remoted's and authd's pairs and the agents'
bundle from wazuh-manager.conf, the Server API's pair from api.yaml. Both files are writable by the service account,
so a configured name is followed only directly inside <CONF>/certs."""

import io
import os
import shutil

import pytest

IDX = {"WAZUH_INDEXER_MANAGER_PASSWORD": "Idx.Passw0rd-789"}
ISSUED = "remoted.pem, remoted-key.pem, apid.pem, apid-key.pem"


def run(resolver, sandbox, *argv):
    out, err = io.StringIO(), io.StringIO()
    code = resolver.main(list(argv), paths=sandbox.paths, environ=dict(IDX), out=out, err=err)
    return code, out.getvalue(), err.getvalue()


def certs(sandbox, name):
    return os.path.join(sandbox.certs, name)


def conf_file(sandbox):
    return os.path.join(sandbox.conf, "wazuh-manager.conf")


def api_file(sandbox):
    return os.path.join(sandbox.home, "api", "configuration", "api.yaml")


def rename_pair(sandbox, old, new):
    os.rename(certs(sandbox, f"{old}.pem"), certs(sandbox, f"{new}.pem"))
    os.rename(certs(sandbox, f"{old}-key.pem"), certs(sandbox, f"{new}-key.pem"))


def listener_conf(sandbox, name, auth=True):
    """remote.https (and authd, unless `auth` is False) pointed at certs/<name>.pem and its key."""
    dump = {"remote.https.certificate": certs(sandbox, f"{name}.pem"),
            "remote.https.key": certs(sandbox, f"{name}-key.pem")}
    if auth:
        dump.update({"auth.ssl_manager_cert": certs(sandbox, f"{name}.pem"),
                     "auth.ssl_manager_key": certs(sandbox, f"{name}-key.pem")})
    return dump


# ---------------------------------------------------------------- pairs under configured names

def test_api_pair_under_configured_names(resolver, sandbox):
    """The Server API's pair renamed and api.yaml pointed at it: the start goes on, and nothing is issued under the
    default name the configuration no longer uses."""
    sandbox.stage_ca()
    rename_pair(sandbox, "apid", "custom")
    sandbox.api_yaml("https:\n  cert: custom.pem\n  key: custom-key.pem\n")
    assert run(resolver, sandbox, "--check")[0::2] == (0, "")
    code, out, err = run(resolver, sandbox, "--prestart")
    assert (code, err) == (0, "") and f"{certs(sandbox, 'custom.pem')}: kept" in out
    assert run(resolver, sandbox, "--install")[0::2] == (0, "")
    assert not os.path.exists(certs(sandbox, "apid.pem"))


def test_listener_pair_under_configured_names(resolver, sandbox):
    """remoted's listener on its own pair, authd still on the default one: the default pair is issued for authd, the
    configured one is checked against the agents' bundle."""
    sandbox.stage_ca()
    rename_pair(sandbox, "remoted", "listener")
    sandbox.control(conf_dump=listener_conf(sandbox, "listener", auth=False))
    code, _, err = run(resolver, sandbox, "--prestart")
    assert code == 1 and err == (f"MISSING {certs(sandbox, 'remoted.pem')}: run --install to issue it, or stage the "
                                 f"pair\n")
    code, out, err = run(resolver, sandbox, "--install")
    assert (code, err) == (0, "") and f"{certs(sandbox, 'remoted.pem')}: issued" in out
    assert f"{certs(sandbox, 'listener.pem')}: kept" in out
    assert run(resolver, sandbox, "--prestart")[0::2] == (0, "")


def test_broken_configured_pair_is_named(resolver, sandbox):
    sandbox.stage_ca()
    rename_pair(sandbox, "remoted", "listener")
    shutil.copyfile(certs(sandbox, "apid-key.pem"), certs(sandbox, "listener-key.pem"))
    sandbox.control(conf_dump=listener_conf(sandbox, "listener"))
    for mode in ("--check", "--prestart"):
        code, _, err = run(resolver, sandbox, mode)
        assert code == 1 and err.startswith(f"INVALID {certs(sandbox, 'listener.pem')}: "), err
        assert err.count("\n") == 1


def test_configured_pair_absent(resolver, sandbox):
    """A pair the resolver does not issue: MISSING with what to do at --prestart, nothing at --check, nothing issued
    at --install."""
    sandbox.stage_ca()
    sandbox.api_yaml("https:\n  cert: custom.pem\n  key: custom-key.pem\n")
    expected = (f"MISSING {certs(sandbox, 'custom.pem')}: configured as https.cert in {api_file(sandbox)}; stage the "
                f"pair (the resolver issues only {ISSUED})\n")
    assert run(resolver, sandbox, "--prestart")[0::2] == (1, expected)
    assert run(resolver, sandbox, "--check")[0::2] == (0, "")
    assert run(resolver, sandbox, "--install")[0] == 0
    assert not os.path.exists(certs(sandbox, "custom.pem"))


def test_configured_key_mode_is_checked(resolver, sandbox):
    sandbox.stage_ca()
    rename_pair(sandbox, "apid", "custom")
    os.chmod(certs(sandbox, "custom-key.pem"), 0o660)
    sandbox.api_yaml("https:\n  cert: custom.pem\n  key: custom-key.pem\n")
    code, _, err = run(resolver, sandbox, "--check")
    assert code == 1 and err == f"UNSAFE {certs(sandbox, 'custom-key.pem')}: mode is 0660, not 0640\n"


@pytest.mark.parametrize("listener", ["api", "authd"])
@pytest.mark.parametrize("files", ["absent", "broken"])
def test_turned_off_listener_is_not_checked(resolver, sandbox, listener, files):
    sandbox.stage_ca()
    if files == "broken":
        sandbox.write(certs(sandbox, "off.pem"), b"not a certificate\n", mode=0o640, gid=sandbox.account_gid)
        sandbox.write(certs(sandbox, "off-key.pem"), b"not a key\n", mode=0o640, gid=sandbox.account_gid)

    def configure(on):
        if listener == "api":
            sandbox.api_yaml(f"https:\n  enabled: {'true' if on else 'false'}\n  cert: off.pem\n  key: off-key.pem\n")
        else:
            sandbox.control(conf_dump={"auth.disabled": not on, "auth.ssl_manager_cert": certs(sandbox, "off.pem"),
                                       "auth.ssl_manager_key": certs(sandbox, "off-key.pem")})

    configure(on=False)
    for mode in ("--check", "--prestart"):
        assert run(resolver, sandbox, mode)[0::2] == (0, ""), mode
    configure(on=True)                                   # the same pair, its listener on: judged
    code, _, err = run(resolver, sandbox, "--prestart")
    assert code == 1 and certs(sandbox, "off") in err


# ---------------------------------------------------------------- names outside certs/

def _outside_cases(sandbox):
    planted = sandbox.path("outside.pem")
    return {
        "absolute elsewhere": ("conf", "remote.https.certificate", planted, planted),
        "relative to the home": ("conf", "remote.https.certificate", "etc/outside.pem",
                                 os.path.join(sandbox.home, "etc", "outside.pem")),
        "directly in conf": ("conf", "auth.ssl_manager_cert", os.path.join(sandbox.conf, "outside.pem"),
                             os.path.join(sandbox.conf, "outside.pem")),
        "dot-dot through certs": ("conf", "remote.https.certificate", certs(sandbox, "../outside.pem"),
                                  certs(sandbox, "../outside.pem")),
        "below certs": ("conf", "remote.https.ca_certificate", certs(sandbox, "sub/outside.pem"),
                        certs(sandbox, "sub/outside.pem")),
        "api dot-dot": ("api", "https.cert", "../outside.pem", certs(sandbox, "../outside.pem")),
        "api absolute": ("api", "https.key", planted, planted),
        "indexer pair": ("conf", "indexer.ssl.certificate", planted, planted),
        "indexer ca list": ("conf", "indexer.ssl.certificate_authorities", [planted], planted),
    }


@pytest.mark.parametrize("case", ["absolute elsewhere", "relative to the home", "directly in conf",
                                  "dot-dot through certs", "below certs", "api dot-dot", "api absolute",
                                  "indexer pair", "indexer ca list"])
@pytest.mark.parametrize("mode", ["--check", "--prestart"])
def test_name_outside_certs_is_refused_unread(resolver, sandbox, monkeypatch, case, mode):
    """The account can edit both configuration files: a name outside <CONF>/certs is refused and never opened."""
    sandbox.stage_ca()
    source, key, value, path = _outside_cases(sandbox)[case]
    for planted in (sandbox.path("outside.pem"), os.path.join(sandbox.conf, "outside.pem")):
        shutil.copyfile(certs(sandbox, "apid.pem"), planted)
    if source == "conf":
        sandbox.control(conf_dump={key: value})
    else:
        sandbox.api_yaml(f"https:\n  {key.split('.')[1]}: {value}\n")
    opened = []
    real = resolver.read_file

    def spy(parent, name, *args, **kwargs):
        opened.append(os.path.normpath(parent.child(name)))
        return real(parent, name, *args, **kwargs)

    monkeypatch.setattr(resolver, "read_file", spy)
    code, _, err = run(resolver, sandbox, mode)
    where = conf_file(sandbox) if source == "conf" else api_file(sandbox)
    assert code == 1
    assert (f"INVALID {key}: {path} is outside {sandbox.certs}, the only place the resolver checks (set in "
            f"{where})\n") in err
    assert os.path.normpath(path) not in opened


# ---------------------------------------------------------------- the agents' bundle

def test_configured_bundle(resolver, sandbox):
    sandbox.stage_ca()
    os.rename(certs(sandbox, "root-ca.pem"), certs(sandbox, "agents-ca.pem"))
    sandbox.control(conf_dump={"remote.https.ca_certificate": certs(sandbox, "agents-ca.pem")})
    assert run(resolver, sandbox, "--check")[0::2] == (0, "")
    assert run(resolver, sandbox, "--install")[0::2] == (0, "")
    assert not os.path.exists(certs(sandbox, "root-ca.pem"))
    assert run(resolver, sandbox, "--prestart")[0::2] == (0, "")
    os.unlink(certs(sandbox, "agents-ca.pem"))
    assert run(resolver, sandbox, "--install")[0] == 0
    assert not os.path.exists(certs(sandbox, "agents-ca.pem")) and not os.path.exists(certs(sandbox, "root-ca.pem"))
    code, _, err = run(resolver, sandbox, "--prestart")
    assert code == 1 and (f"MISSING {certs(sandbox, 'agents-ca.pem')}: configured as remote.https.ca_certificate in "
                          f"{conf_file(sandbox)}; stage the agents' CA bundle there\n") in err


def test_configured_bundle_must_hold_the_ca(resolver, sandbox):
    sandbox.stage_ca()
    with open(certs(sandbox, "apid.pem"), "rb") as leaf:
        sandbox.write(certs(sandbox, "agents-ca.pem"), leaf.read().split(b"-----END CERTIFICATE-----")[0] +
                      b"-----END CERTIFICATE-----\n", mode=0o640, gid=sandbox.account_gid)
    sandbox.control(conf_dump={"remote.https.ca_certificate": certs(sandbox, "agents-ca.pem")})
    code, _, err = run(resolver, sandbox, "--check")
    assert code == 1 and f"INVALID {certs(sandbox, 'agents-ca.pem')}: does not contain " in err


def test_no_ca_minted_beside_a_configured_pair(resolver, sandbox):
    sandbox.write(certs(sandbox, "listener.pem"), b"staged\n", mode=0o640, gid=sandbox.account_gid)
    sandbox.control(conf_dump=listener_conf(sandbox, "listener"))
    code, _, err = run(resolver, sandbox, "--install")
    assert code == 0 and f"MISSING {sandbox.conf}/ca/root-ca.pem: stage the CA that issued the pairs" in err
    assert not os.path.exists(os.path.join(sandbox.conf, "ca", "root-ca.pem"))


# ---------------------------------------------------------------- reading the configuration

@pytest.mark.parametrize("mode", ["--check", "--prestart", "--install"])
def test_configuration_read_once_per_run(resolver, sandbox, monkeypatch, mode):
    sandbox.stage_ca()
    calls = []
    real = resolver.run_wazuh

    def spy(paths, argv, stdin=None, want_stdout=False):
        calls.append(list(argv))
        return real(paths, argv, stdin=stdin, want_stdout=want_stdout)

    monkeypatch.setattr(resolver, "run_wazuh", spy)
    run(resolver, sandbox, mode)
    dumps = [argv for argv in calls if argv[-1] == "dump"]
    assert dumps == [[sandbox.paths.conf_bin, "-H", sandbox.home, "-f", conf_file(sandbox), "--skip-file-checks",
                      "dump"]]


@pytest.mark.parametrize("control,reason", [
    ({"dump_exit": 1}, "wazuh-manager-conf exited with 1"),
    ({"dump_raw": "<ossec_config/>"}, "its output is not a JSON object"),
    ({"dump_raw": "[1, 2]"}, "its output is not a JSON object"),
    ({"dump_raw": "{" + " " * (1024 * 1024) + "}"}, "its output is larger than 1048576 bytes"),
])
def test_unreadable_configuration(resolver, sandbox, control, reason):
    """The default names are used, and the start is refused: what the daemons serve is unknown."""
    sandbox.stage_ca()
    sandbox.control(**control)
    expected = (f"INVALID {conf_file(sandbox)}: cannot read the TLS paths ({reason}); run wazuh-manager-conf "
                f"validate\n")
    assert run(resolver, sandbox, "--check")[0::2] == (1, expected)


@pytest.mark.parametrize("mode", ["--check", "--prestart"])
def test_configuration_reader_that_hangs(resolver, sandbox, monkeypatch, mode):
    """A reader that does not answer in time is killed and reported like one that failed: an INVALID verdict about
    the configuration, the default names used, not an internal error."""
    sandbox.stage_ca()
    monkeypatch.setattr(resolver, "SUBPROCESS_TIMEOUT", 1)
    sandbox.control(dump_sleep=30)
    code, _, err = run(resolver, sandbox, mode)
    assert code == 1, err
    assert (f"INVALID {conf_file(sandbox)}: cannot read the TLS paths (wazuh-manager-conf did not answer within 1 "
            f"seconds); run wazuh-manager-conf validate\n") in err, err
    assert "internal error" not in err and "Traceback" not in err, err


def test_configuration_reader_missing(resolver, sandbox):
    sandbox.stage_ca()
    os.unlink(sandbox.paths.conf_bin)
    code, _, err = run(resolver, sandbox, "--check")
    assert code == 1 and err == (f"INVALID {conf_file(sandbox)}: cannot read the TLS paths ({sandbox.paths.conf_bin} "
                                 f"is missing); run wazuh-manager-conf validate\n")


@pytest.mark.parametrize("text,expected", [
    (None, None),
    ("", None),
    ("logs:\n  level: info\n", None),
    ("https: [\n", "INVALID {api}: not valid YAML (line 2)"),
    ("- https\n", "INVALID {api}: not a mapping of options"),
    ("https: on\n", "INVALID {api}: https: not a mapping of options"),
    ("https:\n  cert: 5\n", "INVALID {api}: https.cert: not a file name"),
    ("https:\n  enabled: 'no'\n", "INVALID {api}: https.enabled: not true or false"),
])
def test_api_yaml(resolver, sandbox, text, expected):
    """An absent file or an absent option means the Server API's defaults; anything unreadable is refused (and the
    defaults are checked)."""
    sandbox.stage_ca()
    if text is not None:
        sandbox.api_yaml(text)
    code, _, err = run(resolver, sandbox, "--check")
    assert (code, err) == ((0, "") if expected is None else (1, expected.format(api=api_file(sandbox)) + "\n"))


def test_api_yaml_symlink_is_unsafe(resolver, sandbox):
    sandbox.stage_ca()
    sandbox.api_yaml("https:\n  cert: apid.pem\n")
    target = sandbox.plant(sandbox.path("elsewhere.yaml"), b"https:\n  cert: other.pem\n")
    os.unlink(api_file(sandbox))
    os.symlink(target, api_file(sandbox))
    code, _, err = run(resolver, sandbox, "--check")
    assert code == 1 and err == f"UNSAFE {api_file(sandbox)}: a symbolic link\n"


# ---------------------------------------------------------------- the indexer connection (indexer.ssl.*)

def export_files(sandbox):
    """What the indexer's export holds now: its CA and the client pair it issued."""
    names = {"ca": "ca.pem", "client": "manager-client.pem", "key": "manager-client-key.pem"}
    return {role: open(os.path.join(sandbox.indexer_export, name), "rb").read() for role, name in names.items()}


def stage(sandbox, name, data):
    sandbox.write(certs(sandbox, name), data, mode=0o640, gid=sandbox.account_gid)


def indexer_conf(sandbox, cas=None, pair=None):
    """indexer.ssl.* with CA file names and a (certificate, key) pair of names in certs/; None keeps the default."""
    dump = {}
    if cas is not None:
        dump["indexer.ssl.certificate_authorities"] = [certs(sandbox, name) for name in cas]
    if pair is not None:
        dump["indexer.ssl.certificate"] = certs(sandbox, pair[0]) if pair[0] else ""
        dump["indexer.ssl.key"] = certs(sandbox, pair[1]) if pair[1] else ""
    return dump


def test_indexer_ca_under_configured_name(resolver, sandbox):
    """The CA list names the operator's own file: it is checked, the pair is still imported, and indexer-ca.pem is
    never written."""
    stage(sandbox, "my-indexer-ca.pem", export_files(sandbox)["ca"])
    sandbox.control(conf_dump=indexer_conf(sandbox, cas=["my-indexer-ca.pem"]))
    code, out, err = run(resolver, sandbox, "--install")
    assert (code, err) == (0, "") and f"{certs(sandbox, 'indexer-connector.pem')}: imported" in out
    assert not os.path.exists(certs(sandbox, "indexer-ca.pem"))
    assert run(resolver, sandbox, "--prestart")[0::2] == (0, "")
    assert run(resolver, sandbox, "--check")[0::2] == (0, "")


def test_indexer_pair_under_configured_names(resolver, sandbox):
    files = export_files(sandbox)
    stage(sandbox, "my-client.pem", files["client"])
    stage(sandbox, "my-client-key.pem", files["key"])
    sandbox.control(conf_dump=indexer_conf(sandbox, pair=("my-client.pem", "my-client-key.pem")))
    code, out, err = run(resolver, sandbox, "--install")
    assert (code, err) == (0, "") and f"{certs(sandbox, 'indexer-ca.pem')}: imported" in out
    assert f"{certs(sandbox, 'my-client.pem')}: staged; kept as it is" in out
    assert not os.path.exists(certs(sandbox, "indexer-connector.pem"))
    assert run(resolver, sandbox, "--prestart")[0::2] == (0, "")


def test_configured_indexer_pair_absent(resolver, sandbox):
    sandbox.control(conf_dump=indexer_conf(sandbox, pair=("my-client.pem", "my-client-key.pem")))
    expected = (f"MISSING {certs(sandbox, 'my-client.pem')}: configured as indexer.ssl.certificate in "
                f"{conf_file(sandbox)}; stage a pair issued by the indexer's CA for this node (the resolver imports "
                f"only indexer-connector.pem and indexer-connector-key.pem)\n")
    assert run(resolver, sandbox, "--check")[0::2] == (0, "")
    code, _, err = run(resolver, sandbox, "--prestart")
    assert code == 1 and expected in err


def test_configured_indexer_pair_from_another_ca(resolver, sandbox):
    old = export_files(sandbox)
    sandbox.make_indexer_trust()                          # the indexer's CA is now another one
    stage(sandbox, "my-client.pem", old["client"])
    stage(sandbox, "my-client-key.pem", old["key"])
    sandbox.control(conf_dump=indexer_conf(sandbox, pair=("my-client.pem", "my-client-key.pem")))
    for mode in ("--check", "--prestart"):
        code, _, err = run(resolver, sandbox, mode)
        assert code == 1 and f"INVALID {certs(sandbox, 'my-client.pem')}: not issued by " in err, (mode, err)


def test_indexer_trust_is_the_union_of_the_listed_files(resolver, sandbox):
    """The connector merges every listed CA file: a pair issued by any of them is accepted."""
    other = export_files(sandbox)
    stage(sandbox, "other-ca.pem", other["ca"])
    stage(sandbox, "my-client.pem", other["client"])
    stage(sandbox, "my-client-key.pem", other["key"])
    current = sandbox.make_indexer_trust()               # the export now holds a CA that did not issue my-client
    pair = ("my-client.pem", "my-client-key.pem")
    sandbox.control(conf_dump=indexer_conf(sandbox, cas=["indexer-ca.pem"], pair=pair))
    code, _, err = run(resolver, sandbox, "--prestart")
    assert code == 1 and f"INVALID {certs(sandbox, 'my-client.pem')}: not issued by " in err
    sandbox.control(conf_dump=indexer_conf(sandbox, cas=["indexer-ca.pem", "other-ca.pem"], pair=pair))
    assert run(resolver, sandbox, "--install")[0::2] == (0, "")
    assert open(certs(sandbox, "indexer-ca.pem"), "rb").read() == current["ca"]
    assert run(resolver, sandbox, "--prestart")[0::2] == (0, "")


def test_extra_indexer_ca_absent_or_invalid(resolver, sandbox):
    sandbox.control(conf_dump=indexer_conf(sandbox, cas=["indexer-ca.pem", "other-ca.pem"]))
    assert run(resolver, sandbox, "--check")[0::2] == (0, "")
    code, _, err = run(resolver, sandbox, "--prestart")
    assert code == 1 and (f"MISSING {certs(sandbox, 'other-ca.pem')}: configured in "
                          f"indexer.ssl.certificate_authorities in {conf_file(sandbox)}; stage the indexer's CA "
                          f"there\n") in err
    stage(sandbox, "other-ca.pem", export_files(sandbox)["client"].split(b"-----END CERTIFICATE-----")[0] +
          b"-----END CERTIFICATE-----\n")
    for mode in ("--check", "--prestart"):
        code, _, err = run(resolver, sandbox, mode)
        assert code == 1 and f"INVALID {certs(sandbox, 'other-ca.pem')}: not a CA certificate" in err, mode


@pytest.mark.parametrize("eku,accepted", [("client", True), ("server", False)])
def test_empty_indexer_ca_list(resolver, sandbox, eku, accepted):
    """No CA listed: the connector trusts the system store, so no CA file is wanted and the pair gets the leaf checks
    only."""
    sandbox.make_indexer_trust(eku=eku)
    sandbox.control(conf_dump=indexer_conf(sandbox, cas=[]))
    code, out, err = run(resolver, sandbox, "--install")
    assert not os.path.exists(certs(sandbox, "indexer-ca.pem")) and "indexer-ca.pem" not in err
    code, _, err = run(resolver, sandbox, "--prestart")
    if accepted:
        assert (code, err) == (0, "") and os.path.exists(certs(sandbox, "indexer-connector.pem"))
    else:
        assert code == 1 and (f"INVALID {sandbox.indexer_export}/manager-client.pem: has no extendedKeyUsage with "
                              f"clientAuth") in err


def test_no_indexer_client_pair(resolver, sandbox):
    for name in ("manager-client.pem", "manager-client-key.pem"):
        os.unlink(os.path.join(sandbox.indexer_export, name))
    sandbox.control(conf_dump=indexer_conf(sandbox, pair=("", "")))
    code, out, err = run(resolver, sandbox, "--install")
    assert (code, err) == (0, "") and f"{certs(sandbox, 'indexer-ca.pem')}: imported" in out
    assert not os.path.exists(certs(sandbox, "indexer-connector.pem"))
    assert run(resolver, sandbox, "--prestart")[0::2] == (0, "")


@pytest.mark.parametrize("pair,empty,other", [(("my-client.pem", ""), "key", "certificate"),
                                              (("", "my-client-key.pem"), "certificate", "key")])
def test_indexer_certificate_and_key_together(resolver, sandbox, pair, empty, other):
    sandbox.control(conf_dump=indexer_conf(sandbox, pair=pair))
    expected = (f"INVALID indexer.ssl.{empty}: must be set together with indexer.ssl.{other} (set in "
                f"{conf_file(sandbox)})\n")
    for mode in ("--check", "--prestart"):
        code, _, err = run(resolver, sandbox, mode)
        assert code == 1 and expected in err, mode


def test_new_export_ca_does_not_issue_the_configured_pair(resolver, sandbox):
    """A working connector under configured names is never broken by an import."""
    files = export_files(sandbox)
    stage(sandbox, "my-client.pem", files["client"])
    stage(sandbox, "my-client-key.pem", files["key"])
    sandbox.control(conf_dump=indexer_conf(sandbox, pair=("my-client.pem", "my-client-key.pem")))
    assert run(resolver, sandbox, "--install")[0::2] == (0, "")
    before = sandbox.tree_state()
    sandbox.make_indexer_trust()
    expected = (f"INVALID {sandbox.indexer_export}/ca.pem: does not issue the staged "
                f"{certs(sandbox, 'my-client.pem')}; nothing was imported\n")
    for mode in ("--check", "--prestart"):
        code, _, err = run(resolver, sandbox, mode)
        assert code == 1 and expected in err, (mode, err)
    after = sandbox.tree_state()
    assert {k: v for k, v in after.items() if k.startswith("conf/")} == \
        {k: v for k, v in before.items() if k.startswith("conf/")}


def test_clear_keeps_configured_indexer_files(resolver, sandbox):
    files = export_files(sandbox)
    stage(sandbox, "my-indexer-ca.pem", files["ca"])
    stage(sandbox, "my-client.pem", files["client"])
    stage(sandbox, "my-client-key.pem", files["key"])
    sandbox.control(conf_dump=indexer_conf(sandbox, cas=["my-indexer-ca.pem"],
                                           pair=("my-client.pem", "my-client-key.pem")))
    assert run(resolver, sandbox, "--install")[0::2] == (0, "")
    assert run(resolver, sandbox, "--clear")[0] == 0
    for name in ("my-indexer-ca.pem", "my-client.pem", "my-client-key.pem"):
        assert os.path.exists(certs(sandbox, name)), name
