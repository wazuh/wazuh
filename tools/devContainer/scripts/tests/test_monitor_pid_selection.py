# Copyright (C) Wazuh Inc.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""The monitor attaches to THIS host's manager, never to a container's daemon of the same name.

With the e2e cluster pods up, every manager daemon (and the indexer) runs several times, each with
the same /var/wazuh-manager/bin/... path as its exe; the old "newest wins" rule often picked a pod's
process (an RSS of 11.5 GB for one A/B run). The fakes below play psutil.process_iter.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), ".."))
monitor = pytest.importorskip("monitor")

HOST_NS, POD_NS = "mnt:[1]", "mnt:[2]"


class FakeProc:
    def __init__(self, pid, exe, created, ns, cmdline=None):
        self.pid = pid
        self.info = {"pid": pid, "exe": exe, "cmdline": cmdline or [exe]}
        self._created = created
        self.ns = ns

    def create_time(self):
        return self._created


@pytest.fixture
def procs(monkeypatch):
    table = []
    namespaces = {}

    def mount_ns(pid):
        if pid == "self":
            return HOST_NS
        return namespaces.get(pid)

    def add(*args, **kwargs):
        p = FakeProc(*args, **kwargs)
        table.append(p)
        namespaces[p.pid] = p.ns
        return p

    monkeypatch.setattr(monitor.psutil, "process_iter", lambda attrs=None: list(table))
    monkeypatch.setattr(monitor, "_mount_ns", mount_ns)
    return add


def target(home, daemon="wazuh-manager-modulesd"):
    return monitor.process_target_from_exe(f"{home}/bin/{daemon}")


def test_an_impostor_in_a_container_is_never_chosen(procs, tmp_path):
    exe = f"{tmp_path}/bin/wazuh-manager-modulesd"
    host = procs(100, exe, created=1000.0, ns=HOST_NS)
    procs(200, exe, created=5000.0, ns=POD_NS)          # newer: the old rule took it
    assert monitor.find_process_by_target(target(tmp_path)) is host


def test_only_impostors_means_not_found(procs, tmp_path):
    procs(200, f"{tmp_path}/bin/wazuh-manager-modulesd", created=5000.0, ns=POD_NS)
    assert monitor.find_process_by_target(target(tmp_path)) is None


def test_the_pidfile_wins_over_a_newer_process_of_the_same_host(procs, tmp_path):
    exe = f"{tmp_path}/bin/wazuh-manager-analysisd"
    run = tmp_path / "var" / "run"
    run.mkdir(parents=True)
    (run / "wazuh-manager-analysisd-100.pid").write_text("100\n")
    (run / "wazuh-manager-analysisd_helper-300.pid").write_text("300\n")   # another daemon's pidfile
    daemon = procs(100, exe, created=1000.0, ns=HOST_NS)
    procs(300, exe, created=9000.0, ns=HOST_NS)        # e.g. a leftover the pidfile does not name
    assert monitor.find_process_by_target(target(tmp_path, "wazuh-manager-analysisd")) is daemon


def test_without_a_pidfile_the_newest_host_process_still_wins(procs, tmp_path):
    exe = f"{tmp_path}/bin/wazuh-manager-db"
    procs(100, exe, created=1000.0, ns=HOST_NS)
    newest = procs(150, exe, created=2000.0, ns=HOST_NS)
    assert monitor.find_process_by_target(target(tmp_path, "wazuh-manager-db")) is newest


def test_the_python_daemons_use_their_own_pidfile(procs, tmp_path):
    script = f"{tmp_path}/api/scripts/wazuh_manager_apid.py"
    py = f"{tmp_path}/framework/python/bin/python3"
    run = tmp_path / "var" / "run"
    run.mkdir(parents=True)
    (run / "wazuh-manager-apid-120.pid").write_text("120\n")
    (run / "wazuh-manager-apid_auth-121.pid").write_text("121\n")
    procs(110, py, created=1000.0, ns=POD_NS, cmdline=[py, script])       # a pod's apid
    main = procs(120, py, created=900.0, ns=HOST_NS, cmdline=[py, script])
    procs(121, py, created=900.0, ns=HOST_NS, cmdline=[py, script])       # its auth worker
    t = monitor.process_target_from_exe(script)
    assert t.pidfile_glob == f"{tmp_path}/var/run/wazuh-manager-apid-[0-9]*.pid"
    assert monitor.find_process_by_target(t) is main


def test_pidfile_globs_of_the_default_targets():
    globs = {e: monitor.manager_pidfile_glob(e) for e in monitor.DEFAULT_EXECUTABLES}
    assert globs["/var/wazuh-manager/bin/wazuh-manager-remoted"] == \
        "/var/wazuh-manager/var/run/wazuh-manager-remoted-[0-9]*.pid"
    assert globs["/var/wazuh-manager/framework/scripts/wazuh_manager_clusterd.py"] == \
        "/var/wazuh-manager/var/run/wazuh-manager-clusterd-[0-9]*.pid"
    assert all(globs.values())
    assert monitor.manager_pidfile_glob(monitor.INDEXER_EXECUTABLE) is None


def test_an_unreadable_namespace_counts_as_ours(procs, tmp_path):
    exe = f"{tmp_path}/bin/wazuh-manager-remoted"
    p = procs(100, exe, created=1000.0, ns=None)
    assert monitor.find_process_by_target(target(tmp_path, "wazuh-manager-remoted")) is p
