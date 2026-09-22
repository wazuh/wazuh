#!/usr/bin/env python3
# Copyright (C) 2015, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

"""Tests for wazuh-migrate-identity.py.

`export` is exercised against a 4.x installation tree built in a temporary directory. `import` and
`check` are exercised against a stub of the manager's API that implements the endpoints the tool
uses and records what it was asked to do, so the assertions are about the calls the tool makes
rather than about files it no longer writes.

    python3 tools/migration/test_wazuh_migrate_identity.py
"""

import http.server
import importlib.util
import json
import os
import sqlite3
import ssl
import subprocess
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))

_spec = importlib.util.spec_from_file_location(
    "wazuh_migrate_identity", os.path.join(HERE, "wazuh-migrate-identity.py"))
tool = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tool)


# The 4.x agent table as 4.14 defines it, reduced to what the exporter reads.
SOURCE_SCHEMA = """
CREATE TABLE agent (id INTEGER PRIMARY KEY, name TEXT, ip TEXT, register_ip TEXT,
                    internal_key TEXT, os_platform TEXT, date_add INTEGER NOT NULL,
                    'group' TEXT, connection_status TEXT NOT NULL DEFAULT 'never_connected');
CREATE TABLE 'group' (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE);
CREATE TABLE belongs (id_agent INTEGER, id_group INTEGER, priority INTEGER NOT NULL DEFAULT 0,
                      PRIMARY KEY (id_agent, id_group));
CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT);
INSERT INTO metadata (key, value) VALUES ('db_version', '7');
"""

AGENTS = [
    # id, name, groups in priority order
    (1, "web-ubuntu24", ["linux-servers", "pci-scope"]),
    (2, "win11-lab", ["default", "pci-scope"]),
    (3, "db-al2023", ["db-servers", "pci-scope"]),
]
GROUPS = ["default", "linux-servers", "db-servers", "pci-scope"]
CUSTOM_GROUPS = [g for g in GROUPS if g != "default"]


def build_source(root):
    """A 4.x installation holding three agents in four groups."""
    for relative in ["queue/db", "api/configuration/security", "var/run"] + \
                    ["etc/shared/" + g for g in GROUPS]:
        os.makedirs(os.path.join(root, relative), exist_ok=True)

    with open(os.path.join(root, "VERSION.json"), "w") as handle:
        json.dump({"version": "4.14.7"}, handle)
    with open(os.path.join(root, "etc", "client.keys"), "w") as handle:
        for agent_id, name, _ in AGENTS:
            handle.write("%03d %s any %064x\n" % (agent_id, name, agent_id))
        handle.write("004 !removed-agent any %064x\n" % 4)  # 4.x marks a removed entry with !
    with open(os.path.join(root, "etc", "authd.pass"), "w") as handle:
        handle.write("MigrationLab2026\n")

    for group in GROUPS:
        with open(os.path.join(root, "etc", "shared", group, "agent.conf"), "w") as handle:
            handle.write("<agent_config><!-- %s --></agent_config>\n" % group)
    # Compiled by the manager; must never be carried.
    with open(os.path.join(root, "etc", "shared", "linux-servers", "merged.mg"), "w") as handle:
        handle.write("stale\n")
    # Operator content the API cannot upload; has to be reported, not silently dropped.
    with open(os.path.join(root, "etc", "shared", "pci-scope", "custom-list.txt"), "w") as handle:
        handle.write("a:b\n")

    database = os.path.join(root, "queue", "db", "global.db")
    with sqlite3.connect(database) as connection:
        connection.executescript(SOURCE_SCHEMA)
        connection.execute("INSERT INTO agent (id, name, ip, register_ip, date_add) VALUES"
                           " (0, 'mgr4', '127.0.0.1', '127.0.0.1', 1)")
        for group in GROUPS:
            connection.execute("INSERT INTO `group` (name) VALUES (?)", (group,))
        ids = {row[1]: row[0] for row in connection.execute("SELECT id, name FROM `group`")}
        for agent_id, name, groups in AGENTS:
            connection.execute(
                "INSERT INTO agent (id, name, ip, register_ip, date_add, `group`) VALUES"
                " (?, ?, ?, 'any', ?, ?)",
                (agent_id, name, "10.0.0.%d" % agent_id, 1700000000 + agent_id, ",".join(groups)))
            for priority, group in enumerate(groups):
                connection.execute("INSERT INTO belongs VALUES (?, ?, ?)",
                                   (agent_id, ids[group], priority))
    with sqlite3.connect(os.path.join(root, "api/configuration/security/rbac.db")) as connection:
        connection.executescript(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT);"
            "INSERT INTO users VALUES (1, 'wazuh'), (100, 'soc-analyst');"
            "PRAGMA user_version = 1;")
    return root


def build_target(root):
    """Enough of a 5.0 installation for the version check and the rbac.db placement."""
    os.makedirs(os.path.join(root, "api/configuration/security"), exist_ok=True)
    os.makedirs(os.path.join(root, "etc"), exist_ok=True)
    with open(os.path.join(root, "VERSION.json"), "w") as handle:
        json.dump({"version": "5.0.0"}, handle)
    return root


class FakeManager(http.server.BaseHTTPRequestHandler):
    """The endpoints the tool uses, plus a record of every call."""

    calls = []
    agents = {}      # id -> {name, ip, key, groups}
    groups = set()
    configurations = {}
    reject_agents = set()

    @classmethod
    def reset(cls):
        cls.calls, cls.agents, cls.groups = [], {}, {"default"}
        cls.configurations, cls.reject_agents = {}, set()

    def log_message(self, *args):
        pass

    def _send(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode() if length else ""
        try:
            return json.loads(raw) if raw else None
        except ValueError:
            return raw

    def do_POST(self):
        body = self._body()
        FakeManager.calls.append(("POST", self.path, body))
        if self.path.startswith("/security/user/authenticate"):
            if not self.headers.get("Authorization", "").startswith("Basic "):
                return self._send(401, {"title": "Unauthorized"})
            return self._send(200, {"data": {"token": "stub-token"}, "error": 0})
        if self.path == "/groups":
            FakeManager.groups.add(body["group_id"])
            return self._send(200, {"data": {}, "error": 0})
        if self.path == "/agents/insert":
            agent_id = int(body["id"])
            if agent_id in FakeManager.reject_agents:
                return self._send(400, {"data": {"failed_items": [
                    {"error": {"message": "Agent ID already in use"}, "id": [body["id"]]}]},
                    "error": 1})
            FakeManager.agents[agent_id] = {"name": body["name"], "ip": body.get("ip"),
                                            "key": body["key"], "groups": []}
            return self._send(200, {"data": {"id": body["id"]}, "error": 0})
        return self._send(404, {"title": "Not Found"})

    def do_PUT(self):
        body = self._body()
        FakeManager.calls.append(("PUT", self.path, body))
        if self.path.startswith("/groups/") and self.path.endswith("/configuration"):
            # The real endpoint refuses anything but XML; a stub that accepts JSON would have
            # let that through to an operator.
            if self.headers.get("Content-Type") != "application/xml":
                return self._send(415, {"title": "Unsupported Media Type",
                                        "detail": "Invalid Content-type (%s), expected"
                                                  " ['application/xml']"
                                                  % self.headers.get("Content-Type")})
            FakeManager.configurations[self.path.split("/")[2]] = body
            return self._send(200, {"data": {}, "error": 0})
        if "/group/" in self.path:
            _, _, agent_id, _, group = self.path.split("/", 4)
            if int(agent_id) not in FakeManager.agents:
                return self._send(404, {"data": {"failed_items": [
                    {"error": {"message": "Agent does not exist"}, "id": [agent_id]}]},
                    "error": 1})
            FakeManager.agents[int(agent_id)]["groups"].append(group)
            return self._send(200, {"data": {}, "error": 0})
        return self._send(404, {"title": "Not Found"})

    def do_GET(self):
        FakeManager.calls.append(("GET", self.path, None))
        if self.path.startswith("/agents"):
            items = [{"id": "000", "name": "manager", "group": []}] + [
                {"id": "%03d" % i, "name": a["name"], "group": a["groups"]}
                for i, a in sorted(FakeManager.agents.items())]
            return self._send(200, {"data": {"affected_items": items,
                                             "total_affected_items": len(items)}, "error": 0})
        if self.path.startswith("/groups"):
            items = [{"name": n} for n in sorted(FakeManager.groups)]
            return self._send(200, {"data": {"affected_items": items,
                                             "total_affected_items": len(items)}, "error": 0})
        return self._send(404, {"title": "Not Found"})


class MigrationToolTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        FakeManager.reset()
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), FakeManager)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.api_url = "http://127.0.0.1:%d" % cls.server.server_port

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        FakeManager.reset()
        self.workspace = tempfile.TemporaryDirectory()
        base = self.workspace.name
        self.source = build_source(os.path.join(base, "source"))
        self.target = build_target(os.path.join(base, "target"))
        self.bundle = os.path.join(base, "bundle")
        self.password = os.path.join(base, "pw")
        with open(self.password, "w") as handle:
            handle.write("secret\n")

    def tearDown(self):
        self.workspace.cleanup()

    # -- helpers

    def export(self, *extra):
        return tool.main(["export", self.bundle, "--source-dir", self.source] + list(extra))

    def do_import(self, *extra):
        return tool.main(["import", self.bundle, "--target-dir", self.target,
                          "--api-url", self.api_url, "--api-password-file", self.password]
                         + list(extra))

    def check(self, *extra):
        return tool.main(["check", self.bundle, "--target-dir", self.target,
                          "--api-url", self.api_url, "--api-password-file", self.password]
                         + list(extra))

    def manifest(self):
        with open(os.path.join(self.bundle, "manifest.json")) as handle:
            return json.load(handle)

    # -- export

    def test_export_reads_identity_out_of_the_4x_files(self):
        self.assertEqual(0, self.export())
        manifest = self.manifest()
        self.assertEqual(len(AGENTS), len(manifest["agents"]),
                         "a removed client.keys entry is not an agent")
        by_id = {a["id"]: a for a in manifest["agents"]}
        for agent_id, name, groups in AGENTS:
            self.assertEqual(name, by_id[agent_id]["name"])
            self.assertEqual("%064x" % agent_id, by_id[agent_id]["key"])
            self.assertEqual(groups, by_id[agent_id]["groups"], "priority order is preserved")
        self.assertEqual(sorted(CUSTOM_GROUPS), sorted(g["name"] for g in manifest["groups"]),
                         "default is the target's own group and is never recreated")

    def test_export_carries_agent_conf_and_records_what_it_cannot(self):
        self.assertEqual(0, self.export())
        groups = {g["name"]: g for g in self.manifest()["groups"]}
        self.assertIn("linux-servers", groups["linux-servers"]["agent_conf"])
        self.assertEqual([], groups["linux-servers"]["extra_files"],
                         "merged.mg is compiled by the manager and is not operator content")
        self.assertEqual(["custom-list.txt"], groups["pci-scope"]["extra_files"],
                         "a file the API cannot upload is recorded rather than dropped silently")

    def test_neither_secret_is_collected_by_default(self):
        self.assertEqual(0, self.export())
        self.assertFalse(os.path.exists(os.path.join(self.bundle, "authd.pass")))
        self.assertFalse(os.path.exists(os.path.join(self.bundle, "rbac.db")))
        self.assertEqual([], self.manifest()["secrets"])

    def test_export_refuses_a_5x_source(self):
        self.assertEqual(2, tool.main(["export", self.bundle, "--source-dir", self.target]))
        self.assertFalse(os.path.exists(self.bundle))

    def test_export_refuses_an_unknown_source_schema(self):
        with sqlite3.connect(os.path.join(self.source, "queue/db/global.db")) as connection:
            connection.execute("UPDATE metadata SET value = '99' WHERE key = 'db_version'")
        self.assertEqual(2, self.export())
        self.assertFalse(os.path.exists(self.bundle), "no partial bundle is left behind")

    def test_export_refuses_a_running_manager(self):
        with open(os.path.join(self.source, "var/run/wazuh-remoted.pid"), "w"):
            pass
        self.assertEqual(2, self.export())

    def test_export_dry_run_writes_nothing(self):
        self.assertEqual(0, self.export("--dry-run"))
        self.assertFalse(os.path.exists(self.bundle))

    # -- import

    def test_import_recreates_everything_through_the_api(self):
        self.assertEqual(0, self.export())
        self.assertEqual(0, self.do_import())

        self.assertEqual(set(GROUPS), FakeManager.groups,
                         "default was already there; the rest were created")
        for group in CUSTOM_GROUPS:
            self.assertIn(group, FakeManager.configurations)

        self.assertEqual({a[0] for a in AGENTS}, set(FakeManager.agents))
        for agent_id, name, groups in AGENTS:
            recorded = FakeManager.agents[agent_id]
            self.assertEqual(name, recorded["name"])
            self.assertEqual("%064x" % agent_id, recorded["key"], "the 4.x key is reused as is")
            self.assertEqual([g for g in groups if g != "default"], recorded["groups"],
                             "default is not assigned: every agent lands in it anyway")

    def test_import_writes_no_manager_files(self):
        self.assertEqual(0, self.export())
        before = sorted(os.listdir(os.path.join(self.target, "etc")))
        self.assertEqual(0, self.do_import())
        self.assertEqual(before, sorted(os.listdir(os.path.join(self.target, "etc"))),
                         "the API owns client.keys and the registry, not this tool")

    def test_import_dry_run_calls_nothing_that_writes(self):
        self.assertEqual(0, self.export())
        self.assertEqual(0, self.do_import("--dry-run"))
        writes = [c for c in FakeManager.calls if c[0] in ("POST", "PUT")
                  and "authenticate" not in c[1]]
        self.assertEqual([], writes)

    def test_import_refuses_a_populated_target(self):
        self.assertEqual(0, self.export())
        FakeManager.agents[42] = {"name": "someone-else", "ip": None, "key": "x", "groups": []}
        self.assertEqual(2, self.do_import())
        writes = [c for c in FakeManager.calls if c[0] == "POST" and c[1] == "/agents/insert"]
        self.assertEqual([], writes, "a refused import inserts nothing")

    def test_import_reports_an_agent_the_manager_refuses(self):
        self.assertEqual(0, self.export())
        FakeManager.reject_agents = {2}
        self.assertEqual(1, self.do_import(), "a partial import is not a success")
        self.assertEqual({1, 3}, set(FakeManager.agents), "the others still went in")

    def test_import_refuses_a_bundle_from_another_version(self):
        self.assertEqual(0, self.export())
        path = os.path.join(self.bundle, "manifest.json")
        with open(path) as handle:
            manifest = json.load(handle)
        manifest["bundle_version"] = 99
        with open(path, "w") as handle:
            json.dump(manifest, handle)
        self.assertEqual(2, self.do_import())

    def test_import_refuses_a_truncated_manifest(self):
        self.assertEqual(0, self.export())
        with open(os.path.join(self.bundle, "manifest.json"), "w") as handle:
            handle.write('{"bundle_version": 2, "agents"')
        self.assertEqual(2, self.do_import(), "a truncated manifest is a refusal, not a traceback")

    def test_secrets_are_opt_in_at_both_ends(self):
        self.assertEqual(0, self.export("--with-rbac"))
        self.assertTrue(os.path.exists(os.path.join(self.bundle, "rbac.db")))
        self.assertEqual(0, self.do_import())
        self.assertFalse(os.path.exists(
            os.path.join(self.target, "api/configuration/security/rbac.db")),
            "exported is not imported: the import flag gates it too")

    def test_rbac_import_stages_the_api_upgrade(self):
        self.assertEqual(0, self.export("--with-rbac"))
        self.assertEqual(0, self.do_import("--with-rbac"))
        path = os.path.join(self.target, "api/configuration/security/rbac.db")
        with tool.open_ro(path) as connection:
            self.assertEqual(0, connection.execute("PRAGMA user_version").fetchone()[0],
                             "version 0 is what makes the API rebuild its 5.0 defaults")

    def test_a_second_import_keeps_the_first_backup(self):
        path = os.path.join(self.target, "api/configuration/security/rbac.db")
        with open(path, "w") as handle:
            handle.write("the manager's own")  # something worth backing up on the first import
        self.assertEqual(0, self.export("--with-rbac"))
        self.assertEqual(0, self.do_import("--with-rbac"))
        with open(path + ".pre-migration") as handle:
            self.assertEqual("the manager's own", handle.read())
        self.assertEqual(0, self.do_import("--with-rbac", "--force"))
        with open(path + ".pre-migration") as handle:
            self.assertEqual("the manager's own", handle.read(),
                             "the first backup must not be overwritten")
        extra = [n for n in os.listdir(os.path.dirname(path))
                 if n.startswith("rbac.db.pre-migration.")]
        self.assertEqual(1, len(extra), "the second import takes its own timestamped backup")

    def test_the_password_never_comes_from_the_command_line(self):
        completed = subprocess.run(
            ["python3", os.path.join(HERE, "wazuh-migrate-identity.py"), "import", "--help"],
            capture_output=True, text=True)
        self.assertNotIn("--api-password ", completed.stdout,
                         "ps is world-readable; only a file, the environment or a tty")

    # -- check

    def test_check_passes_after_an_import(self):
        self.assertEqual(0, self.export())
        self.assertEqual(0, self.do_import())
        self.assertEqual(0, self.check())

    def test_check_reports_a_missing_agent(self):
        self.assertEqual(0, self.export())
        self.assertEqual(0, self.do_import())
        del FakeManager.agents[2]
        self.assertEqual(1, self.check())

    def test_check_reports_an_agent_the_bundle_never_carried(self):
        self.assertEqual(0, self.export())
        self.assertEqual(0, self.do_import())
        FakeManager.agents[9] = {"name": "some-host", "ip": None, "key": "x", "groups": []}
        self.assertEqual(1, self.check(),
                         "an id the bundle never carried is the signature of an agent that"
                         " re-enrolled against an empty registry")

    def test_check_reports_a_missing_group(self):
        self.assertEqual(0, self.export())
        self.assertEqual(0, self.do_import())
        FakeManager.groups.discard("pci-scope")
        self.assertEqual(1, self.check())

    def test_check_reports_a_membership_that_did_not_land(self):
        self.assertEqual(0, self.export())
        self.assertEqual(0, self.do_import())
        FakeManager.agents[1]["groups"] = []
        self.assertEqual(1, self.check())


if __name__ == "__main__":
    unittest.main(verbosity=2)
