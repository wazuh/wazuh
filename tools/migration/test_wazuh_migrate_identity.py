#!/usr/bin/env python3
# Copyright (C) Wazuh Inc.
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
import shutil
import sqlite3
import ssl
import subprocess
import tempfile
import threading
import unittest
import urllib.parse

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
    with open(os.path.join(root, "VERSION.json"), "w") as handle:
        json.dump({"version": "5.0.0"}, handle)
    return root


def build_target_conf(root):
    """The 5.0 configuration directory, which lives outside the installation home."""
    os.makedirs(root, exist_ok=True)
    return root


class FakeManager(http.server.BaseHTTPRequestHandler):
    """The endpoints the tool uses, plus a record of every call."""

    calls = []
    agents = {}      # id -> {name, ip, key, groups}
    groups = set()
    configurations = {}
    reject_agents = set()
    reject_configurations = set()
    shared_dir = None   # where POST /groups creates the group folder, as the manager does

    # What a fresh 5.0 manager holds in default/agent.conf: comments and an empty element.
    STOCK_DEFAULT = "<!-- Shared agent configuration of this group. -->\n\n<agent_config>\n\n</agent_config>\n"

    @classmethod
    def reset(cls):
        cls.calls, cls.agents, cls.groups = [], {}, {"default"}
        cls.configurations = {"default": cls.STOCK_DEFAULT}
        cls.reject_agents, cls.reject_configurations, cls.shared_dir = set(), set(), None

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
            if FakeManager.shared_dir:
                os.makedirs(os.path.join(FakeManager.shared_dir, body["group_id"]), exist_ok=True)
            return self._send(200, {"data": {}, "error": 0})
        if self.path == "/agents/insert":
            agent_id = int(body["id"])
            if agent_id in FakeManager.reject_agents:
                return self._send(400, {"data": {"failed_items": [
                    {"error": {"message": "Agent ID already in use"}, "id": [body["id"]]}]},
                    "error": 1})
            # The manager puts every inserted agent in default.
            FakeManager.agents[agent_id] = {"name": body["name"], "ip": body.get("ip"),
                                            "key": body["key"], "groups": ["default"]}
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
            name = self.path.split("/")[2]
            if name in FakeManager.reject_configurations:
                return self._send(400, {"title": "Bad Request", "detail": "Wrong XML syntax"})
            FakeManager.configurations[name] = body
            return self._send(200, {"data": {}, "error": 0})
        if "/group/" in self.path:
            parts = urllib.parse.urlsplit(self.path)
            _, _, agent_id, _, group = parts.path.split("/", 4)
            if int(agent_id) not in FakeManager.agents:
                return self._send(404, {"data": {"failed_items": [
                    {"error": {"message": "Agent does not exist"}, "id": [agent_id]}]},
                    "error": 1})
            groups = FakeManager.agents[int(agent_id)]["groups"]
            if "force_single_group=true" in parts.query:
                groups[:] = [group]
            elif group in groups:
                return self._send(400, {"data": {"failed_items": [
                    {"error": {"message": "The group is already assigned to the agent"},
                     "id": [agent_id]}]}, "error": 1})
            else:
                groups.append(group)
            return self._send(200, {"data": {}, "error": 0})
        return self._send(404, {"title": "Not Found"})

    def do_GET(self):
        FakeManager.calls.append(("GET", self.path, None))
        if self.path.startswith("/groups/") and "/files/agent.conf" in self.path:
            body = FakeManager.configurations.get(self.path.split("/")[2], "").encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/xml; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return None
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
        self.target_conf = build_target_conf(os.path.join(base, "target-conf"))
        FakeManager.shared_dir = os.path.join(self.target_conf, "shared")
        os.makedirs(os.path.join(FakeManager.shared_dir, "default"))
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
                          "--target-conf-dir", self.target_conf, "--api-url", self.api_url, "--api-password-file", self.password]
                         + list(extra))

    def check(self, *extra):
        return tool.main(["check", self.bundle, "--target-dir", self.target,
                          "--target-conf-dir", self.target_conf, "--api-url", self.api_url, "--api-password-file", self.password]
                         + list(extra))

    def manifest(self):
        with open(os.path.join(self.bundle, "manifest.json")) as handle:
            return json.load(handle)

    def output_of(self, step, *extra):
        """(exit code, standard output, standard error) of export, do_import or check."""
        import io, contextlib as cl
        out, err = io.StringIO(), io.StringIO()
        with cl.redirect_stdout(out), cl.redirect_stderr(err):
            code = step(*extra)
        return code, out.getvalue(), err.getvalue()

    def write_group_file(self, group, name, content):
        with open(os.path.join(self.source, "etc", "shared", group, name), "w") as handle:
            handle.write(content)

    def customize_default(self):
        self.write_group_file("default", "agent.conf",
                              "<!-- 4.x -->\n<agent_config>\n  <syscheck>\n"
                              "    <directories>/root/fim-test</directories>\n"
                              "  </syscheck>\n</agent_config>\n")

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
            self.assertEqual(groups, recorded["groups"],
                             "exactly the 4.x groups, in the 4.x order: an agent that was not in"
                             " default does not stay there")

    def test_import_writes_no_manager_files(self):
        self.assertEqual(0, self.export())
        before = sorted(os.listdir(self.target_conf))
        self.assertEqual(0, self.do_import())
        self.assertEqual(before, sorted(os.listdir(self.target_conf)),
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

    def test_the_password_lands_in_the_configuration_directory(self):
        import io, contextlib as cl
        err = io.StringIO()
        with cl.redirect_stderr(err):
            self.assertEqual(0, self.export("--with-password"))
        self.assertNotIn("shorter than", err.getvalue(),
                         "a password of exactly the 5.0 minimum (16 bytes) is not warned about")
        self.assertEqual(0, self.do_import("--with-password"))
        with open(os.path.join(self.target_conf, "authd.pass")) as handle:
            self.assertEqual("MigrationLab2026\n", handle.read())
        self.assertFalse(os.path.exists(os.path.join(self.target, "etc", "authd.pass")),
                         "a 5.0 manager reads authd.pass from its configuration directory only")

    def test_a_password_under_the_5x_minimum_is_refused_at_import(self):
        with open(os.path.join(self.source, "etc", "authd.pass"), "w") as handle:
            handle.write("Lab2026Short15c\r\n")   # 15 bytes once CR/LF are trimmed
        import io, contextlib as cl
        err = io.StringIO()
        with cl.redirect_stderr(err):
            self.assertEqual(0, self.export("--with-password"), "export only warns: the 4.x side is still fine")
        self.assertIn("shorter than 16 bytes", err.getvalue(),
                      "the export warns now, before the bundle reaches the 5.0 manager")
        self.assertEqual(2, self.do_import("--with-password"),
                         "the 5.0 authd would refuse to start with it, so the import refuses it first")
        self.assertFalse(os.path.exists(os.path.join(self.target_conf, "authd.pass")))

    def test_a_missing_configuration_directory_is_refused(self):
        self.assertEqual(0, self.export("--with-password"))
        shutil.rmtree(self.target_conf)
        FakeManager.shared_dir = None  # the stub would create it again with the group folders
        self.assertEqual(2, self.do_import("--with-password"))

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

    # -- the manager's published API password

    def test_credentials_env_is_parsed_not_sourced(self):
        path = os.path.join(self.workspace.name, "credentials.env")
        with open(path, "w") as handle:
            handle.write("# operator line\n"
                         "WAZUH_INDEXER_MANAGER_PASSWORD='Str0ng.Pass+01'\n"
                         "# >>> wazuh generated <<<\n"
                         "WAZUH_MANAGER_API_PASSWORD=\"first\"\n"
                         "WAZUH_MANAGER_API_PASSWORD=\"zL9dH.second$(echo never-run)\"\n"
                         "WAZUH_MANAGER_WUI_PASSWORD='cF4nP'\n")
        self.assertEqual("zL9dH.second$(echo never-run)", tool.read_credentials_env(path),
                         "last assignment wins and nothing inside is ever executed")
        self.assertIsNone(tool.read_credentials_env(path + ".missing"))
        self.assertIsNone(tool.read_credentials_env(path, key="NOT_THERE"))

    def test_credentials_env_default_path(self):
        self.assertEqual("/etc/wazuh-manager/export/credentials.env", tool.CREDENTIALS_ENV,
                         "where the manager's credential resolver publishes the API password")

    def test_api_password_falls_back_to_credentials_env(self):
        path = os.path.join(self.workspace.name, "credentials.env")
        with open(path, "w") as handle:
            handle.write("WAZUH_MANAGER_API_PASSWORD=fromfile1234\n")
        original = tool.CREDENTIALS_ENV
        tool.CREDENTIALS_ENV = path
        try:
            args = type("A", (), {"api_password_file": None, "api_user": "wazuh"})()
            saved = {k: os.environ.pop(k, None)
                     for k in ("WAZUH_API_PASSWORD", "WAZUH_MANAGER_API_PASSWORD")}
            try:
                self.assertEqual("fromfile1234", tool.read_api_password(args))
                os.environ["WAZUH_MANAGER_API_PASSWORD"] = "fromenv12345"
                self.assertEqual("fromenv12345", tool.read_api_password(args),
                                 "the manager's own key name must be honoured in the environment")
            finally:
                os.environ.pop("WAZUH_MANAGER_API_PASSWORD", None)
                for k, v in saved.items():
                    if v is not None:
                        os.environ[k] = v
        finally:
            tool.CREDENTIALS_ENV = original

    def test_rbac_import_warns_that_the_published_password_is_stale(self):
        path = os.path.join(self.workspace.name, "credentials.env")
        with open(path, "w") as handle:
            handle.write("WAZUH_MANAGER_API_PASSWORD=generated12345\n")
        original = tool.CREDENTIALS_ENV
        tool.CREDENTIALS_ENV = path
        try:
            self.assertEqual(0, self.export("--with-rbac"))
            import io, contextlib as cl
            err = io.StringIO()
            with cl.redirect_stderr(err):
                self.assertEqual(0, self.do_import("--with-rbac"))
            self.assertIn("no longer match", err.getvalue(),
                          "carrying rbac.db silently changes the API password; say so")
        finally:
            tool.CREDENTIALS_ENV = original

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

    def test_check_reports_a_membership_the_bundle_did_not_carry(self):
        self.assertEqual(0, self.export())
        self.assertEqual(0, self.do_import())
        FakeManager.agents[1]["groups"].insert(0, "default")
        code, out, _ = self.output_of(self.check)
        self.assertEqual(1, code, "web-ubuntu24 was not in default on 4.x")
        self.assertIn("also in default", out)

    def test_check_reports_groups_in_another_order(self):
        self.assertEqual(0, self.export())
        self.assertEqual(0, self.do_import())
        FakeManager.agents[1]["groups"].reverse()
        code, out, _ = self.output_of(self.check)
        self.assertEqual(1, code, "the order decides which group's setting wins")
        self.assertIn("in the order pci-scope, linux-servers", out)

    # -- the default group

    def test_a_stock_default_group_is_not_carried(self):
        self.write_group_file("default", "rootkit_files.txt", "stock\n")
        code, out, _ = self.output_of(self.export)
        self.assertEqual(0, code)
        self.assertFalse(self.manifest()["default_group"]["customized"])
        self.assertNotIn("rootkit_files.txt", out, "4.x ships it in every default group")
        self.assertEqual(0, self.do_import())
        self.assertEqual(FakeManager.STOCK_DEFAULT, FakeManager.configurations["default"],
                         "nothing to merge into the 5.0 default")

    def test_a_customized_default_group_is_merged_after_the_5x_one(self):
        self.customize_default()
        code, out, _ = self.output_of(self.export, "--dry-run")
        self.assertEqual(0, code)
        self.assertIn("customized agent.conf, merged at import", out,
                      "the dry run says the default group is carried")
        self.assertEqual(0, self.export())
        self.assertEqual(0, self.do_import())
        merged = FakeManager.configurations["default"]
        self.assertTrue(merged.startswith(FakeManager.STOCK_DEFAULT.rstrip()),
                        "the 5.0 default is kept")
        self.assertIn("<directories>/root/fim-test</directories>", merged,
                      "the 4.x settings applied to every agent")
        self.assertEqual(0, self.check())

        FakeManager.reject_agents = {1, 2, 3}  # already there: only the merge is of interest here
        self.assertEqual(1, self.do_import("--force"))
        self.assertEqual(merged, FakeManager.configurations["default"],
                         "a second import does not append the 4.x settings again")

    def test_check_reports_a_default_group_without_the_4x_settings(self):
        self.customize_default()
        self.assertEqual(0, self.export())
        self.assertEqual(0, self.do_import())
        FakeManager.configurations["default"] = FakeManager.STOCK_DEFAULT
        code, out, _ = self.output_of(self.check)
        self.assertEqual(1, code)
        self.assertIn("default group's agent.conf does not hold the 4.x settings", out)

    def test_a_default_group_the_manager_refuses_does_not_stop_the_import(self):
        self.customize_default()
        self.assertEqual(0, self.export())
        FakeManager.reject_configurations = {"default"}
        code, _, err = self.output_of(self.do_import)
        self.assertEqual(1, code, "a partial import is not a success")
        self.assertIn("default group were not merged", err)
        self.assertEqual({a[0] for a in AGENTS}, set(FakeManager.agents),
                         "the agents still went in")

    # -- SCA policies in a group folder

    def add_sca_policy(self):
        self.write_group_file("linux-servers", "acme_web_baseline.yml", "policy:\n  id: acme\n")
        self.write_group_file("linux-servers", "agent.conf",
                              "<agent_config os=\"Linux\">\n  <sca>\n    <policies>\n"
                              "      <policy>etc/shared/acme_web_baseline.yml</policy>\n"
                              "    </policies>\n  </sca>\n</agent_config>\n")

    def test_an_sca_policy_the_group_loads_is_carried(self):
        self.add_sca_policy()
        code, out, _ = self.output_of(self.export)
        self.assertEqual(0, code)
        group = {g["name"]: g for g in self.manifest()["groups"]}["linux-servers"]
        self.assertEqual(["acme_web_baseline.yml"], group["sca_policies"])
        self.assertEqual([], group["extra_files"], "it is not reported as left behind")
        self.assertNotIn("acme_web_baseline.yml not migrated", out)
        self.assertEqual(0, self.do_import())
        installed = os.path.join(self.target_conf, "shared", "linux-servers", "acme_web_baseline.yml")
        with open(installed) as handle:
            self.assertEqual("policy:\n  id: acme\n", handle.read())
        self.assertEqual(0o660, os.stat(installed).st_mode & 0o777)
        self.assertEqual(0, self.check())
        os.remove(installed)
        self.assertEqual(1, self.check(), "check looks for the policy too")

    def test_a_windows_policy_path_is_recognised(self):
        self.write_group_file("pci-scope", "win_baseline.yml", "policy: {}\n")
        self.write_group_file("pci-scope", "agent.conf",
                              "<agent_config os=\"Windows\"><sca><policies>"
                              "<policy>shared\\win_baseline.yml</policy>"
                              "</policies></sca></agent_config>")
        self.assertEqual(0, self.export())
        group = {g["name"]: g for g in self.manifest()["groups"]}["pci-scope"]
        self.assertEqual(["win_baseline.yml"], group["sca_policies"])
        self.assertEqual(["custom-list.txt"], group["extra_files"])

    # -- what will not work the same on 5.0

    def test_removed_settings_are_named_in_the_dry_run_export_and_import(self):
        self.write_group_file("db-servers", "agent.conf",
                              "<agent_config>\n  <labels>\n    <label key=\"role\">database</label>\n"
                              "  </labels>\n  <!-- <client_buffer/> is commented out -->\n"
                              "</agent_config>\n")
        dry = self.output_of(self.export, "--dry-run")
        real = self.output_of(self.export)
        imported = self.output_of(self.do_import)
        for code, out, _ in (dry, real, imported):
            self.assertEqual(0, code)
            self.assertEqual(1, out.count("group 'db-servers': <labels> is ignored by 5.0 agents"),
                             "named once, on standard output, at every step")
            self.assertIn("wazuh.agent.groups", out, "and what to use instead")
            self.assertNotIn("client_buffer", out, "a commented-out element is not a setting")
            self.assertEqual(1, out.count("custom-list.txt not migrated"))
        reviewed = [out.split("Review before going on")[1].split("\n\n")[0] for _, out, _ in (dry, real)]
        self.assertEqual(reviewed[0], reviewed[1], "the dry run reviews exactly what the export reviews")

    def test_manager_features_that_stop_at_cutover_are_listed(self):
        with open(os.path.join(self.source, "etc", "ossec.conf"), "w") as handle:
            handle.write("<ossec_config>\n"
                         "  <integration><name>slack</name><hook_url>x</hook_url></integration>\n"
                         "  <active-response><disabled>no</disabled></active-response>\n"
                         "  <active-response><command>firewall-drop</command><location>local</location>"
                         "</active-response>\n"
                         "  <wodle name=\"open-scap\"><disabled>yes</disabled></wodle>\n"
                         "  <remote><connection>syslog</connection><port>514</port></remote>\n"
                         "</ossec_config>\n"
                         "<ossec_config>\n"
                         "  <localfile><log_format>syslog</log_format><location>/var/log/auth.log</location>"
                         "</localfile>\n"
                         "</ossec_config>\n")
        code, out, _ = self.output_of(self.export, "--dry-run")
        self.assertEqual(0, code)
        self.assertIn("integrations (Slack", out)
        self.assertIn("active responses stop", out, "a block with a <command> configures a response")
        self.assertIn("(1 block(s))", out.split("active responses stop")[1].split("\n")[0],
                      "the 4.x global <active-response> block configures none")
        self.assertNotIn("OpenSCAP", out, "a disabled block did nothing on 4.x either")
        self.assertIn("stops receiving syslog", out)
        self.assertIn("monitored its own host (localfile)", out)
        self.assertEqual(0, self.export())
        code, out, _ = self.output_of(self.do_import)
        self.assertIn("integrations (Slack", out, "the import repeats it from the bundle")

    def test_an_agent_conf_that_does_not_parse_is_reported(self):
        self.write_group_file("db-servers", "agent.conf", "<agent_config><syscheck></agent_config>")
        code, out, _ = self.output_of(self.export)
        self.assertEqual(0, code)
        self.assertIn("group 'db-servers': agent.conf is not well-formed XML", out)

    def test_a_version_2_bundle_is_imported_with_a_notice(self):
        self.assertEqual(0, self.export())
        path = os.path.join(self.bundle, "manifest.json")
        manifest = self.manifest()
        manifest["bundle_version"], manifest["tool_version"] = 2, "2.0.0"
        del manifest["default_group"]
        for group in manifest["groups"]:
            del group["sca_policies"]
        with open(path, "w") as handle:
            json.dump(manifest, handle)
        code, _, err = self.output_of(self.do_import)
        self.assertEqual(0, code)
        self.assertIn("carried neither the default group's agent.conf", err)
        self.assertEqual(0, self.check())

    # -- verifying the API it sends the password and the agent keys to

    def call_api(self, command, url, *extra):
        return tool.main([command, self.bundle, "--target-dir", self.target,
                          "--target-conf-dir", self.target_conf, "--api-url", url, "--api-password-file", self.password] + list(extra))

    def test_loopback_detection(self):
        for host in ("localhost", "LOCALHOST", "127.0.0.1", "127.8.9.10", "::1"):
            self.assertTrue(tool.is_loopback(host), host)
        for host in (None, "", "10.0.0.5", "manager.example.com", "localhost.example.com",
                     "::ffff:10.0.0.5", "0.0.0.0"):
            self.assertFalse(tool.is_loopback(host), host)

    def test_a_remote_api_without_a_ca_is_refused_before_any_call(self):
        self.assertEqual(0, self.export())
        for command in ("import", "check"):
            for url in ("https://10.0.0.5:55000", "https://manager.example.com:55000"):
                self.assertEqual(2, self.call_api(command, url), "%s %s" % (command, url))
        self.assertEqual([], FakeManager.calls, "the password must not leave before verification")

    def test_a_remote_api_over_plain_http_is_refused_even_with_a_ca(self):
        self.assertEqual(0, self.export())
        ca = os.path.join(self.workspace.name, "ca.pem")
        open(ca, "w").close()
        self.assertEqual(2, self.call_api("import", "http://10.0.0.5:55000", "--api-ca", ca))
        self.assertEqual([], FakeManager.calls)

    def test_ca_resolution(self):
        def resolve(url, ca=None):
            return tool.resolve_api_ca(tool.build_parser().parse_args(
                ["check", self.bundle, "--target-dir", self.target,
                 "--target-conf-dir", self.target_conf, "--api-url", url]
                + (["--api-ca", ca] if ca else [])))

        root_ca = os.path.join(self.target_conf, "certs", "root-ca.pem")
        with self.assertRaises(tool.MigrationError, msg="loopback with no root-ca.pem to trust"):
            resolve("https://localhost:55000")
        os.makedirs(os.path.dirname(root_ca))
        open(root_ca, "w").close()
        self.assertEqual(root_ca, resolve("https://localhost:55000"))
        self.assertEqual(root_ca, resolve("https://[::1]:55000"))
        self.assertIsNone(resolve("http://127.0.0.1:55000"), "plain loopback carries no TLS")
        with self.assertRaises(tool.MigrationError, msg="the local CA never vouches for a remote"):
            resolve("https://10.0.0.5:55000")
        self.assertEqual(root_ca, resolve("https://10.0.0.5:55000", ca=root_ca))
        with self.assertRaises(tool.MigrationError):
            resolve("https://10.0.0.5:55000", ca=root_ca + ".missing")
        with self.assertRaises(tool.MigrationError):
            resolve("ftp://localhost:55000")

    @unittest.skipUnless(shutil.which("openssl"), "needs openssl to mint a test certificate")
    def test_the_api_certificate_is_verified_against_the_target_root_ca(self):
        def mint(name):
            cert, key = (os.path.join(self.workspace.name, name + s) for s in (".pem", "-key.pem"))
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                            "-days", "1", "-subj", "/CN=localhost", "-keyout", key, "-out", cert,
                            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
                           check=True, capture_output=True)
            return cert, key

        served_cert, served_key = mint("apid")
        other_ca, _ = mint("other")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(served_cert, served_key)
        server = http.server.HTTPServer(("127.0.0.1", 0), FakeManager)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        url = "https://localhost:%d" % server.server_port

        self.assertEqual(0, self.export())
        root_ca = os.path.join(self.target_conf, "certs", "root-ca.pem")
        os.makedirs(os.path.dirname(root_ca))
        shutil.copy(other_ca, root_ca)
        self.assertEqual(2, self.call_api("import", url),
                         "a certificate the target's CA did not issue is refused")
        self.assertEqual([], FakeManager.calls, "nothing, the password included, was sent")

        shutil.copy(served_cert, root_ca)
        self.assertEqual(0, self.call_api("import", url))
        self.assertEqual(0, self.call_api("check", url))


if __name__ == "__main__":
    unittest.main(verbosity=2)
