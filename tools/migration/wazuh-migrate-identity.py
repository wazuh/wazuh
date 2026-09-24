#!/usr/bin/env python3
# Copyright (C) 2015, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

"""Carry a 4.x manager's agent identity into a fresh 5.0 installation.

A 4.x manager cannot be upgraded in place, and a 5.0 installation starts empty, so the agents, the
groups they belong to and the configuration those groups carry have to be moved across by hand.

  export  on the **stopped** 4.x manager, read the identity out of its files into a bundle
  import  on the **running** 5.0 manager, recreate it through the manager's own API
  check   on the running 5.0 manager, compare what it holds against the bundle

The two halves are deliberately asymmetric. The 4.x manager is being decommissioned and its files
are the only thing left to read, so `export` reads them directly. The 5.0 manager is the one that
has to end up correct, so `import` never writes its files: every agent, group and membership is
created through the API, which applies the same validation, ownership and bookkeeping it applies to
any other client. The only exceptions are the two credentials the API cannot express, and both are
opt-in.

Standard library only, so it runs on either host without installing anything.
"""

import argparse
import contextlib
import getpass
import grp
import json
import os
import pwd
import shutil
import sqlite3
import ssl
import sys
import time
import urllib.error
import urllib.request

TOOL_VERSION = "2.0.0"
BUNDLE_VERSION = 2

DEFAULT_SOURCE_DIR = "/var/ossec"
DEFAULT_TARGET_DIR = "/var/wazuh-manager"
DEFAULT_API_URL = "https://localhost:55000"

# Where a 5.0 manager publishes the Server API password it generated at install (#39554). Read
# as data, never sourced; the last assignment of the key wins, as the manager's own reader does.
CREDENTIALS_ENV = "/etc/wazuh/credentials.env"
CREDENTIALS_KEY = "WAZUH_MANAGER_API_PASSWORD"

# 4.x stamps PRAGMA user_version 0 and tracks its own schema in metadata.db_version. Only the
# revisions whose agent table this reader has been checked against are accepted.
SOURCE_DB_VERSIONS_CHECKED = (7, 8, 9, 10, 11, 12)

# Group folders the target ships itself: recreating them would replace 5.0 content.
RESERVED_GROUPS = ("default",)

# The two credentials no endpoint can express, so they stay file copies. Both are opt-in.
#   key: bundle name -> (source relative path, target relative path, owner, group, mode)
# Both belong to the service account: authd creates authd.pass itself and the API rewrites
# rbac.db, each after dropping privileges.
SECRET_FILES = {
    "authd.pass": ("etc/authd.pass", "etc/authd.pass",
                   "wazuh-manager", "wazuh-manager", 0o640),
    "rbac.db": ("api/configuration/security/rbac.db", "api/configuration/security/rbac.db",
                "wazuh-manager", "wazuh-manager", 0o640),
}


class MigrationError(Exception):
    """A condition the operator has to resolve; reported without a traceback."""


def log(message):
    print(message)


def warn(message):
    print("WARNING: %s" % message, file=sys.stderr)


# --------------------------------------------------------------------------------------
# the manager's API
# --------------------------------------------------------------------------------------

class ManagerApi:
    """The 5.0 manager's REST API, over the standard library.

    Every write this tool performs on the target goes through here, so the manager validates it,
    writes its own files with its own ownership, and keeps `client.keys` and `global.db` in step
    with each other. That is the whole reason the import side has no notion of either.
    """

    def __init__(self, url, user, password, ca_path=None):
        self.url = url.rstrip("/")
        self.user = user
        self.password = password
        self.token = None
        if ca_path:
            self.context = ssl.create_default_context(cafile=ca_path)
        else:
            # The default target is the manager's own loopback address, where the connection never
            # leaves the host and apid serves a certificate it issued itself. Pass --api-ca to
            # verify instead, which is what a non-local --api-url needs.
            self.context = ssl.create_default_context()
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE

    def _call(self, method, path, body=None, auth=None, content_type="application/json"):
        request = urllib.request.Request(self.url + path, method=method)
        request.add_header("Content-Type", content_type)
        if auth:
            request.add_header("Authorization", auth)
        if body is None:
            data = None
        elif content_type == "application/json":
            data = json.dumps(body).encode()
        else:
            # A group's agent.conf goes up as the XML document it is; the endpoint rejects
            # anything else with "Invalid Content-type".
            data = body.encode() if isinstance(body, str) else body
        try:
            with urllib.request.urlopen(request, data=data, context=self.context,
                                        timeout=60) as response:
                return json.loads(response.read().decode() or "{}")
        except urllib.error.HTTPError as error:
            payload = error.read().decode(errors="replace")
            try:
                return {"__status": error.code, **json.loads(payload)}
            except ValueError:
                return {"__status": error.code, "title": error.reason, "detail": payload[:200]}
        except urllib.error.URLError as error:
            raise MigrationError(
                "cannot reach the manager API at %s: %s. The API has to be running for the"
                " import, unlike the 4.x side. Check the address and --api-user/--api-password-file."
                % (self.url, error.reason))

    def authenticate(self):
        import base64
        basic = base64.b64encode(("%s:%s" % (self.user, self.password)).encode()).decode()
        answer = self._call("POST", "/security/user/authenticate", auth="Basic " + basic)
        token = (answer.get("data") or {}).get("token")
        if not token:
            raise MigrationError(
                "the API refused the credentials for '%s' (%s). A fresh 5.0 installation"
                " publishes the password it generated in %s; one that carried the 4.x rbac.db"
                " answers to the 4.x password instead."
                % (self.user, answer.get("detail") or answer.get("title") or "no detail",
                   CREDENTIALS_ENV))
        self.token = "Bearer " + token

    def request(self, method, path, body=None, content_type="application/json"):
        """Returns (ok, payload). A non-2xx is data, not an exception: the caller decides."""
        answer = self._call(method, path, body, auth=self.token, content_type=content_type)
        status = answer.pop("__status", 200)
        return status < 300 and answer.get("error", 0) == 0, answer

    def require(self, method, path, body=None, what="", content_type="application/json"):
        ok, answer = self.request(method, path, body, content_type)
        if not ok:
            raise MigrationError("%s failed: %s" % (what or "%s %s" % (method, path),
                                                    describe_api_error(answer)))
        return answer


def describe_api_error(answer):
    """The manager's own words, which are more use than anything this tool could invent."""
    failed = (answer.get("data") or {}).get("failed_items")
    if failed:
        first = failed[0]
        return "%s (%s)" % (first.get("error", {}).get("message", "unknown"),
                            ", ".join(str(i) for i in first.get("id", [])[:5]))
    return (answer.get("detail") or answer.get("message")
            or answer.get("title") or json.dumps(answer)[:200])


# --------------------------------------------------------------------------------------
# reading the 4.x manager
# --------------------------------------------------------------------------------------

def read_version(install_dir):
    """Returns the installation's version string, or None when it cannot be determined."""
    for name, parse in (("VERSION.json", lambda t: json.loads(t).get("version")),
                        ("VERSION", lambda t: t.strip())):
        path = os.path.join(install_dir, name)
        if os.path.isfile(path):
            try:
                with open(path) as handle:
                    return parse(handle.read())
            except (ValueError, OSError):
                return None
    return None


def major_of(version):
    """4 out of 'v4.14.7'. None when it does not parse."""
    if not version:
        return None
    digits = version.lstrip("vV").split(".")[0]
    return int(digits) if digits.isdigit() else None


def assert_install(install_dir, expected_major, role):
    if not os.path.isdir(install_dir):
        raise MigrationError("%s directory '%s' does not exist. Pass --%s-dir."
                             % (role, install_dir, role))
    version = read_version(install_dir)
    major = major_of(version)
    if major is None:
        warn("could not read the %s version from '%s'; continuing on the operator's word."
             % (role, install_dir))
        return version
    if major != expected_major:
        raise MigrationError("'%s' holds version %s, not a %d.x manager."
                             % (install_dir, version, expected_major))
    return version


def assert_stopped(install_dir, force):
    """The 4.x files are read underneath live daemons otherwise."""
    run_dir = os.path.join(install_dir, "var", "run")
    running = []
    if os.path.isdir(run_dir):
        try:
            running = [n for n in os.listdir(run_dir) if n.endswith(".pid")]
        except OSError:
            pass
    if not running:
        return
    message = ("the manager at '%s' looks like it is running (%d pid file(s) under var/run)."
               % (install_dir, len(running)))
    if force:
        warn(message + " Continuing because --force was given.")
        return
    raise MigrationError(message + " Stop it first, or pass --force if you know it is down.")


def open_ro(path):
    """A read-only connection that closes on leaving its `with` block."""
    return contextlib.closing(sqlite3.connect("file:%s?mode=ro" % path, uri=True))


def read_client_keys(path):
    """Returns {id: {name, ip, key}} from a client.keys, skipping removed and malformed entries."""
    agents = {}
    with open(path) as handle:
        for line in handle:
            fields = line.split()
            if len(fields) < 4 or not fields[0].isdigit():
                continue
            if fields[1].startswith("!") or fields[1].startswith("#"):
                continue  # a removed entry, which 4.x marks by prefixing the name
            agents[int(fields[0])] = {"name": fields[1], "ip": fields[2], "key": fields[3]}
    return agents


def read_registry(path, agents):
    """Fills in each agent's group membership, in priority order, from the 4.x registry."""
    with open_ro(path) as connection:
        try:
            row = connection.execute(
                "SELECT value FROM metadata WHERE key = 'db_version'").fetchone()
            db_version = int(row[0]) if row and str(row[0]).isdigit() else None
        except sqlite3.Error:
            db_version = None

        for agent_id, group in connection.execute(
                "SELECT b.id_agent, g.name FROM belongs b JOIN `group` g ON g.id = b.id_group"
                " WHERE b.id_agent > 0 ORDER BY b.id_agent, b.priority"):
            if agent_id in agents:
                agents[agent_id].setdefault("groups", []).append(group)
        known = {row[0] for row in connection.execute("SELECT name FROM `group`")}
    return db_version, known


def read_groups(shared_dir, known_names):
    """Returns [{name, agent_conf, extra_files}] for every custom group folder."""
    groups = []
    if not os.path.isdir(shared_dir):
        return groups
    for name in sorted(os.listdir(shared_dir)):
        folder = os.path.join(shared_dir, name)
        if not os.path.isdir(folder) or os.path.islink(folder) or name in RESERVED_GROUPS:
            continue
        agent_conf, extra = None, []
        for entry in sorted(os.listdir(folder)):
            path = os.path.join(folder, entry)
            if not os.path.isfile(path) or entry == "merged.mg":
                continue  # merged.mg is compiled by the manager from everything else here
            if entry == "agent.conf":
                with open(path, errors="replace") as handle:
                    agent_conf = handle.read()
            else:
                extra.append(entry)
        groups.append({"name": name, "agent_conf": agent_conf, "extra_files": extra})
    for name in sorted(known_names - {g["name"] for g in groups} - set(RESERVED_GROUPS)):
        # Recorded in the registry but with no folder: still a group agents belong to.
        groups.append({"name": name, "agent_conf": None, "extra_files": []})
    return groups


# --------------------------------------------------------------------------------------
# export
# --------------------------------------------------------------------------------------

def command_export(args):
    source = args.source_dir
    version = assert_install(source, 4, "source")
    assert_stopped(source, args.force)

    if os.path.exists(args.bundle) and os.listdir(args.bundle):
        raise MigrationError("bundle directory '%s' exists and is not empty." % args.bundle)

    keys_path = os.path.join(source, "etc", "client.keys")
    registry_path = os.path.join(source, "queue", "db", "global.db")
    for path, what in ((keys_path, "agent keys"), (registry_path, "the agent registry")):
        if not os.path.isfile(path):
            raise MigrationError("'%s' not found: %s cannot be read. In 4.x the registry lives"
                                 " under queue/db, not var/db." % (path, what))

    agents = read_client_keys(keys_path)
    if not agents:
        raise MigrationError("'%s' holds no usable agent entries: nothing to migrate." % keys_path)
    db_version, known_groups = read_registry(registry_path, agents)

    if db_version is not None and db_version not in SOURCE_DB_VERSIONS_CHECKED:
        message = ("the source registry reports db_version %d, which this tool has not been"
                   " checked against (known: %s)."
                   % (db_version, ", ".join(str(v) for v in SOURCE_DB_VERSIONS_CHECKED)))
        if args.force:
            warn(message + " Continuing because --force was given.")
        else:
            raise MigrationError(message + " Re-run with --force to export it anyway.")

    groups = read_groups(os.path.join(source, "etc", "shared"), known_groups)
    payload = [dict(id=agent_id, **data) for agent_id, data in sorted(agents.items())]

    log("  agents   %d" % len(payload))
    log("  groups   %d (%s)" % (len(groups), ", ".join(g["name"] for g in groups) or "none"))
    for group in groups:
        if group["extra_files"]:
            warn("group '%s' holds files other than agent.conf (%s). They are recorded but not"
                 " migrated: 5.0 compiles whatever is in a group folder and pushes it to its"
                 " agents, and a 4.x list or rootcheck file has no meaning there."
                 % (group["name"], ", ".join(group["extra_files"])))

    secrets = []
    for name, (relative, _, _, _, _) in SECRET_FILES.items():
        asked = args.with_password if name == "authd.pass" else args.with_rbac
        path = os.path.join(source, relative)
        if not asked:
            log("  skip     %s (--with-%s not given)"
                % (name, "password" if name == "authd.pass" else "rbac"))
        elif not os.path.isfile(path):
            log("  skip     %s (not present on the source)" % name)
        else:
            secrets.append((name, path))

    manifest = {
        "bundle_version": BUNDLE_VERSION,
        "tool_version": TOOL_VERSION,
        "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "source_dir": source,
        "source_version": version,
        "source_db_version": db_version,
        "agents": payload,
        "groups": groups,
        "secrets": [name for name, _ in secrets],
    }

    if args.dry_run:
        log("")
        log("DRY RUN: nothing was written.")
        return 0

    os.makedirs(args.bundle, mode=0o700, exist_ok=True)
    os.chmod(args.bundle, 0o700)
    for name, path in secrets:
        destination = os.path.join(args.bundle, name)
        if name.endswith(".db"):
            with contextlib.closing(sqlite3.connect("file:%s?mode=ro" % path, uri=True)) as src:
                with contextlib.closing(sqlite3.connect(destination)) as dst:
                    src.backup(dst)
        else:
            shutil.copy2(path, destination)
        os.chmod(destination, 0o600)
        log("  export   %s" % name)

    reference = os.path.join(args.bundle, "reference")
    os.makedirs(reference, mode=0o700, exist_ok=True)
    for relative in ("etc/ossec.conf", "etc/local_internal_options.conf",
                     "api/configuration/api.yaml"):
        path = os.path.join(source, relative)
        if os.path.isfile(path):
            shutil.copy2(path, os.path.join(reference, os.path.basename(relative)))

    manifest_path = os.path.join(args.bundle, "manifest.json")
    with open(manifest_path, "w") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.chmod(manifest_path, 0o600)

    log("")
    log("Exported %d agent(s) and %d group(s) from %s"
        % (len(payload), len(groups), version or "an unknown version"))
    log("Bundle: %s" % args.bundle)
    log("It carries agent keys%s. Move it like a credential."
        % (" and API password hashes" if "rbac.db" in manifest["secrets"] else ""))
    return 0


# --------------------------------------------------------------------------------------
# import
# --------------------------------------------------------------------------------------

def load_manifest(bundle):
    path = os.path.join(bundle, "manifest.json")
    if not os.path.isfile(path):
        raise MigrationError("'%s' has no manifest.json; it is not an export bundle." % bundle)
    with open(path) as handle:
        manifest = json.load(handle)
    if manifest.get("bundle_version") != BUNDLE_VERSION:
        raise MigrationError("bundle version %s is not supported by this tool (expected %d)."
                             % (manifest.get("bundle_version"), BUNDLE_VERSION))
    for field in ("agents", "groups"):
        if not isinstance(manifest.get(field), list):
            raise MigrationError("the manifest has no '%s' list; the bundle is incomplete."
                                 % field)
    return manifest


def read_credentials_env(path=None, key=CREDENTIALS_KEY):
    """The value the manager published for `key`, or None. Parsed, never sourced."""
    # Resolved at call time rather than bound as a default, so the module setting stays the single
    # place that names the file.
    path = CREDENTIALS_ENV if path is None else path
    try:
        with open(path) as handle:
            lines = handle.read().splitlines()
    except OSError:
        return None
    value = None
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, _, raw = line.partition("=")
        if name.strip() != key:
            continue
        raw = raw.strip()
        if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "\"'":
            raw = raw[1:-1]
        value = raw or None
    return value


def read_api_password(args):
    """In order: --api-password-file, the environment, the manager's credentials.env, a tty."""
    if args.api_password_file:
        source = sys.stdin if args.api_password_file == "-" else open(args.api_password_file)
        with contextlib.closing(source):
            password = source.readline().strip()
        if password:
            return password
        raise MigrationError("no password was read from %s." % args.api_password_file)
    # The manager's own key name is honoured too, so a value exported for it serves both.
    password = os.environ.get("WAZUH_API_PASSWORD") or os.environ.get(CREDENTIALS_KEY)
    if password:
        return password
    password = read_credentials_env()
    if password:
        log("  api      password taken from %s (%s)" % (CREDENTIALS_ENV, CREDENTIALS_KEY))
        return password
    if sys.stdin.isatty():
        return getpass.getpass("API password for %s: " % args.api_user)
    # Never accepted on the command line: ps is world-readable.
    raise MigrationError("no API password. Use --api-password-file, WAZUH_API_PASSWORD, or run"
                         " it on a terminal. A 5.0 manager publishes the one it generated in %s."
                         % CREDENTIALS_ENV)


def api_preflight(api, manifest, force):
    """Every reason to refuse, asked of the manager itself, before the first write."""
    ok, answer = api.request("GET", "/agents?select=id&limit=1&offset=0")
    if not ok:
        raise MigrationError("cannot read the agent list: %s" % describe_api_error(answer))
    # The manager itself is agent 0 and is always present; anything else is a real agent.
    existing = answer["data"]["total_affected_items"] - 1
    if existing > 0 and not force:
        raise MigrationError(
            "the target already holds %d agent(s). Importing would collide with them by id"
            " (the API refuses a duplicate id with error 1708). Re-run with --force to attempt"
            " it anyway." % existing)

    wanted = {group["name"] for group in manifest["groups"]}
    ok, answer = api.request("GET", "/groups?limit=500")
    if not ok:
        raise MigrationError("cannot read the group list: %s" % describe_api_error(answer))
    present = {item["name"] for item in answer["data"]["affected_items"]}
    return present & wanted


def import_groups(api, manifest, already_present, dry_run):
    created = 0
    for group in manifest["groups"]:
        name = group["name"]
        if name in already_present:
            log("  group    %-20s exists already, configuration left alone" % name)
            continue
        log("  group    %-20s create%s" % (name, " + agent.conf" if group["agent_conf"] else ""))
        if dry_run:
            continue
        api.require("POST", "/groups", {"group_id": name}, "creating group '%s'" % name)
        created += 1
        if group["agent_conf"]:
            api.require("PUT", "/groups/%s/configuration" % name, group["agent_conf"],
                        "uploading the configuration of group '%s'" % name,
                        content_type="application/xml")
    return created


def import_agents(api, manifest, dry_run):
    """Returns (ids the manager now holds, failures). Membership follows only for the former."""
    inserted, failed = set(), []
    for agent in manifest["agents"]:
        body = {"id": "%03d" % agent["id"], "name": agent["name"], "key": agent["key"]}
        if agent.get("ip"):
            body["ip"] = agent["ip"]
        log("  agent    %-20s id %s" % (agent["name"], body["id"]))
        if dry_run:
            inserted.add(agent["id"])
            continue
        ok, answer = api.request("POST", "/agents/insert", body)
        if ok:
            inserted.add(agent["id"])
        else:
            failed.append((agent, describe_api_error(answer)))
    return inserted, failed


def import_memberships(api, manifest, inserted, dry_run):
    assigned, failed = 0, []
    for agent in manifest["agents"]:
        if agent["id"] not in inserted:
            continue  # it is not there to assign; its insertion failure is reported already
        for group in agent.get("groups", []):
            if group in RESERVED_GROUPS:
                continue  # every agent lands in default on its own
            if dry_run:
                assigned += 1
                continue
            ok, answer = api.request(
                "PUT", "/agents/%03d/group/%s" % (agent["id"], group))
            if ok:
                assigned += 1
            else:
                failed.append((agent, group, describe_api_error(answer)))
    return assigned, failed


def install_secret(bundle, name, target_dir, dry_run):
    """The two credentials no endpoint can express."""
    _, relative, owner, group, mode = SECRET_FILES[name]
    source = os.path.join(bundle, name)
    destination = os.path.join(target_dir, relative)
    if not os.path.isdir(os.path.dirname(destination)):
        raise MigrationError("'%s' does not exist; is '%s' a 5.0 installation?"
                             % (os.path.dirname(destination), target_dir))

    backup = None
    if os.path.exists(destination):
        backup = "%s.pre-migration" % destination
        if os.path.exists(backup):
            # Never overwrite an earlier backup, and never skip one either.
            backup = "%s.pre-migration.%s" % (destination, time.strftime("%Y%m%d%H%M%S"))
    log("  secret   %-20s -> %s (%s:%s %o)%s"
        % (name, destination, owner, group, mode,
           (" [would back up]" if dry_run else " [backed up]") if backup else ""))
    if dry_run:
        return

    if backup:
        shutil.copy2(destination, backup)
    shutil.copy2(source, destination)
    os.chmod(destination, mode)
    try:
        os.chown(destination, pwd.getpwnam(owner).pw_uid, grp.getgrnam(group).gr_gid)
    except KeyError:
        warn("user '%s' or group '%s' does not exist; ownership of '%s' left unchanged."
             % (owner, group, destination))


def stage_rbac(target_dir, dry_run):
    """Asks the API to rebuild its defaults on the next start.

    4.x and 5.0 both stamp RBAC version 1, so a carried database is taken for a current one and
    keeps the 4.x default policies: the ones 5.0 added, enrollment-token minting among them, are
    never created. Setting the version to 0 is what asks for the supported upgrade, which rebuilds
    the defaults and migrates across the users, roles and policies an operator created.
    """
    path = os.path.join(target_dir, "api", "configuration", "security", "rbac.db")
    if not os.path.isfile(path):
        return
    log("  stage    rbac.db              PRAGMA user_version = 0, so the API rebuilds its defaults")
    if dry_run:
        return
    with contextlib.closing(sqlite3.connect(path)) as connection:
        connection.execute("PRAGMA user_version = 0")
        connection.commit()


def command_import(args):
    target = args.target_dir
    version = assert_install(target, 5, "target")
    manifest = load_manifest(args.bundle)

    api = ManagerApi(args.api_url, args.api_user, read_api_password(args), args.api_ca)
    api.authenticate()

    log("Bundle from %s (%s), %d agent(s), %d group(s)"
        % (manifest.get("source_version") or "an unknown version",
           manifest.get("created", "unknown date"),
           len(manifest["agents"]), len(manifest["groups"])))
    log("Target %s (%s) through %s" % (target, version or "unknown version", args.api_url))
    if args.dry_run:
        log("DRY RUN: nothing is written.")
    log("")

    already_present = api_preflight(api, manifest, args.force)

    import_groups(api, manifest, already_present, args.dry_run)
    inserted, agent_failures = import_agents(api, manifest, args.dry_run)
    assigned, membership_failures = import_memberships(api, manifest, inserted, args.dry_run)

    for name in manifest.get("secrets", []):
        asked = args.with_password if name == "authd.pass" else args.with_rbac
        if not os.path.isfile(os.path.join(args.bundle, name)):
            continue
        if not asked:
            log("  skip     %-20s (--with-%s not given)"
                % (name, "password" if name == "authd.pass" else "rbac"))
            continue
        install_secret(args.bundle, name, target, args.dry_run)
        if name == "rbac.db":
            stage_rbac(target, args.dry_run)
            if os.path.isfile(CREDENTIALS_ENV):
                # The manager never reseeds an existing rbac.db, so from the next start both
                # Server API users carry their 4.x passwords, while the file still holds the values
                # the install generated and handed to the dashboard. Two records, one true.
                warn("from the next start the 'wazuh' and 'wazuh-wui' passwords are the 4.x ones"
                     " carried in rbac.db; %s and WAZUH_MANAGER_WUI_PASSWORD in %s no longer"
                     " match them, and a dashboard installed with that WUI value cannot log in."
                     " Either set both users back to the published values with"
                     " 'rbac_control change-password' after the restart, or update the dashboard"
                     " and pass --api-password-file to 'check'."
                     % (CREDENTIALS_KEY, CREDENTIALS_ENV))

    log("")
    if args.dry_run:
        log("Dry run complete. Re-run without --dry-run to apply.")
        return 0

    for agent, reason in agent_failures:
        warn("agent %03d (%s) was not inserted: %s" % (agent["id"], agent["name"], reason))
    for agent, group, reason in membership_failures:
        warn("agent %03d (%s) was not added to '%s': %s"
             % (agent["id"], agent["name"], group, reason))

    log("Inserted %d of %d agent(s), %d group membership(s)."
        % (len(inserted), len(manifest["agents"]), assigned))
    if agent_failures or membership_failures:
        log("Some items were refused by the manager; the messages above are its own.")
        return 1
    log("")
    log("Next: open the manager to the fleet, then run this tool's 'check'.")
    return 0


# --------------------------------------------------------------------------------------
# check
# --------------------------------------------------------------------------------------

def command_check(args):
    assert_install(args.target_dir, 5, "target")
    manifest = load_manifest(args.bundle)
    api = ManagerApi(args.api_url, args.api_user, read_api_password(args), args.api_ca)
    api.authenticate()

    problems = []

    answer = api.require("GET", "/agents?select=id,name,group&limit=10000", what="reading agents")
    installed = {}
    for item in answer["data"]["affected_items"]:
        if item["id"] == "000":
            continue  # the manager's own entry
        installed[int(item["id"])] = item
    expected = {agent["id"]: agent for agent in manifest["agents"]}

    log("agents    %d of %d present" % (len(set(expected) & set(installed)), len(expected)))
    for agent_id in sorted(set(expected) - set(installed)):
        problems.append("agent %03d (%s) is missing." % (agent_id, expected[agent_id]["name"]))
    for agent_id in sorted(set(expected) & set(installed)):
        if installed[agent_id]["name"] != expected[agent_id]["name"]:
            problems.append("agent %03d is named '%s', the bundle carried '%s'."
                            % (agent_id, installed[agent_id]["name"], expected[agent_id]["name"]))
        want = {g for g in expected[agent_id].get("groups", []) if g not in RESERVED_GROUPS}
        have = set(installed[agent_id].get("group", []))
        if want - have:
            problems.append("agent %03d is not in %s."
                            % (agent_id, ", ".join(sorted(want - have))))
    # An id the bundle never carried is either a new agent or -- the case worth catching -- one
    # that reached the manager while the registry was still empty and enrolled again.
    for agent_id in sorted(set(installed) - set(expected)):
        problems.append(
            "agent %03d (%s) was not in the bundle. If it appeared during the migration it is an"
            " agent that re-enrolled against the empty registry and lost its original id."
            % (agent_id, installed[agent_id]["name"]))

    answer = api.require("GET", "/groups?limit=500", what="reading groups")
    present = {item["name"] for item in answer["data"]["affected_items"]}
    log("groups    %d of %d present"
        % (len({g["name"] for g in manifest["groups"]} & present), len(manifest["groups"])))
    for group in manifest["groups"]:
        if group["name"] not in present:
            problems.append("group '%s' is missing." % group["name"])

    if "rbac.db" in manifest.get("secrets", []):
        path = os.path.join(args.target_dir, "api", "configuration", "security", "rbac.db")
        if os.path.isfile(path):
            with open_ro(path) as connection:
                staged = connection.execute("PRAGMA user_version").fetchone()[0]
            log("rbac.db   schema version %d%s"
                % (staged, "  (still staged: the API rebuilds its defaults on the next start)"
                   if staged == 0 else ""))

    log("")
    if problems:
        log("%d problem(s):" % len(problems))
        for problem in problems:
            log("  - %s" % problem)
        return 1
    log("The target matches the bundle.")
    return 0


# --------------------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        prog="wazuh-migrate-identity",
        description="Carry a 4.x manager's agent identity into a 5.0 installation.")
    parser.add_argument("--version", action="version", version="%(prog)s " + TOOL_VERSION)
    subparsers = parser.add_subparsers(dest="command", required=True)

    export_parser = subparsers.add_parser(
        "export", help="on the stopped 4.x manager: read its identity into a bundle")
    export_parser.add_argument("bundle", help="directory to create the bundle in")
    export_parser.add_argument("--source-dir", default=DEFAULT_SOURCE_DIR,
                               help="4.x installation directory (default: %(default)s)")
    export_parser.set_defaults(handler=command_export)

    import_parser = subparsers.add_parser(
        "import", help="on the running 5.0 manager: recreate it through the API")
    import_parser.add_argument("bundle", help="bundle directory produced by export")
    import_parser.set_defaults(handler=command_import)

    check_parser = subparsers.add_parser(
        "check", help="on the running 5.0 manager: compare it against a bundle")
    check_parser.add_argument("bundle", help="bundle directory produced by export")
    check_parser.set_defaults(handler=command_check)

    # Both secrets are opt-in at both ends: an operator who does not intend to migrate the API
    # users should not end up moving every password hash to another host either.
    for subparser in (export_parser, import_parser):
        subparser.add_argument("--with-password", action="store_true",
                               help="include etc/authd.pass, the shared enrollment password")
        subparser.add_argument("--with-rbac", action="store_true",
                               help="include the API users, roles and policies (password hashes)")
        subparser.add_argument("--dry-run", action="store_true",
                               help="report what would happen and change nothing")
        subparser.add_argument("--force", action="store_true",
                               help="proceed past the safety checks")

    for subparser in (import_parser, check_parser):
        subparser.add_argument("--target-dir", default=DEFAULT_TARGET_DIR,
                               help="5.0 installation directory (default: %(default)s)")
        subparser.add_argument("--api-url", default=DEFAULT_API_URL,
                               help="manager API (default: %(default)s)")
        subparser.add_argument("--api-user", default="wazuh",
                               help="API user (default: %(default)s)")
        subparser.add_argument("--api-password-file",
                               help="file holding the API password, or '-' for standard input."
                                    " WAZUH_API_PASSWORD is read when this is not given")
        subparser.add_argument("--api-ca",
                               help="CA bundle to verify the API certificate with. Without it the"
                                    " connection to the default loopback address is not verified")

    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.handler(args)
    except MigrationError as error:
        print("error: %s" % error, file=sys.stderr)
        return 2
    except PermissionError as error:
        print("error: %s. Run as root." % error, file=sys.stderr)
        return 2
    except (sqlite3.Error, ValueError) as error:
        # A truncated manifest (json raises ValueError) or an unreadable database. Exit 2, not 1:
        # 1 is reserved for 'check found problems', and this is a refusal.
        print("error: %s." % error, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
