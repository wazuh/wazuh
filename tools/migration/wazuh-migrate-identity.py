#!/usr/bin/env python3
# Copyright (C) Wazuh Inc.
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
import ipaddress
import json
import os
import pwd
import re
import shutil
import sqlite3
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ElementTree

TOOL_VERSION = "3.0.0"
BUNDLE_VERSION = 3
# Bundles this tool still imports and checks. A version 2 bundle predates the default group's
# configuration and the SCA policy files: it is accepted, and the import says what it lacks.
BUNDLE_VERSIONS_ACCEPTED = (2, 3)

DEFAULT_SOURCE_DIR = "/var/ossec"
DEFAULT_TARGET_DIR = "/var/wazuh-manager"
# A 5.0 manager keeps its configuration in a fixed directory outside the installation home.
DEFAULT_TARGET_CONF_DIR = "/etc/wazuh-manager"
DEFAULT_API_URL = "https://localhost:55000"

# The CA the manager issued apid.pem from at install, relative to the 5.0 configuration directory.
# The default trust anchor for --api-ca: apid.pem carries localhost, 127.0.0.1 and ::1 among its SANs.
TARGET_ROOT_CA = os.path.join("certs", "root-ca.pem")

# Where a 5.0 manager publishes the Server API password it generated at install (#39554): the
# credential resolver writes it to export/credentials.env in the configuration directory, root-only
# (#40339). Read as data, never sourced; the last assignment of the key wins, as the manager's own
# reader does.
CREDENTIALS_ENV = "/etc/wazuh-manager/export/credentials.env"
CREDENTIALS_KEY = "WAZUH_MANAGER_API_PASSWORD"

# 4.x stamps PRAGMA user_version 0 and tracks its own schema in metadata.db_version. Only the
# revisions whose agent table this reader has been checked against are accepted.
SOURCE_DB_VERSIONS_CHECKED = (7, 8, 9, 10, 11, 12)

# Group folders the target ships itself: recreating them would replace 5.0 content. The default
# group's 4.x configuration is merged into the target's instead (see merge_default_group()).
RESERVED_GROUPS = ("default",)
DEFAULT_GROUP = "default"

# Top-level agent.conf settings a 5.0 agent ignores, each with what to do instead. Mirrors
# OBSOLETE_ELEMENTS and the client_buffer case of read_main_elements() in src/config/src/config.c:
# keep the two in step. The agent only logs them, so the export is where an operator can still
# hear about them before the fleet does.
REMOVED_AGENT_SETTINGS = {
    "agent-key-polling": "The agent key polling module was removed in 5.0.0.",
    "agentless": "The wazuh-agentlessd daemon was removed in 5.0.0.",
    "alerts": "Alert output is not configured in the configuration file.",
    "client_buffer": "Event batching is configured under <agent><batch>.",
    "command": "Active Response commands are not defined in the configuration file.",
    "database_output": "The wazuh-dbd daemon was removed in 5.0.0.",
    "email_alerts": "The wazuh-maild daemon was removed in 5.0.0.",
    "fluent-forward": "The fluent forwarder module was removed in 5.0.0.",
    "integration": "The wazuh-integratord daemon was removed in 5.0.0.",
    "labels": "Agent labels were removed in 5.0.0, so agent.labels.* no longer reaches events, rules"
              " or dashboards. Group membership (wazuh.agent.groups in every event) is the closest"
              " replacement: put the agents that shared a label in a group.",
    "reports": "The wazuh-reportd daemon was removed in 5.0.0.",
    "rule_test": "Rule testing is provided by the engine.",
    "ruleset": "Rules and decoders are managed by the engine.",
    "syslog_output": "The wazuh-csyslogd daemon was removed in 5.0.0.",
}

# 4.x manager features that stop at cutover, by the ossec.conf element that configures them, with
# what stops and the guide (docs/guide/migration/) that rebuilds it. The configuration itself is
# not migrated by this tool, but the export is the last point where they can be listed before the
# 4.x manager is gone. Mirrors the table "Sections to remove" in
# docs/guide/migration/manager-configuration-migration.md.
REMOVED_MANAGER_FEATURES = (
    ("integration", "integrations (Slack, PagerDuty, VirusTotal...) stop: the integrations daemon"
                    " was removed", "Integratord to notifications plugin"),
    ("email_alerts", "email alerts stop", "Mail forwarding and reporting"),
    ("reports", "email reports stop", "Mail forwarding and reporting"),
    ("syslog_output", "alert forwarding to syslog stops", "Remote syslog output"),
    ("agentless", "agentless monitoring stops", "Agentless to supported alternatives"),
    ("active-response", "active responses stop until they are rebuilt; 4.x agents never get one",
                        "Active Response"),
    ("open-scap", "OpenSCAP scans stop", "CIS-CAT/OpenSCAP to SCA migration"),
    ("cis-cat", "CIS-CAT scans stop", "CIS-CAT/OpenSCAP to SCA migration"),
    ("syslog", "the manager stops receiving syslog from network devices (<remote> syslog"
               " connection)", "Migrating Syslog Input to Logcollector with rsyslog"),
)
# What a 4.x manager collected from its own host as agent 000, which 5.0 removed.
SELF_MONITORING = ("localfile", "syscheck", "rootcheck", "wodle:syscollector", "sca")

# A group's SCA policy files are carried: no endpoint uploads them, but they are what the group's
# agent.conf loads, and 5.0 agents still run them. Installed like the agent.conf the API writes.
GROUP_FILE_OWNER = ("wazuh-manager", "wazuh-manager", 0o660)

# What a 4.x installation ships in shared/default besides agent.conf: the rootcheck lists and audit
# policies (rootkit_files.txt, system_audit_rcl.txt, win_audit_rcl.txt, cis_*_rcl.txt...).
STOCK_DEFAULT_FILES = re.compile(r"^(rootkit_\w+\.txt|system_audit_\w+\.txt|win_\w+_rcl\.txt|cis_\w+_rcl\.txt)$")

# The two credentials no endpoint can express, so they stay file copies. Both are opt-in.
#   key: bundle name -> (source relative path, target root, target relative path, owner, group, mode)
# The source path is relative to the 4.x installation. The target root names what the target path is
# relative to: TARGET_CONF for the 5.0 configuration directory, TARGET_HOME for the 5.0 installation.
# Both belong to the service account: authd creates authd.pass itself and the API rewrites
# rbac.db, each after dropping privileges.
TARGET_CONF = "conf"
TARGET_HOME = "home"
SECRET_FILES = {
    "authd.pass": ("etc/authd.pass", TARGET_CONF, "authd.pass",
                   "wazuh-manager", "wazuh-manager", 0o640),
    "rbac.db": ("api/configuration/security/rbac.db", TARGET_HOME, "api/configuration/security/rbac.db",
                "wazuh-manager", "wazuh-manager", 0o640),
}


class MigrationError(Exception):
    """A condition the operator has to resolve; reported without a traceback."""


# The shortest authd.pass the 5.0 manager accepts: AUTHD_PASS_MIN_BYTES in src/os_auth/include/auth.h. A
# shorter one stops wazuh-manager-authd at start, so it is refused here before it reaches the manager.
AUTHD_PASS_MIN_BYTES = 16


def authd_pass_too_short(path):
    """True when the first line of the password file, CR/LF trimmed, is shorter than the 5.0 minimum.
    Empty and blank lines are left to authd's own error: they were never valid."""
    with open(path, "rb") as handle:
        line = handle.readline().rstrip(b"\r\n")
    return bool(line.strip()) and len(line) < AUTHD_PASS_MIN_BYTES


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

    def __init__(self, url, user, password, ca_path):
        self.url = url.rstrip("/")
        self.user = user
        self.password = password
        self.token = None
        # Always verified, chain and hostname: this connection carries the superuser password and
        # every imported agent key. resolve_api_ca() decides which CA, and refuses when none fits.
        self.context = None
        if ca_path:
            try:
                self.context = ssl.create_default_context(cafile=ca_path)
            except (ssl.SSLError, OSError) as error:
                raise MigrationError("cannot load the CA bundle %s: %s" % (ca_path, error))

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
                text = response.read().decode()
                if "json" not in (response.headers.get("Content-Type") or "application/json"):
                    # A group file read with raw=true comes back as the file it is.
                    return {"__raw": text}
                return json.loads(text or "{}")
        except urllib.error.HTTPError as error:
            payload = error.read().decode(errors="replace")
            try:
                return {"__status": error.code, **json.loads(payload)}
            except ValueError:
                return {"__status": error.code, "title": error.reason, "detail": payload[:200]}
        except urllib.error.URLError as error:
            if isinstance(error.reason, ssl.SSLCertVerificationError):
                raise MigrationError(
                    "the manager API at %s presented a certificate that does not verify: %s."
                    " Pass --api-ca with the CA that issued it, and an --api-url whose host the"
                    " certificate names." % (self.url, error.reason.verify_message or error.reason))
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


def is_loopback(host):
    """True for localhost and any loopback address, the only hosts a connection never leaves."""
    if not host:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def resolve_api_ca(args):
    """The CA to verify the manager API with, or None for a plain-HTTP loopback URL.

    The password and the agent keys this tool sends are worth an on-path attacker's while, so the
    connection is never left unverified. Without --api-ca it trusts the target's own root-ca.pem,
    which issued apid.pem, and only for a loopback --api-url: a remote API is verified against a CA
    the operator names, never against a file that merely sits on this host.
    """
    parts = urllib.parse.urlsplit(args.api_url)
    if parts.scheme not in ("https", "http"):
        raise MigrationError("--api-url %s is not an http(s) URL" % args.api_url)
    loopback = is_loopback(parts.hostname)
    if parts.scheme == "http":
        if not loopback:
            raise MigrationError(
                "--api-url %s would send the API password and the agent keys in clear. Use"
                " https, or run the tool on the manager against its loopback address."
                % args.api_url)
        return None
    if args.api_ca:
        if not os.path.isfile(args.api_ca):
            raise MigrationError("--api-ca %s is not a file" % args.api_ca)
        return args.api_ca
    if not loopback:
        raise MigrationError(
            "--api-url %s is not a loopback address, so --api-ca is required: name the CA that"
            " issued the API certificate (on that manager, %s)."
            % (args.api_url, os.path.join(DEFAULT_TARGET_CONF_DIR, TARGET_ROOT_CA)))
    ca_path = os.path.join(args.target_conf_dir, TARGET_ROOT_CA)
    if not os.path.isfile(ca_path):
        raise MigrationError(
            "%s is missing, so the API certificate cannot be verified. Pass --api-ca with the CA"
            " that issued it." % ca_path)
    return ca_path


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


def parse_agent_conf(text):
    """(top-level setting names, SCA policy paths) of an agent.conf, or None if it does not parse.

    An agent.conf is a sequence of <agent_config> elements rather than one XML document, so it is
    parsed inside a wrapper. Comments are dropped by the parser, so a commented-out example is not
    mistaken for a setting.
    """
    body = re.sub(r"^\s*<\?xml[^>]*\?>", "", text or "")
    try:
        root = ElementTree.fromstring("<migration-wrapper>%s</migration-wrapper>" % body)
    except ElementTree.ParseError:
        return None
    settings, policies = [], []
    for block in root.iter("agent_config"):
        for child in block:
            if child.tag not in settings:
                settings.append(child.tag)
            if child.tag == "sca":
                for policy in child.iter("policy"):
                    if policy.text and policy.text.strip():
                        policies.append(policy.text.strip())
    return settings, policies


def sca_policy_names(policies, entries):
    """The entries of a group folder that one of the group's SCA <policy> paths loads.

    A group's files land in the agent's shared directory (etc/shared/ on Linux and macOS, shared\\ on
    Windows), so a policy shipped with the group is named by that directory and its file name.
    """
    wanted = set()
    for policy in policies:
        directory, _, name = policy.replace("\\", "/").rpartition("/")
        if directory.rstrip("/").split("/")[-1] == "shared":
            wanted.add(name)
    return [entry for entry in entries if entry in wanted]


def read_group_folder(folder):
    """{agent_conf, sca_policies, extra_files} of one group folder."""
    agent_conf, files = None, []
    for entry in sorted(os.listdir(folder)):
        path = os.path.join(folder, entry)
        if not os.path.isfile(path) or entry == "merged.mg":
            continue  # merged.mg is compiled by the manager from everything else here
        if entry == "agent.conf":
            with open(path, errors="replace") as handle:
                agent_conf = handle.read()
        else:
            files.append(entry)
    parsed = parse_agent_conf(agent_conf) if agent_conf is not None else None
    policies = sca_policy_names(parsed[1], files) if parsed else []
    return {"agent_conf": agent_conf, "sca_policies": policies,
            "extra_files": [entry for entry in files if entry not in policies]}


def read_groups(shared_dir, known_names):
    """Returns [{name, agent_conf, sca_policies, extra_files}] for every custom group folder."""
    groups = []
    if not os.path.isdir(shared_dir):
        return groups
    for name in sorted(os.listdir(shared_dir)):
        folder = os.path.join(shared_dir, name)
        if not os.path.isdir(folder) or os.path.islink(folder) or name in RESERVED_GROUPS:
            continue
        groups.append(dict(name=name, **read_group_folder(folder)))
    for name in sorted(known_names - {g["name"] for g in groups} - set(RESERVED_GROUPS)):
        # Recorded in the registry but with no folder: still a group agents belong to.
        groups.append({"name": name, "agent_conf": None, "sca_policies": [], "extra_files": []})
    return groups


def is_customized(agent_conf):
    """True when an agent.conf sets anything: the stock 4.x and 5.0 files hold only comments and
    empty <agent_config> elements. One that does not parse is treated as customized, so it is
    carried and reported rather than silently judged empty."""
    if agent_conf is None:
        return False
    parsed = parse_agent_conf(agent_conf)
    return parsed is None or bool(parsed[0])


def read_default_group(shared_dir):
    """The 4.x default group, or None when it holds nothing the 5.0 one lacks."""
    folder = os.path.join(shared_dir, DEFAULT_GROUP)
    if not os.path.isdir(folder) or os.path.islink(folder):
        return None
    group = read_group_folder(folder)
    # The rootcheck files every 4.x installation ships in default: not operator content.
    group["extra_files"] = [entry for entry in group["extra_files"]
                            if not STOCK_DEFAULT_FILES.match(entry)]
    group["customized"] = is_customized(group["agent_conf"])
    if not group["customized"]:
        group["agent_conf"] = None  # the stock file: the 5.0 default replaces it as is
    return dict(name=DEFAULT_GROUP, **group)


def review_lines(manifest):
    """What will not work the same on 5.0, per group: the settings its agents ignore and the files
    left behind. Printed by the export (dry run included) and again by the import, once each."""
    lines = []
    groups = list(manifest["groups"])
    default = manifest.get("default_group")
    if default:
        groups = [default] + groups
    for group in groups:
        name = group["name"]
        if group.get("agent_conf") is not None:
            parsed = parse_agent_conf(group["agent_conf"])
            if parsed is None:
                lines.append("group '%s': agent.conf is not well-formed XML; it is carried as is, and"
                             " the 5.0 manager will refuse it at import." % name)
            else:
                for setting in parsed[0]:
                    if setting in REMOVED_AGENT_SETTINGS:
                        lines.append("group '%s': <%s> is ignored by 5.0 agents. %s"
                                     % (name, setting, REMOVED_AGENT_SETTINGS[setting]))
        if group.get("extra_files"):
            lines.append("group '%s': %s not migrated. 5.0 pushes every file in a group folder to its"
                         " agents, and a 4.x CDB list or rootcheck file has no use there. Copy any you"
                         " still need into the group on the 5.0 manager."
                         % (name, ", ".join(group["extra_files"])))
        if group.get("sca_policies"):
            lines.append("group '%s': SCA %s %s carried: the group's agent.conf loads %s, and 5.0"
                         " agents still run %s."
                         % (name, "policy" if len(group["sca_policies"]) == 1 else "policies",
                            ", ".join(group["sca_policies"]),
                            "it" if len(group["sca_policies"]) == 1 else "them",
                            "it" if len(group["sca_policies"]) == 1 else "them"))
    if default and default.get("customized"):
        lines.append("group 'default': its 4.x agent.conf is customized and is appended to the 5.0"
                     " default group's agent.conf at import, so every agent keeps it.")
    return lines + list(manifest.get("manager_review") or [])


def manager_review(ossec_conf):
    """What the 4.x manager did that 5.0 does not, read from its ossec.conf: a list of lines.

    Only configured, enabled features count: a block with <disabled>yes</disabled> (or <enabled>no)
    did nothing on 4.x either, and the 4.x default file ships some that way.
    """
    if not os.path.isfile(ossec_conf):
        return []
    with open(ossec_conf, errors="replace") as handle:
        text = re.sub(r"^\s*<\?xml[^>]*\?>", "", handle.read())
    try:
        root = ElementTree.fromstring("<migration-wrapper>%s</migration-wrapper>" % text)
    except ElementTree.ParseError:
        return ["4.x ossec.conf: not well-formed XML, so the features it configures could not be"
                " listed. Read it against the manager configuration migration guide."]

    def enabled(element):
        disabled = (element.findtext("disabled") or "").strip().lower()
        flag = (element.findtext("enabled") or "").strip().lower()
        return disabled not in ("yes", "true") and flag not in ("no", "false")

    found, self_monitoring = {}, []
    for block in root.iter("ossec_config"):
        for child in block:
            key = child.tag
            if child.tag == "wodle":
                key = child.get("name", "")
                if key == "syscollector" and enabled(child):
                    self_monitoring.append("wodle:syscollector")
            if child.tag == "remote" and (child.findtext("connection") or "").strip() == "syslog":
                key = "syslog"
            if child.tag == "active-response" and child.find("command") is None:
                continue  # the 4.x global settings block, which configures no response
            if child.tag in SELF_MONITORING and enabled(child):
                self_monitoring.append(child.tag)
            if enabled(child):
                found[key] = found.get(key, 0) + 1
    lines = []
    for key, what, guide in REMOVED_MANAGER_FEATURES:
        if key in found:
            lines.append("4.x ossec.conf: %s (%d block(s)). See the migration guide \"%s\"."
                         % (what, found[key], guide))
    if self_monitoring:
        lines.append("4.x ossec.conf: the manager monitored its own host (%s). 5.0 has no agent 000;"
                     " install an agent on the server host to keep it."
                     % ", ".join(sorted(set(m.split(":")[-1] for m in self_monitoring))))
    return lines


def print_review(manifest):
    lines = review_lines(manifest)
    if not lines:
        return
    log("")
    log("Review before going on (%d item(s)):" % len(lines))
    for line in lines:
        log("  - %s" % line)


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

    shared_dir = os.path.join(source, "etc", "shared")
    groups = read_groups(shared_dir, known_groups)
    default_group = read_default_group(shared_dir)
    payload = [dict(id=agent_id, **data) for agent_id, data in sorted(agents.items())]

    log("  agents   %d" % len(payload))
    log("  groups   %d (%s)" % (len(groups), ", ".join(g["name"] for g in groups) or "none"))
    log("  default  %s" % ("customized agent.conf, merged at import"
                           if default_group and default_group["customized"]
                           else "stock, nothing to carry"))

    secrets = []
    for name, (relative, _, _, _, _, _) in SECRET_FILES.items():
        asked = args.with_password if name == "authd.pass" else args.with_rbac
        path = os.path.join(source, relative)
        if not asked:
            log("  skip     %s (--with-%s not given)"
                % (name, "password" if name == "authd.pass" else "rbac"))
        elif not os.path.isfile(path):
            log("  skip     %s (not present on the source)" % name)
        else:
            if name == "authd.pass" and authd_pass_too_short(path):
                warn("the 4.x enrollment password is shorter than %d bytes, the minimum the 5.0"
                     " manager accepts: 'import' will refuse it. Set a longer one on the 4.x manager"
                     " and on the agents that still enroll, and export again." % AUTHD_PASS_MIN_BYTES)
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
        "default_group": default_group,
        "manager_review": manager_review(os.path.join(source, "etc", "ossec.conf")),
        "secrets": [name for name, _ in secrets],
    }
    print_review(manifest)

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

    for group in ([default_group] if default_group else []) + groups:
        if not group["sca_policies"]:
            continue
        folder = os.path.join(args.bundle, "groups", group["name"])
        os.makedirs(folder, mode=0o700, exist_ok=True)
        for name in group["sca_policies"]:
            shutil.copy2(os.path.join(shared_dir, group["name"], name), os.path.join(folder, name))
            os.chmod(os.path.join(folder, name), 0o600)
            log("  export   %s/%s (SCA policy)" % (group["name"], name))

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
    if manifest.get("bundle_version") not in BUNDLE_VERSIONS_ACCEPTED:
        raise MigrationError("bundle version %s is not supported by this tool (expected %s)."
                             % (manifest.get("bundle_version"),
                                " or ".join(str(v) for v in BUNDLE_VERSIONS_ACCEPTED)))
    for field in ("agents", "groups"):
        if not isinstance(manifest.get(field), list):
            raise MigrationError("the manifest has no '%s' list; the bundle is incomplete."
                                 % field)
    if manifest["bundle_version"] < 3:
        warn("this bundle was exported by tool version %s, which carried neither the default"
             " group's agent.conf nor the groups' SCA policy files. If the 4.x manager still exists,"
             " export again with this version; otherwise merge shared/default/agent.conf and copy"
             " the policies by hand." % manifest.get("tool_version", "2.x"))
    for group in manifest["groups"]:
        group.setdefault("sca_policies", [])
        group.setdefault("extra_files", [])
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


def install_group_files(bundle, group, target_conf_dir, dry_run):
    """The group's SCA policy files, which no endpoint uploads. Installed before its agent.conf,
    which loads them, so the agents never receive one without the other."""
    for name in group.get("sca_policies", []):
        source = os.path.join(bundle, "groups", group["name"], name)
        destination = os.path.join(target_conf_dir, "shared", group["name"], name)
        log("  file     %-20s %s (SCA policy)" % (group["name"], name))
        if dry_run:
            continue
        if not os.path.isfile(source):
            raise MigrationError("'%s' is missing from the bundle; the bundle is incomplete." % source)
        if not os.path.isdir(os.path.dirname(destination)):
            raise MigrationError("'%s' does not exist; is '%s' a 5.0 configuration directory?"
                                 % (os.path.dirname(destination), target_conf_dir))
        owner, group_name, mode = GROUP_FILE_OWNER
        shutil.copyfile(source, destination)
        os.chmod(destination, mode)
        try:
            os.chown(destination, pwd.getpwnam(owner).pw_uid, grp.getgrnam(group_name).gr_gid)
        except KeyError:
            warn("user '%s' or group '%s' does not exist; ownership of '%s' left unchanged."
                 % (owner, group_name, destination))


def import_groups(api, manifest, already_present, bundle, target_conf_dir, dry_run):
    created = 0
    for group in manifest["groups"]:
        name = group["name"]
        if name in already_present:
            log("  group    %-20s exists already, configuration left alone" % name)
            continue
        log("  group    %-20s create%s" % (name, " + agent.conf" if group["agent_conf"] else ""))
        if not dry_run:
            api.require("POST", "/groups", {"group_id": name}, "creating group '%s'" % name)
            created += 1
        install_group_files(bundle, group, target_conf_dir, dry_run)
        if group["agent_conf"] and not dry_run:
            api.require("PUT", "/groups/%s/configuration" % name, group["agent_conf"],
                        "uploading the configuration of group '%s'" % name,
                        content_type="application/xml")
    return created


DEFAULT_MERGE_MARK = "<!-- Carried from the 4.x default group by wazuh-migrate-identity -->"


def read_group_conf(api, name):
    """The group's agent.conf as the manager holds it."""
    answer = api.require("GET", "/groups/%s/files/agent.conf?raw=true" % name,
                         what="reading the configuration of group '%s'" % name)
    return answer.get("__raw", "")


def merge_default_group(api, manifest, bundle, target_conf_dir, dry_run):
    """Appends the 4.x default group's settings to the 5.0 one's.

    The default group is the target's own, so it is never recreated, but a customized 4.x one holds
    what applied to the whole fleet. Its <agent_config> elements are added after the 5.0 file's,
    which keeps both: the 5.0 file holds comments and an empty element. A second import finds the
    4.x text already there and leaves the file alone.
    """
    default = manifest.get("default_group")
    if not default or not default.get("customized"):
        return None
    install_group_files(bundle, default, target_conf_dir, dry_run)
    carried = default["agent_conf"].strip()
    current = read_group_conf(api, DEFAULT_GROUP)
    if carried in current:
        log("  group    %-20s 4.x agent.conf already merged" % DEFAULT_GROUP)
        return None
    log("  group    %-20s merge the 4.x agent.conf after the 5.0 one" % DEFAULT_GROUP)
    if dry_run:
        return None
    merged = "%s\n\n%s\n%s\n" % (current.rstrip(), DEFAULT_MERGE_MARK, carried)
    ok, answer = api.request("PUT", "/groups/%s/configuration" % DEFAULT_GROUP, merged,
                             content_type="application/xml")
    # Not fatal: the agents and their memberships do not depend on it. Reported with the others.
    return None if ok else describe_api_error(answer)


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


def expected_groups(agent):
    """The groups an agent must end up in, in priority order. The manager puts an agent that
    belongs to no group in default, as 4.x did."""
    return list(agent.get("groups") or [DEFAULT_GROUP])


def import_memberships(api, manifest, inserted, dry_run):
    """Gives each agent exactly its 4.x groups, in the 4.x priority order.

    The manager inserts every agent in default. When the agent's first 4.x group is another one,
    it replaces default (force_single_group); the rest are appended in order, default included
    wherever 4.x had it. So an agent that was not in default does not end up there.
    """
    assigned, failed = 0, []
    for agent in manifest["agents"]:
        if agent["id"] not in inserted:
            continue  # it is not there to assign; its insertion failure is reported already
        for position, group in enumerate(expected_groups(agent)):
            if position == 0 and group == DEFAULT_GROUP:
                continue  # where the manager put it
            path = "/agents/%03d/group/%s" % (agent["id"], group)
            if position == 0:
                path += "?force_single_group=true"
            if dry_run:
                assigned += 1
                continue
            ok, answer = api.request("PUT", path)
            if ok:
                assigned += 1
            else:
                failed.append((agent, group, describe_api_error(answer)))
                if position == 0:
                    break  # appending the rest would leave it in default after all
    return assigned, failed


def install_secret(bundle, name, target_dir, target_conf_dir, dry_run):
    """The two credentials no endpoint can express."""
    _, root, relative, owner, group, mode = SECRET_FILES[name]
    source = os.path.join(bundle, name)
    base = target_conf_dir if root == TARGET_CONF else target_dir
    destination = os.path.join(base, relative)
    if not os.path.isdir(os.path.dirname(destination)):
        raise MigrationError("'%s' does not exist; is '%s' a 5.0 %s?"
                             % (os.path.dirname(destination), base,
                                "configuration directory" if root == TARGET_CONF else "installation"))

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
    the defaults, gives user 2 its 5.0 name (`wazuh-internal-client`, keeping its password) and
    migrates across the users, roles and policies an operator created.
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
    ca_path = resolve_api_ca(args)

    api = ManagerApi(args.api_url, args.api_user, read_api_password(args), ca_path)
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

    import_groups(api, manifest, already_present, args.bundle, args.target_conf_dir, args.dry_run)
    default_failure = merge_default_group(api, manifest, args.bundle, args.target_conf_dir,
                                          args.dry_run)
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
        if name == "authd.pass" and authd_pass_too_short(os.path.join(args.bundle, name)):
            raise MigrationError(
                "the enrollment password in the bundle is shorter than %d bytes, and the 5.0"
                " wazuh-manager-authd refuses to start with it. Set a longer password on the 4.x"
                " manager and on the agents that still enroll, then export again; or re-run without"
                " --with-password to let the manager generate a new one." % AUTHD_PASS_MIN_BYTES)
        install_secret(args.bundle, name, target, args.target_conf_dir, args.dry_run)
        if name == "rbac.db":
            stage_rbac(target, args.dry_run)
            if os.path.isfile(CREDENTIALS_ENV):
                # The manager never reseeds an existing rbac.db, so from the next start both
                # Server API users carry their 4.x passwords, while the file still holds the values
                # the install generated and handed to the dashboard. Two records, one true.
                warn("from the next start the 'wazuh' and 'wazuh-internal-client' passwords are the 4.x ones"
                     " carried in rbac.db; %s and WAZUH_MANAGER_WUI_PASSWORD in %s no longer"
                     " match them, and a dashboard installed with that value cannot log in."
                     " Either set both users back to the published values with"
                     " 'rbac_control change-password' after the restart, or update the dashboard"
                     " and pass --api-password-file to 'check'."
                     % (CREDENTIALS_KEY, CREDENTIALS_ENV))

    print_review(manifest)
    log("")
    if args.dry_run:
        log("Dry run complete. Re-run without --dry-run to apply.")
        return 0

    for agent, reason in agent_failures:
        warn("agent %03d (%s) was not inserted: %s" % (agent["id"], agent["name"], reason))
    for agent, group, reason in membership_failures:
        warn("agent %03d (%s) was not added to '%s': %s"
             % (agent["id"], agent["name"], group, reason))
    if default_failure:
        warn("the 4.x settings of the default group were not merged: %s. Fix the file in the bundle"
             " (default_group in manifest.json) or merge it by hand." % default_failure)

    log("Inserted %d of %d agent(s), %d group membership(s)."
        % (len(inserted), len(manifest["agents"]), assigned))
    if agent_failures or membership_failures or default_failure:
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
    ca_path = resolve_api_ca(args)
    api = ManagerApi(args.api_url, args.api_user, read_api_password(args), ca_path)
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
        want = expected_groups(expected[agent_id])
        have = list(installed[agent_id].get("group") or [])
        if set(want) - set(have):
            problems.append("agent %03d is not in %s."
                            % (agent_id, ", ".join(sorted(set(want) - set(have)))))
        if set(have) - set(want):
            problems.append("agent %03d is also in %s, which the bundle did not carry for it."
                            % (agent_id, ", ".join(sorted(set(have) - set(want)))))
        if set(want) == set(have) and want != have:
            problems.append("agent %03d has its groups in the order %s, the bundle carried %s: the"
                            " order decides which group's setting wins."
                            % (agent_id, ", ".join(have), ", ".join(want)))
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

    default = manifest.get("default_group")
    if default and default.get("customized"):
        merged = default["agent_conf"].strip() in read_group_conf(api, DEFAULT_GROUP)
        log("default   4.x agent.conf %s" % ("merged" if merged else "NOT merged"))
        if not merged:
            problems.append("the default group's agent.conf does not hold the 4.x settings the"
                            " bundle carried.")
    for group in ([default] if default else []) + manifest["groups"]:
        for name in group.get("sca_policies", []):
            if not os.path.isfile(os.path.join(args.target_conf_dir, "shared", group["name"], name)):
                problems.append("group '%s' lacks its SCA policy %s." % (group["name"], name))

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
        subparser.add_argument("--target-conf-dir", default=DEFAULT_TARGET_CONF_DIR,
                               help="5.0 configuration directory, which holds authd.pass and"
                                    " certs/root-ca.pem (default: %(default)s)")
        subparser.add_argument("--api-url", default=DEFAULT_API_URL,
                               help="manager API (default: %(default)s)")
        subparser.add_argument("--api-user", default="wazuh",
                               help="API user (default: %(default)s)")
        subparser.add_argument("--api-password-file",
                               help="file holding the API password, or '-' for standard input."
                                    " WAZUH_API_PASSWORD is read when this is not given")
        subparser.add_argument("--api-ca",
                               help="CA bundle to verify the API certificate with. Required for a"
                                    " non-loopback --api-url; a loopback one defaults to the"
                                    " target's <--target-conf-dir>/%s" % TARGET_ROOT_CA)

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
