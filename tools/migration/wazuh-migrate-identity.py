#!/usr/bin/env python3
# Copyright (C) 2015, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

"""Carry a 4.x manager's agent identity data into a fresh 5.0 installation.

A 4.x manager cannot be upgraded in place, and a 5.0 installation starts empty. Everything that
identifies the fleet -- agent keys, the agent registry, group membership, the enrollment password
and the API users -- has to be moved by hand, with per-file ownership rules and a schema transform
for the registry. This performs that move.

  export  on the 4.x manager, collect the data into a bundle
  import  on the 5.0 manager, restore the bundle
  check   on the 5.0 manager, compare what is installed against the bundle

Both managers must be stopped: the files are read and written underneath running daemons otherwise.
Standard library only, so it runs on the 4.x host without installing anything.
"""

import argparse
import contextlib
import errno
import grp
import hashlib
import json
import os
import pwd
import shutil
import sqlite3
import sys
import tarfile
import time

TOOL_VERSION = "1.0.0"
BUNDLE_VERSION = 1

DEFAULT_SOURCE_DIR = "/var/ossec"
DEFAULT_TARGET_DIR = "/var/wazuh-manager"

# The 5.0 schema the transform below was written against. wazuh-db refuses anything outside
# 1..N, so a target stamped differently means this tool predates the installed manager.
SUPPORTED_TARGET_USER_VERSION = (1,)
# 4.x stamps PRAGMA user_version 0 and tracks its own schema in metadata.db_version. Only the
# revisions whose agent table this transform has been checked against are accepted.
SOURCE_DB_VERSIONS_CHECKED = (7, 8, 9, 10, 11, 12)

# Group folders the target ships itself: restoring the 4.x copy would replace 5.0 content.
RESERVED_GROUPS = ("default",)

# Files carried verbatim, with the ownership and mode a 5.0 installation ships for each.
#   key: bundle name
#   value: (target relative path, owner, group, mode, required)
# All three belong to the service account: authd reopens client.keys for append and creates
# authd.pass itself, both after dropping privileges, and the API rewrites rbac.db as that user.
# Modes follow the installer (client.keys 0660, inst-functions.sh) and the daemons' own umask.
PLAIN_FILES = {
    "client.keys": ("etc/client.keys", "wazuh-manager", "wazuh-manager", 0o660, True),
    "authd.pass": ("etc/authd.pass", "wazuh-manager", "wazuh-manager", 0o640, False),
    "rbac.db": ("api/configuration/security/rbac.db", "wazuh-manager", "wazuh-manager", 0o640, False),
}

SOURCE_PATHS = {
    "client.keys": "etc/client.keys",
    "authd.pass": "etc/authd.pass",
    "rbac.db": "api/configuration/security/rbac.db",
    "global.db": "queue/db/global.db",
    "shared": "etc/shared",
}


class MigrationError(Exception):
    """A condition the operator has to resolve; reported without a traceback."""


def log(message):
    print(message)


def warn(message):
    print("WARNING: %s" % message, file=sys.stderr)


# --------------------------------------------------------------------------------------
# environment checks
# --------------------------------------------------------------------------------------

def read_version(install_dir):
    """Returns the installation's version string, or None when it cannot be determined."""
    version_json = os.path.join(install_dir, "VERSION.json")
    if os.path.isfile(version_json):
        try:
            with open(version_json) as handle:
                return json.load(handle).get("version")
        except (ValueError, OSError):
            return None

    version_file = os.path.join(install_dir, "VERSION")
    if os.path.isfile(version_file):
        try:
            with open(version_file) as handle:
                return handle.read().strip()
        except OSError:
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


def running_daemons(install_dir):
    """Returns the pid files found under var/run, which is how both versions mark a live manager."""
    run_dir = os.path.join(install_dir, "var", "run")
    if not os.path.isdir(run_dir):
        return []
    try:
        return sorted(name for name in os.listdir(run_dir) if name.endswith(".pid"))
    except OSError:
        return []


def assert_stopped(install_dir, force):
    daemons = running_daemons(install_dir)
    if not daemons:
        return
    message = ("the manager at '%s' looks like it is running (%d pid file(s) under var/run)."
               % (install_dir, len(daemons)))
    if force:
        warn(message + " Continuing because --force was given.")
        return
    raise MigrationError(message + " Stop it first, or pass --force if you know it is down.")


def assert_master(install_dir, force):
    """A worker's registry and keys come from the master; importing into one diverges the cluster."""
    for name in ("etc/wazuh-manager.conf", "etc/ossec.conf"):
        path = os.path.join(install_dir, name)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, errors="replace") as handle:
                content = handle.read()
        except OSError:
            continue
        lowered = content.lower().replace(" ", "")
        if "<node_type>worker</node_type>" in lowered:
            message = "'%s' is configured as a cluster worker." % install_dir
            if force:
                warn(message + " Continuing because --force was given.")
                return
            raise MigrationError(
                message + " Import into the master and let the cluster distribute it,"
                          " or pass --force.")
        return


def resolve_ownership(owner, group):
    """Returns (uid, gid), or (None, None) when the accounts do not exist (non-root dry runs)."""
    try:
        return pwd.getpwnam(owner).pw_uid, grp.getgrnam(group).gr_gid
    except KeyError:
        return None, None


# --------------------------------------------------------------------------------------
# bundle helpers
# --------------------------------------------------------------------------------------

def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sqlite_backup(source, destination):
    """Copies a database through the backup API, so a journal left beside it cannot be missed."""
    with contextlib.closing(sqlite3.connect("file:%s?mode=ro" % source, uri=True)) as src:
        with contextlib.closing(sqlite3.connect(destination)) as dst:
            src.backup(dst)


def open_ro(path):
    """A read-only connection that closes on leaving its `with` block.

    sqlite3's own context manager commits a transaction and leaves the handle open, which on a
    tool that opens several databases per run leaks descriptors.
    """
    return contextlib.closing(sqlite3.connect("file:%s?mode=ro" % path, uri=True))


def table_columns(connection, table):
    return [row[1] for row in connection.execute("PRAGMA table_info(`%s`)" % table)]


def source_db_version(connection):
    """4.x keeps its schema revision in metadata; returns None when the table is absent."""
    try:
        row = connection.execute(
            "SELECT value FROM metadata WHERE key = 'db_version'").fetchone()
    except sqlite3.Error:
        return None
    if not row:
        return None
    return int(row[0]) if str(row[0]).isdigit() else None


def derive_os_type(os_platform):
    """5.0 splits the 4.x os_platform into a family plus the platform itself."""
    if os_platform is None:
        return None
    platform = str(os_platform).lower()
    if platform == "windows":
        return "windows"
    if platform == "darwin":
        return "macos"
    return "linux"


def custom_groups(shared_dir):
    """Group folders worth carrying: real directories, minus the ones 5.0 ships itself."""
    if not os.path.isdir(shared_dir):
        return []
    found = []
    for name in sorted(os.listdir(shared_dir)):
        path = os.path.join(shared_dir, name)
        if not os.path.isdir(path) or os.path.islink(path):
            continue
        if name in RESERVED_GROUPS:
            continue
        found.append(name)
    return found


# --------------------------------------------------------------------------------------
# export
# --------------------------------------------------------------------------------------

def command_export(args):
    source = args.source_dir
    version = assert_install(source, 4, "source")
    assert_stopped(source, args.force)

    if os.path.exists(args.bundle) and os.listdir(args.bundle):
        raise MigrationError("bundle directory '%s' exists and is not empty." % args.bundle)

    keys_path = os.path.join(source, SOURCE_PATHS["client.keys"])
    if not os.path.isfile(keys_path):
        raise MigrationError("'%s' not found: nothing to migrate." % keys_path)

    global_db = os.path.join(source, SOURCE_PATHS["global.db"])
    if not os.path.isfile(global_db):
        raise MigrationError("'%s' not found. In 4.x the registry lives under queue/db,"
                             " not var/db." % global_db)

    # Checked before anything is written, so a source this tool cannot read leaves no half-built
    # bundle for an operator to mistake for a complete one.
    with open_ro(global_db) as connection:
        db_version = source_db_version(connection)
    if db_version is not None and db_version not in SOURCE_DB_VERSIONS_CHECKED:
        message = ("the source registry reports db_version %d, which this tool has not been"
                   " checked against (known: %s)."
                   % (db_version,
                      ", ".join(str(v) for v in SOURCE_DB_VERSIONS_CHECKED)))
        if args.force:
            warn(message + " Continuing because --force was given.")
        else:
            raise MigrationError(message + " Re-run with --force to export it anyway.")

    manifest = {
        "bundle_version": BUNDLE_VERSION,
        "tool_version": TOOL_VERSION,
        "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "source_dir": source,
        "source_version": version,
        "files": {},
        "counts": {},
        "groups": [],
    }

    if args.dry_run:
        log("DRY RUN: nothing is written.")
    else:
        os.makedirs(args.bundle, mode=0o700, exist_ok=True)
        os.chmod(args.bundle, 0o700)

    # --- plain files
    for name, relative in (("client.keys", SOURCE_PATHS["client.keys"]),
                           ("authd.pass", SOURCE_PATHS["authd.pass"]),
                           ("rbac.db", SOURCE_PATHS["rbac.db"])):
        path = os.path.join(source, relative)
        if not os.path.isfile(path):
            if name == "client.keys":
                raise MigrationError("'%s' not found: nothing to migrate." % path)
            log("  skip     %-14s (not present)" % name)
            continue
        if name == "authd.pass" and not args.with_password:
            log("  skip     %-14s (--with-password not given)" % name)
            continue
        destination = os.path.join(args.bundle, name)
        log("  export   %-14s <- %s" % (name, path))
        if not args.dry_run:
            if name == "rbac.db":
                sqlite_backup(path, destination)
            else:
                shutil.copy2(path, destination)
            os.chmod(destination, 0o600)
            manifest["files"][name] = sha256_of(destination)

    # --- the registry
    destination = os.path.join(args.bundle, "global.db")
    log("  export   %-14s <- %s" % ("global.db", global_db))
    if not args.dry_run:
        sqlite_backup(global_db, destination)
        os.chmod(destination, 0o600)
        manifest["files"]["global.db"] = sha256_of(destination)

    with open_ro(global_db) as connection:
        manifest["source_db_version"] = db_version
        agents = connection.execute("SELECT count(*) FROM agent WHERE id > 0").fetchone()[0]
        groups = connection.execute("SELECT count(*) FROM `group`").fetchone()[0]
        belongs = connection.execute(
            "SELECT count(*) FROM belongs WHERE id_agent > 0").fetchone()[0]
        manifest["counts"] = {"agents": agents, "groups": groups, "belongs": belongs}
        manifest["agents"] = [
            {"id": row[0], "name": row[1]}
            for row in connection.execute(
                "SELECT id, name FROM agent WHERE id > 0 ORDER BY id")
        ]

    # --- group folders
    shared = os.path.join(source, SOURCE_PATHS["shared"])
    names = custom_groups(shared)
    manifest["groups"] = names
    if names:
        log("  export   %-14s <- %s (%s)" % ("groups", shared, ", ".join(names)))
        if not args.dry_run:
            archive = os.path.join(args.bundle, "groups.tar.gz")
            with tarfile.open(archive, "w:gz") as tar:
                for name in names:
                    tar.add(os.path.join(shared, name), arcname=name,
                            filter=lambda info: None if os.path.basename(
                                info.name) == "merged.mg" else info)
            os.chmod(archive, 0o600)
            manifest["files"]["groups.tar.gz"] = sha256_of(archive)
    else:
        log("  skip     %-14s (no custom groups)" % "groups")

    # --- configuration, for reference only
    if not args.dry_run:
        reference = os.path.join(args.bundle, "reference")
        os.makedirs(reference, mode=0o700, exist_ok=True)
        for relative in ("etc/ossec.conf", "etc/local_internal_options.conf",
                         "api/configuration/api.yaml"):
            path = os.path.join(source, relative)
            if os.path.isfile(path):
                shutil.copy2(path, os.path.join(reference, os.path.basename(relative)))

    if not args.dry_run:
        manifest_path = os.path.join(args.bundle, "manifest.json")
        with open(manifest_path, "w") as handle:
            json.dump(manifest, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.chmod(manifest_path, 0o600)

    log("")
    log("Exported %d agent(s), %d group(s) from %s"
        % (manifest["counts"]["agents"], len(names), version or "an unknown version"))
    if not args.dry_run:
        log("Bundle: %s" % args.bundle)
        log("It carries agent keys and password hashes. Move it like a credential.")
    return 0


# --------------------------------------------------------------------------------------
# import
# --------------------------------------------------------------------------------------

def load_manifest(bundle):
    path = os.path.join(bundle, "manifest.json")
    if not os.path.isfile(path):
        raise MigrationError("'%s' has no manifest.json; it is not an export bundle." % path)
    with open(path) as handle:
        manifest = json.load(handle)
    if manifest.get("bundle_version") != BUNDLE_VERSION:
        raise MigrationError("bundle version %s is not supported by this tool (expected %d)."
                             % (manifest.get("bundle_version"), BUNDLE_VERSION))
    return manifest


def verify_bundle(bundle, manifest):
    for name, expected in sorted(manifest.get("files", {}).items()):
        path = os.path.join(bundle, name)
        if not os.path.isfile(path):
            raise MigrationError("bundle file '%s' is missing." % name)
        actual = sha256_of(path)
        if actual != expected:
            raise MigrationError("bundle file '%s' does not match its manifest checksum." % name)


def backup_existing(path, dry_run):
    """Keeps whatever is about to be overwritten, once, beside the original."""
    if not os.path.exists(path):
        return None
    backup = "%s.pre-migration" % path
    if os.path.exists(backup):
        return backup
    if not dry_run:
        shutil.copy2(path, backup)
    return backup


def install_file(bundle, name, target_dir, dry_run):
    relative, owner, group, mode, _ = PLAIN_FILES[name]
    source = os.path.join(bundle, name)
    destination = os.path.join(target_dir, relative)

    parent = os.path.dirname(destination)
    if not os.path.isdir(parent):
        raise MigrationError("'%s' does not exist; is '%s' a 5.0 installation?"
                             % (parent, target_dir))

    backup = backup_existing(destination, dry_run)
    log("  install  %-14s -> %s (%s:%s %o)%s"
        % (name, destination, owner, group, mode,
           (" [would back up]" if dry_run else " [backed up]") if backup else ""))
    if dry_run:
        return

    shutil.copy2(source, destination)
    os.chmod(destination, mode)
    uid, gid = resolve_ownership(owner, group)
    if uid is None:
        warn("user '%s' or group '%s' does not exist; ownership of '%s' left unchanged."
             % (owner, group, destination))
    else:
        os.chown(destination, uid, gid)


def preflight_registry(bundle, target_dir, force):
    """Every reason to refuse the import, checked before a single file is written.

    A half-applied migration is worse than a refused one: an operator who sees client.keys land
    and the registry rejected has to work out for themselves what state the manager is in.
    """
    source = os.path.join(bundle, "global.db")
    destination = os.path.join(target_dir, "queue", "db", "global.db")
    if not os.path.isfile(destination):
        raise MigrationError("'%s' does not exist. Install and start the 5.0 manager once so it"
                             " creates its databases, then stop it and re-run." % destination)

    with open_ro(destination) as target:
        target_version = target.execute("PRAGMA user_version").fetchone()[0]
        target_agent_columns = table_columns(target, "agent")
        existing = target.execute("SELECT count(*) FROM agent WHERE id > 0").fetchone()[0]

    if target_version not in SUPPORTED_TARGET_USER_VERSION:
        message = ("the target registry is at schema version %d, which this tool was not written"
                   " against (known: %s)."
                   % (target_version,
                      ", ".join(str(v) for v in SUPPORTED_TARGET_USER_VERSION)))
        if force:
            warn(message + " Continuing because --force was given.")
        else:
            raise MigrationError(message + " Use a tool version that matches the manager.")

    if existing and not force:
        raise MigrationError("the target registry already holds %d agent(s). Importing would"
                             " overwrite rows by id. Re-run with --force if that is intended."
                             % existing)

    with open_ro(source) as src:
        source_agent_columns = table_columns(src, "agent")

    return target_agent_columns, source_agent_columns


def transform_registry(bundle, target_dir, dry_run, columns):
    """Copies the 4.x agent, group and belongs rows into the target's own schema.

    The 4.x file cannot simply replace the target's: 5.0 stamps PRAGMA user_version and rejects
    anything else, and the agent table gained and lost columns. Only the columns both schemas
    share are carried, plus os_type, which 5.0 derives from the 4.x os_platform.
    """
    source = os.path.join(bundle, "global.db")
    destination = os.path.join(target_dir, "queue", "db", "global.db")
    target_agent_columns, source_agent_columns = columns

    shared = [name for name in source_agent_columns if name in target_agent_columns]
    dropped = [name for name in source_agent_columns if name not in target_agent_columns]
    added = [name for name in target_agent_columns if name not in source_agent_columns]

    # connection_status and disconnection_time are set rather than carried: every agent is
    # disconnected until it actually reaches the new manager, and a stale 'active' would
    # misreport the fleet for as long as it takes each agent to reconnect.
    managed = ("connection_status", "disconnection_time", "os_type")
    carried = [name for name in shared if name not in managed]

    log("  registry columns carried: %d, dropped by 5.0: %s, filled in: os_type,"
        " connection_status, disconnection_time"
        % (len(carried), ", ".join(dropped) if dropped else "none"))
    new_columns = [name for name in added if name not in managed]
    if new_columns:
        log("  registry columns new in 5.0 left at their default: %s" % ", ".join(new_columns))

    backup = backup_existing(destination, dry_run)
    if backup:
        log("  registry %s %s" % ("would be backed up to" if dry_run else "backed up to", backup))

    if dry_run:
        with open_ro(source) as src:
            agents = src.execute("SELECT count(*) FROM agent WHERE id > 0").fetchone()[0]
            groups = src.execute("SELECT count(*) FROM `group`").fetchone()[0]
        log("  DRY RUN: would copy %d agent(s) and %d group(s)." % (agents, groups))
        return {"agents": 0, "groups": 0, "belongs": 0}

    connection = sqlite3.connect(destination)
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        connection.execute("ATTACH ? AS old", (source,))
        with connection:
            column_list = ", ".join("`%s`" % name for name in carried)
            connection.execute(
                "INSERT OR REPLACE INTO agent (%s, os_type, connection_status, disconnection_time)"
                " SELECT %s,"
                "        CASE WHEN lower(os_platform) = 'windows' THEN 'windows'"
                "             WHEN lower(os_platform) = 'darwin' THEN 'macos'"
                "             WHEN os_platform IS NULL THEN NULL"
                "             ELSE 'linux' END,"
                "        'disconnected', 0"
                " FROM old.agent WHERE id > 0" % (column_list, column_list))

            connection.execute(
                "INSERT OR IGNORE INTO `group` (name) SELECT name FROM old.`group`")

            connection.execute(
                "INSERT OR REPLACE INTO belongs (id_agent, id_group, priority)"
                " SELECT b.id_agent, target_group.id, b.priority"
                " FROM old.belongs b"
                " JOIN old.`group` source_group ON source_group.id = b.id_group"
                " JOIN `group` target_group ON target_group.name = source_group.name"
                " WHERE b.id_agent > 0")

        result = {
            "agents": connection.execute(
                "SELECT count(*) FROM agent WHERE id > 0").fetchone()[0],
            "groups": connection.execute("SELECT count(*) FROM `group`").fetchone()[0],
            "belongs": connection.execute(
                "SELECT count(*) FROM belongs WHERE id_agent > 0").fetchone()[0],
        }
        connection.execute("DETACH old")
    finally:
        connection.close()

    uid, gid = resolve_ownership("wazuh-manager", "wazuh-manager")
    if uid is not None:
        os.chown(destination, uid, gid)
    os.chmod(destination, 0o640)
    return result


def restore_groups(bundle, target_dir, manifest, dry_run):
    archive = os.path.join(bundle, "groups.tar.gz")
    if not os.path.isfile(archive):
        log("  skip     %-14s (none in the bundle)" % "groups")
        return []

    shared = os.path.join(target_dir, "etc", "shared")
    if not os.path.isdir(shared):
        raise MigrationError("'%s' does not exist; is '%s' a 5.0 installation?"
                             % (shared, target_dir))

    names = manifest.get("groups", [])
    log("  install  %-14s -> %s (%s)" % ("groups", shared, ", ".join(names) or "none"))
    if dry_run:
        return names

    with tarfile.open(archive, "r:gz") as tar:
        for member in tar.getmembers():
            # The archive is ours, but a bundle is a file an operator moves between hosts:
            # refuse anything that would land outside the group tree.
            if member.name.startswith("/") or ".." in member.name.split("/"):
                raise MigrationError("refusing to extract '%s' from the bundle." % member.name)
            if member.issym() or member.islnk():
                raise MigrationError("refusing to extract the link '%s' from the bundle."
                                     % member.name)
        tar.extractall(shared)

    uid, gid = resolve_ownership("wazuh-manager", "wazuh-manager")
    for name in names:
        path = os.path.join(shared, name)
        for root, directories, files in os.walk(path):
            for entry in [root] + [os.path.join(root, item)
                                   for item in directories + files]:
                if uid is not None:
                    os.chown(entry, uid, gid)
                os.chmod(entry, 0o770 if os.path.isdir(entry) else 0o660)
    return names


def stage_rbac(target_dir, dry_run):
    """Asks the API to rebuild its defaults on the next start.

    4.x and 5.0 both stamp RBAC version 1, so a carried database is taken for a current one and
    keeps the 4.x default policies: the ones 5.0 added, enrollment-token minting among them, are
    never created. Setting the version back to 0 triggers check_database_integrity()'s supported
    upgrade, which rebuilds the defaults and migrates the users, roles and policies that were
    created by an operator.
    """
    path = os.path.join(target_dir, "api", "configuration", "security", "rbac.db")
    if not os.path.isfile(path):
        return False
    log("  stage    %-14s (PRAGMA user_version = 0, so the API rebuilds its 5.0 defaults)"
        % "rbac.db")
    if dry_run:
        return True
    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA user_version = 0")
        connection.commit()
    finally:
        connection.close()
    return True


def command_import(args):
    target = args.target_dir
    version = assert_install(target, 5, "target")
    assert_stopped(target, args.force)
    assert_master(target, args.force)

    manifest = load_manifest(args.bundle)
    verify_bundle(args.bundle, manifest)

    log("Bundle from %s (%s), %d agent(s), %d group(s)"
        % (manifest.get("source_version") or "an unknown version",
           manifest.get("created", "unknown date"),
           manifest.get("counts", {}).get("agents", 0),
           len(manifest.get("groups", []))))
    log("Target %s (%s)" % (target, version or "unknown version"))
    if args.dry_run:
        log("DRY RUN: nothing is written.")
    log("")

    # Everything that can refuse the import runs first, so a refusal never leaves the target
    # holding half a migration.
    columns = preflight_registry(args.bundle, target, args.force)

    install_file(args.bundle, "client.keys", target, args.dry_run)

    if os.path.isfile(os.path.join(args.bundle, "authd.pass")):
        if args.with_password:
            install_file(args.bundle, "authd.pass", target, args.dry_run)
        else:
            log("  skip     %-14s (--with-password not given; 5.0 agents do not use it)"
                % "authd.pass")

    counts = transform_registry(args.bundle, target, args.dry_run, columns)
    groups = restore_groups(args.bundle, target, manifest, args.dry_run)

    if os.path.isfile(os.path.join(args.bundle, "rbac.db")):
        if args.with_rbac:
            install_file(args.bundle, "rbac.db", target, args.dry_run)
            stage_rbac(target, args.dry_run)
        else:
            log("  skip     %-14s (--with-rbac not given)" % "rbac.db")

    log("")
    if args.dry_run:
        log("Dry run complete. Re-run without --dry-run to apply.")
        return 0

    log("Imported %d agent(s), %d group(s), %d membership(s)."
        % (counts["agents"], counts["groups"], counts["belongs"]))
    log("")
    log("Next: start the manager, then run this tool's 'check' against the same bundle.")
    return 0


# --------------------------------------------------------------------------------------
# check
# --------------------------------------------------------------------------------------

def command_check(args):
    target = args.target_dir
    assert_install(target, 5, "target")
    manifest = load_manifest(args.bundle)

    problems = []

    keys_path = os.path.join(target, "etc", "client.keys")
    expected_ids = {entry["id"]: entry["name"] for entry in manifest.get("agents", [])}
    installed_ids = {}
    if os.path.isfile(keys_path):
        try:
            with open(keys_path) as handle:
                for line in handle:
                    fields = line.split()
                    if len(fields) >= 2 and fields[0].isdigit():
                        installed_ids[int(fields[0])] = fields[1]
        except OSError as error:
            problems.append("client.keys is not readable: %s" % error)
    else:
        problems.append("client.keys is missing from the target.")

    missing = sorted(set(expected_ids) - set(installed_ids))
    renamed = sorted(agent_id for agent_id in set(expected_ids) & set(installed_ids)
                     if expected_ids[agent_id] != installed_ids[agent_id])
    log("client.keys      %d of %d agent(s) present" % (len(set(expected_ids) & set(installed_ids)),
                                                        len(expected_ids)))
    if missing:
        problems.append("agent id(s) missing from client.keys: %s"
                        % ", ".join(str(item) for item in missing))
    if renamed:
        problems.append("agent id(s) whose name changed: %s"
                        % ", ".join(str(item) for item in renamed))

    db_path = os.path.join(target, "queue", "db", "global.db")
    if os.path.isfile(db_path):
        try:
            with open_ro(db_path) as connection:
                agents = connection.execute(
                    "SELECT count(*) FROM agent WHERE id > 0").fetchone()[0]
                groups = {row[0] for row in connection.execute("SELECT name FROM `group`")}
                belongs = connection.execute(
                    "SELECT count(*) FROM belongs WHERE id_agent > 0").fetchone()[0]
                untyped = connection.execute(
                    "SELECT count(*) FROM agent WHERE id > 0 AND os_platform IS NOT NULL"
                    " AND os_type IS NULL").fetchone()[0]
        except sqlite3.Error as error:
            problems.append("the registry could not be read: %s" % error)
        else:
            expected_counts = manifest.get("counts", {})
            log("global.db        %d agent(s), %d group(s), %d membership(s)"
                % (agents, len(groups), belongs))
            if agents < expected_counts.get("agents", 0):
                problems.append("the registry holds %d agent(s), the bundle carried %d."
                                % (agents, expected_counts.get("agents", 0)))
            if belongs < expected_counts.get("belongs", 0):
                problems.append("the registry holds %d membership(s), the bundle carried %d."
                                % (belongs, expected_counts.get("belongs", 0)))
            for name in manifest.get("groups", []):
                if name not in groups:
                    problems.append("group '%s' is not in the registry." % name)
            if untyped:
                problems.append("%d agent row(s) have an os_platform but no os_type." % untyped)
    else:
        problems.append("the registry is missing from the target.")

    shared = os.path.join(target, "etc", "shared")
    for name in manifest.get("groups", []):
        path = os.path.join(shared, name)
        if not os.path.isdir(path):
            problems.append("group folder '%s' was not restored." % path)

    rbac_path = os.path.join(target, "api", "configuration", "security", "rbac.db")
    if os.path.isfile(os.path.join(args.bundle, "rbac.db")) and os.path.isfile(rbac_path):
        try:
            with open_ro(rbac_path) as connection:
                rbac_version = connection.execute("PRAGMA user_version").fetchone()[0]
                users = connection.execute("SELECT count(*) FROM users").fetchone()[0]
                policies = connection.execute("SELECT count(*) FROM policies").fetchone()[0]
        except sqlite3.Error as error:
            problems.append("rbac.db could not be read: %s" % error)
        else:
            log("rbac.db          %d user(s), %d policy(ies), schema version %d"
                % (users, policies, rbac_version))
            if rbac_version == 0:
                log("                 still staged: the API rebuilds its defaults on the next"
                    " start")

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
        description="Carry a 4.x manager's agent identity data into a 5.0 installation.")
    parser.add_argument("--version", action="version",
                        version="%(prog)s " + TOOL_VERSION)
    subparsers = parser.add_subparsers(dest="command", required=True)

    export_parser = subparsers.add_parser(
        "export", help="on the 4.x manager: collect the data into a bundle")
    export_parser.add_argument("bundle", help="directory to create the bundle in")
    export_parser.add_argument("--source-dir", default=DEFAULT_SOURCE_DIR,
                               help="4.x installation directory (default: %(default)s)")
    export_parser.add_argument("--with-password", action="store_true",
                               help="also export etc/authd.pass")
    export_parser.set_defaults(handler=command_export)

    import_parser = subparsers.add_parser(
        "import", help="on the 5.0 manager: restore a bundle")
    import_parser.add_argument("bundle", help="bundle directory produced by export")
    import_parser.add_argument("--target-dir", default=DEFAULT_TARGET_DIR,
                               help="5.0 installation directory (default: %(default)s)")
    import_parser.add_argument("--with-password", action="store_true",
                               help="also restore etc/authd.pass, for 4.x agents that still enroll")
    import_parser.add_argument("--with-rbac", action="store_true",
                               help="also restore the API users, roles and policies")
    import_parser.set_defaults(handler=command_import)

    check_parser = subparsers.add_parser(
        "check", help="on the 5.0 manager: compare the installation against a bundle")
    check_parser.add_argument("bundle", help="bundle directory produced by export")
    check_parser.add_argument("--target-dir", default=DEFAULT_TARGET_DIR,
                              help="5.0 installation directory (default: %(default)s)")
    check_parser.set_defaults(handler=command_check)

    for subparser in (export_parser, import_parser):
        subparser.add_argument("--dry-run", action="store_true",
                               help="report what would happen and change nothing")
    for subparser in (export_parser, import_parser):
        subparser.add_argument("--force", action="store_true",
                               help="proceed past the safety checks (running manager, worker node,"
                                    " unknown schema, non-empty target registry)")

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
    except OSError as error:
        if error.errno == errno.ENOSPC:
            print("error: no space left on device.", file=sys.stderr)
            return 2
        raise


if __name__ == "__main__":
    sys.exit(main())
