"""
Copyright (C) 2015-2024, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

Shared helpers for the container_images integration tests.

The package-level conftest exposes:
  - the paths to the module's local databases,
  - a query helper to read the reference / package tables,
  - fixtures that build the image inputs the module reads: an OCI image layout directory and a
    saved image archive, both carrying real gzip-compressed layers with a package database.

The images are built here rather than checked in as binaries, so a test states the package
database and the layer order it exercises. Nothing needs a container engine.

Design note on flakiness: the tests never sleep for a fixed time waiting for a scan. They wait
for the deterministic "Scan ended." log line through a FileMonitor and only then read the
database. That log line is emitted exactly once per scan, so the wait is bounded and
race-free.
"""
import gzip
import hashlib
import io
import json
import os
import shutil
import sqlite3
import struct
import tarfile
import tempfile
from pathlib import Path

import pytest
from wazuh_testing.constants.paths import WAZUH_PATH


# Where the tests place the image inputs they ask the module to scan. A fresh, unpredictable
# directory rather than a fixed name under the shared /tmp: a pre-created symlink at a
# well-known path would otherwise redirect what these fixtures write.
LOCAL_IMAGES_ROOT = tempfile.mkdtemp(prefix='wazuh-container-images-')

DPKG_STATUS_PATH = 'var/lib/dpkg/status'
APK_DB_PATH = 'lib/apk/db/installed'
RPM_SQLITE_DB_PATH = 'var/lib/rpm/rpmdb.sqlite'
RPM_NDB_DB_PATH = 'usr/lib/sysimage/rpm/Packages.db'
# The Berkeley DB format rpm used before 4.16, which the module recognizes but does not read.
RPM_BDB_PATH = 'var/lib/rpm/Packages'


def dpkg_status(packages: list) -> str:
    """Build a dpkg status file holding one installed stanza per (name, version) pair."""
    stanzas = []

    for name, version in packages:
        stanzas.append(
            f'Package: {name}\n'
            'Status: install ok installed\n'
            'Priority: optional\n'
            'Section: utils\n'
            'Installed-Size: 100\n'
            f'Maintainer: Debian {name} Maintainers <team@debian.org>\n'
            'Architecture: amd64\n'
            'Multi-Arch: same\n'
            f'Version: {version}\n'
            f'Description: short description of {name}\n'
        )

    return '\n'.join(stanzas) + '\n'


def apk_installed(packages: list) -> str:
    """Build an apk installed database holding one stanza per (name, version) pair."""
    stanzas = []

    for name, version in packages:
        stanzas.append(
            f'P:{name}\n'
            f'V:{version}\n'
            'A:x86_64\n'
            'I:2048\n'
            f'T:short description of {name}\n'
            f'm:Alpine {name} Maintainers <team@alpinelinux.org>\n'
        )

    return '\n'.join(stanzas) + '\n'


def _layer_blob(files: dict, compress: bool = True) -> bytes:
    """Build one image layer: a tar holding ``{in-image path: content}``, gzip by default.

    The content is text for the stanza-based databases and bytes for the binary ones.
    """
    raw = io.BytesIO()

    with tarfile.open(fileobj=raw, mode='w') as tar:
        for path, content in files.items():
            payload = content if isinstance(content, bytes) else content.encode()
            info = tarfile.TarInfo(name=path)
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))

    return gzip.compress(raw.getvalue()) if compress else raw.getvalue()


def _config_blob(seed: str) -> bytes:
    """Image configuration blob. The seed makes a rebuild yield a different digest."""
    return json.dumps({
        'architecture': 'amd64',
        'os': 'linux',
        'os.version': '12',
        '_seed': seed,
    }).encode()


def rpm_header_blob(name: str, version: str, release: str, epoch: int = None, architecture: str = 'x86_64') -> bytes:
    """Build one rpm header blob, the structure every rpm database backend stores.

    The blob is an index of 16-byte entries followed by the data section they point into,
    all big endian.
    """
    TYPE_INT32, TYPE_STRING, TYPE_I18NSTRING = 4, 6, 9

    index = b''
    section = b''

    def add(tag, kind, value):
        nonlocal index, section
        index += struct.pack('>IIII', tag, kind, len(section), 1)

        if kind == TYPE_INT32:
            section += struct.pack('>I', value)
        else:
            section += value.encode() + b'\x00'

    add(1000, TYPE_STRING, name)
    add(1001, TYPE_STRING, version)
    add(1002, TYPE_STRING, release)

    if epoch is not None:
        add(1003, TYPE_INT32, epoch)

    add(1004, TYPE_I18NSTRING, f'short description of {name}')
    add(1008, TYPE_INT32, 1700000000)
    add(1009, TYPE_INT32, 2048)
    add(1011, TYPE_STRING, 'Wazuh Inc.')
    add(1016, TYPE_I18NSTRING, 'Unspecified')
    add(1022, TYPE_STRING, architecture)

    return struct.pack('>II', len(index) // 16, len(section)) + index + section


def rpm_sqlite_db(packages: list) -> bytes:
    """Build an ``rpmdb.sqlite`` holding one header blob per package.

    Written in write-ahead log mode and checkpointed, which is the shape rpm leaves in an
    image layer.
    """
    directory = tempfile.mkdtemp(prefix='wazuh-rpmdb-')
    path = os.path.join(directory, 'rpmdb.sqlite')

    connection = sqlite3.connect(path)
    connection.execute('PRAGMA journal_mode=WAL')
    connection.execute('CREATE TABLE Packages (hnum INTEGER PRIMARY KEY, blob BLOB NOT NULL)')

    for name, version, release, epoch in packages:
        connection.execute('INSERT INTO Packages (blob) VALUES (?)',
                           (rpm_header_blob(name, version, release, epoch),))

    connection.commit()
    connection.execute('PRAGMA wal_checkpoint(TRUNCATE)')
    connection.close()

    content = Path(path).read_bytes()
    shutil.rmtree(directory, ignore_errors=True)

    return content


def rpm_ndb_db(packages: list) -> bytes:
    """Build a ``Packages.db`` holding one header blob per package.

    One slot page behind the 32-byte header, and the blobs from the second page on, each
    behind its own 16-byte header. Every field is little endian.
    """
    BLOCK, PAGE = 16, 4096
    slots = b''
    payloads = b''

    for number, (name, version, release, epoch) in enumerate(packages, start=1):
        blob = rpm_header_blob(name, version, release, epoch)
        slots += b'Slot' + struct.pack('<III', number, (PAGE + len(payloads)) // BLOCK,
                                       -(-(BLOCK + len(blob)) // BLOCK))
        payloads += b'BlbS' + struct.pack('<III', number, 1, len(blob)) + blob
        payloads += b'\x00' * (-len(payloads) % BLOCK)

    header = b'RpmP' + struct.pack('<IIII', 0, 1, 1, len(packages) + 1)
    header += b'\x00' * (32 - len(header))

    return header + slots + b'\x00' * (PAGE - 32 - len(slots)) + payloads


def write_oci_layout(path: str, layers: list, seed: str = 'v1', ref_name: str = 'debian:12') -> None:
    """Write an OCI image layout under ``path``, with the given layers in manifest order.

    Each layer is a ``{in-image path: content}`` mapping. The layout carries the marker, the
    index, the manifest, the configuration blob and one blob per layer, which is what the
    reader walks.
    """
    layout = Path(path)
    blobs = layout / 'blobs' / 'sha256'

    if layout.exists():
        shutil.rmtree(layout)

    blobs.mkdir(parents=True)
    (layout / 'oci-layout').write_text('{"imageLayoutVersion":"1.0.0"}')

    config_body = _config_blob(seed)
    config_digest = hashlib.sha256(config_body).hexdigest()
    (blobs / config_digest).write_bytes(config_body)

    layer_descriptors = []

    for files in layers:
        blob = _layer_blob(files)
        digest = hashlib.sha256(blob).hexdigest()
        (blobs / digest).write_bytes(blob)
        layer_descriptors.append({'digest': f'sha256:{digest}'})

    manifest_body = json.dumps({
        'config': {'digest': f'sha256:{config_digest}'},
        'layers': layer_descriptors,
    }).encode()
    manifest_digest = hashlib.sha256(manifest_body).hexdigest()
    (blobs / manifest_digest).write_bytes(manifest_body)

    (layout / 'index.json').write_text(json.dumps({'manifests': [{
        'digest': f'sha256:{manifest_digest}',
        'annotations': {'org.opencontainers.image.ref.name': ref_name},
    }]}))


def write_saved_archive(path: str, layers: list, seed: str = 'v1', ref_name: str = 'debian:12') -> None:
    """Write a saved image archive at ``path``, the way ``docker save`` writes one.

    The archive holds the layer tars, the configuration file and the ``manifest.json`` that
    names both, in manifest order.
    """
    archive = Path(path)
    archive.parent.mkdir(parents=True, exist_ok=True)

    if archive.exists():
        archive.unlink()

    config_body = _config_blob(seed)
    config_name = f'{hashlib.sha256(config_body).hexdigest()}.json'
    layer_names = []

    with tarfile.open(archive, mode='w') as tar:
        for index, files in enumerate(layers):
            # A saved archive stores its layers uncompressed, under a per-layer directory.
            blob = _layer_blob(files, compress=False)
            name = f'layer{index}/layer.tar'
            info = tarfile.TarInfo(name=name)
            info.size = len(blob)
            tar.addfile(info, io.BytesIO(blob))
            layer_names.append(name)

        info = tarfile.TarInfo(name=config_name)
        info.size = len(config_body)
        tar.addfile(info, io.BytesIO(config_body))

        manifest_body = json.dumps([{
            'Config': config_name,
            'RepoTags': [ref_name],
            'Layers': layer_names,
        }]).encode()
        info = tarfile.TarInfo(name='manifest.json')
        info.size = len(manifest_body)
        tar.addfile(info, io.BytesIO(manifest_body))


def reset_module_database() -> None:
    """Remove the module's own database so a case starts from an empty inventory.

    The tests assert on the whole packages table, and the database survives the agent
    restart between cases, so without this a case reads the rows an earlier case stored
    and the suite only passes when each test is run on its own.
    """
    db_dir = Path(WAZUH_PATH) / 'queue' / 'container_images' / 'db'

    for stored in db_dir.glob('*.db*'):
        stored.unlink(missing_ok=True)


def point_configuration_at(test_configuration: dict, path: str) -> None:
    """Point the configured ``<archive>`` reference at the image the fixture just wrote.

    The test cases carry a placeholder path, while the images are written under a fresh
    per-run directory, so the reference is completed here instead of in the case file.
    """
    for section in test_configuration.get('sections', []):
        if section.get('section') != 'container_images':
            continue

        for element in section.get('elements', []):
            for reference in element.get('references', {}).get('elements', []):
                for entry in reference.values():
                    entry['value'] = path


@pytest.fixture()
def prepare_local_image(request: pytest.FixtureRequest, test_configuration: dict):
    """Lay down an OCI image layout with one dpkg layer, and clean it up afterwards.

    The layout is written under ``LOCAL_IMAGES_ROOT`` and the configured reference is pointed
    at it. Returns a callable the test uses to rebuild the image, with a new configuration
    digest and, optionally, a new package set.
    """
    layout_path = os.path.join(LOCAL_IMAGES_ROOT, 'oci')
    initial_layers = [{DPKG_STATUS_PATH: dpkg_status([('curl', '7.88.1-10'), ('tar', '1.34+dfsg-1')])}]
    write_oci_layout(layout_path, initial_layers, seed='v1')

    def _update_image(seed: str = 'v2', ref_name: str = 'debian:12', layers: list = None) -> None:
        write_oci_layout(layout_path, layers if layers is not None else initial_layers, seed=seed,
                         ref_name=ref_name)

    reset_module_database()
    point_configuration_at(test_configuration, layout_path)

    yield _update_image

    shutil.rmtree(LOCAL_IMAGES_ROOT, ignore_errors=True)


@pytest.fixture()
def prepare_saved_archive(request: pytest.FixtureRequest, test_configuration: dict):
    """Lay down a saved image archive with one apk layer, and clean it up afterwards.

    The archive path is ``LOCAL_IMAGES_ROOT/image.tar``.
    """
    archive_path = os.path.join(LOCAL_IMAGES_ROOT, 'image.tar')
    write_saved_archive(archive_path,
                        [{APK_DB_PATH: apk_installed([('busybox', '1.36.1-r5'), ('musl', '1.2.4-r2')])}],
                        ref_name='alpine:3.19')

    reset_module_database()
    point_configuration_at(test_configuration, archive_path)

    yield archive_path

    shutil.rmtree(LOCAL_IMAGES_ROOT, ignore_errors=True)


@pytest.fixture()
def prepare_layered_image(request: pytest.FixtureRequest, test_configuration: dict):
    """Lay down an OCI layout whose second layer upgrades a package installed by the first.

    The image must be inventoried with the version the last layer provides, which is what the
    composition in manifest order is for.
    """
    layout_path = os.path.join(LOCAL_IMAGES_ROOT, 'oci-layered')
    write_oci_layout(layout_path, [
        {DPKG_STATUS_PATH: dpkg_status([('curl', '7.88.1-10'), ('tar', '1.34+dfsg-1')])},
        {DPKG_STATUS_PATH: dpkg_status([('curl', '8.5.0-2'), ('tar', '1.34+dfsg-1')])},
    ])

    reset_module_database()
    point_configuration_at(test_configuration, layout_path)

    yield layout_path

    shutil.rmtree(LOCAL_IMAGES_ROOT, ignore_errors=True)


@pytest.fixture()
def prepare_whiteout_image(request: pytest.FixtureRequest, test_configuration: dict):
    """Lay down an OCI layout whose second layer deletes the database of the first.

    The second layer removes the dpkg database through an OverlayFS deletion marker and brings
    an apk one instead, so only the apk packages may be inventoried.
    """
    layout_path = os.path.join(LOCAL_IMAGES_ROOT, 'oci-whiteout')
    write_oci_layout(layout_path, [
        {DPKG_STATUS_PATH: dpkg_status([('curl', '7.88.1-10')])},
        {'var/lib/dpkg/.wh.status': '', APK_DB_PATH: apk_installed([('busybox', '1.36.1-r5')])},
    ], ref_name='mixed:latest')

    reset_module_database()
    point_configuration_at(test_configuration, layout_path)

    yield layout_path

    shutil.rmtree(LOCAL_IMAGES_ROOT, ignore_errors=True)


@pytest.fixture()
def prepare_unsupported_image(request: pytest.FixtureRequest, test_configuration: dict):
    """Lay down an OCI layout whose only package database is one that is not parsed yet."""
    layout_path = os.path.join(LOCAL_IMAGES_ROOT, 'oci-rpm')
    write_oci_layout(layout_path, [{RPM_BDB_PATH: 'a Berkeley DB hash file'}], ref_name='centos:7')

    reset_module_database()
    point_configuration_at(test_configuration, layout_path)

    yield layout_path

    shutil.rmtree(LOCAL_IMAGES_ROOT, ignore_errors=True)


@pytest.fixture()
def prepare_rpm_sqlite_image(request: pytest.FixtureRequest, test_configuration: dict):
    """Lay down an OCI layout whose package database is an rpm sqlite one."""
    layout_path = os.path.join(LOCAL_IMAGES_ROOT, 'oci-rpm-sqlite')
    database = rpm_sqlite_db([('bash', '5.1.8', '9.el9', None), ('gdbm-libs', '1.19', '4.el9', 1)])
    write_oci_layout(layout_path, [{RPM_SQLITE_DB_PATH: database}], ref_name='rockylinux:9')

    reset_module_database()
    point_configuration_at(test_configuration, layout_path)

    yield layout_path

    shutil.rmtree(LOCAL_IMAGES_ROOT, ignore_errors=True)


@pytest.fixture()
def prepare_rpm_ndb_image(request: pytest.FixtureRequest, test_configuration: dict):
    """Lay down an OCI layout whose package database is an rpm ndb one, under /usr."""
    layout_path = os.path.join(LOCAL_IMAGES_ROOT, 'oci-rpm-ndb')
    database = rpm_ndb_db([('aaa_base', '84.87', '150300.10.20.1', None)])
    write_oci_layout(layout_path, [{RPM_NDB_DB_PATH: database}], ref_name='opensuse/leap:15.5')

    reset_module_database()
    point_configuration_at(test_configuration, layout_path)

    yield layout_path

    shutil.rmtree(LOCAL_IMAGES_ROOT, ignore_errors=True)
