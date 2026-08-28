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
import tarfile
import tempfile
from pathlib import Path

import pytest


# Where the tests place the image inputs they ask the module to scan. A fresh, unpredictable
# directory rather than a fixed name under the shared /tmp: a pre-created symlink at a
# well-known path would otherwise redirect what these fixtures write.
LOCAL_IMAGES_ROOT = tempfile.mkdtemp(prefix='wazuh-container-images-')

DPKG_STATUS_PATH = 'var/lib/dpkg/status'
APK_DB_PATH = 'lib/apk/db/installed'
RPM_DB_PATH = 'var/lib/rpm/rpmdb.sqlite'


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
    """Build one image layer: a tar holding ``{in-image path: content}``, gzip by default."""
    raw = io.BytesIO()

    with tarfile.open(fileobj=raw, mode='w') as tar:
        for path, content in files.items():
            payload = content.encode()
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


@pytest.fixture()
def prepare_local_image(request: pytest.FixtureRequest):
    """Lay down an OCI image layout with one dpkg layer, and clean it up afterwards.

    The layout path is ``LOCAL_IMAGES_ROOT/oci``, matching the ARCHIVE_PATH used in the
    configuration templates. Returns a callable the test uses to rebuild the image, with a new
    configuration digest and, optionally, a new package set.
    """
    layout_path = os.path.join(LOCAL_IMAGES_ROOT, 'oci')
    initial_layers = [{DPKG_STATUS_PATH: dpkg_status([('curl', '7.88.1-10'), ('tar', '1.34+dfsg-1')])}]
    write_oci_layout(layout_path, initial_layers, seed='v1')

    def _update_image(seed: str = 'v2', ref_name: str = 'debian:12', layers: list = None) -> None:
        write_oci_layout(layout_path, layers if layers is not None else initial_layers, seed=seed,
                         ref_name=ref_name)

    yield _update_image

    shutil.rmtree(LOCAL_IMAGES_ROOT, ignore_errors=True)


@pytest.fixture()
def prepare_saved_archive(request: pytest.FixtureRequest):
    """Lay down a saved image archive with one apk layer, and clean it up afterwards.

    The archive path is ``LOCAL_IMAGES_ROOT/image.tar``.
    """
    archive_path = os.path.join(LOCAL_IMAGES_ROOT, 'image.tar')
    write_saved_archive(archive_path,
                        [{APK_DB_PATH: apk_installed([('busybox', '1.36.1-r5'), ('musl', '1.2.4-r2')])}],
                        ref_name='alpine:3.19')

    yield archive_path

    shutil.rmtree(LOCAL_IMAGES_ROOT, ignore_errors=True)


@pytest.fixture()
def prepare_layered_image(request: pytest.FixtureRequest):
    """Lay down an OCI layout whose second layer upgrades a package installed by the first.

    The image must be inventoried with the version the last layer provides, which is what the
    composition in manifest order is for.
    """
    layout_path = os.path.join(LOCAL_IMAGES_ROOT, 'oci-layered')
    write_oci_layout(layout_path, [
        {DPKG_STATUS_PATH: dpkg_status([('curl', '7.88.1-10'), ('tar', '1.34+dfsg-1')])},
        {DPKG_STATUS_PATH: dpkg_status([('curl', '8.5.0-2'), ('tar', '1.34+dfsg-1')])},
    ])

    yield layout_path

    shutil.rmtree(LOCAL_IMAGES_ROOT, ignore_errors=True)


@pytest.fixture()
def prepare_whiteout_image(request: pytest.FixtureRequest):
    """Lay down an OCI layout whose second layer deletes the database of the first.

    The second layer removes the dpkg database through an OverlayFS deletion marker and brings
    an apk one instead, so only the apk packages may be inventoried.
    """
    layout_path = os.path.join(LOCAL_IMAGES_ROOT, 'oci-whiteout')
    write_oci_layout(layout_path, [
        {DPKG_STATUS_PATH: dpkg_status([('curl', '7.88.1-10')])},
        {'var/lib/dpkg/.wh.status': '', APK_DB_PATH: apk_installed([('busybox', '1.36.1-r5')])},
    ], ref_name='mixed:latest')

    yield layout_path

    shutil.rmtree(LOCAL_IMAGES_ROOT, ignore_errors=True)


@pytest.fixture()
def prepare_unsupported_image(request: pytest.FixtureRequest):
    """Lay down an OCI layout whose only package database is one that is not parsed yet."""
    layout_path = os.path.join(LOCAL_IMAGES_ROOT, 'oci-rpm')
    write_oci_layout(layout_path, [{RPM_DB_PATH: 'SQLite format 3\x00'}], ref_name='rocky:9')

    yield layout_path

    shutil.rmtree(LOCAL_IMAGES_ROOT, ignore_errors=True)
