"""
Copyright (C) 2015-2024, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

Shared helpers for the container_images integration tests.

The package-level conftest exposes:
  - the paths to the module's local databases,
  - a query helper to read the reference / package tables,
  - fixtures to build and update a minimal on-disk OCI image layout (used by the inventory
    tests to simulate an image and a later image rebuild).

Design note on flakiness: the tests never sleep for a fixed time waiting for a scan. They wait
for the deterministic "Scan ended." log line through a FileMonitor and only then read the
database. That log line is emitted exactly once per scan, so the wait is bounded and
race-free.
"""
import hashlib
import json
import os
import shutil
from pathlib import Path

import pytest


# Where the tests place the on-disk OCI layouts they ask the module to scan.
LOCAL_IMAGES_ROOT = '/tmp/wazuh-container-images'


def _write_oci_layout(path: str, config_digest_seed: str, ref_name: str) -> None:
    """Write a minimal but valid OCI image layout under ``path``.

    The layout is just enough for the local reader: an ``oci-layout`` marker, an
    ``index.json`` pointing at a manifest blob, the manifest blob pointing at a config blob,
    and the config blob with platform fields. The config-blob content is seeded so that a
    rebuild (different seed) yields a different config digest.
    """
    layout = Path(path)
    blobs = layout / 'blobs' / 'sha256'
    if layout.exists():
        shutil.rmtree(layout)
    blobs.mkdir(parents=True)

    (layout / 'oci-layout').write_text('{"imageLayoutVersion":"1.0.0"}')

    config_body = json.dumps({
        'architecture': 'amd64',
        'os': 'linux',
        'os.version': '12',
        '_seed': config_digest_seed,
    })
    config_digest = hashlib.sha256(config_body.encode()).hexdigest()
    (blobs / config_digest).write_text(config_body)

    manifest_body = json.dumps({'config': {'digest': f'sha256:{config_digest}'}})
    manifest_digest = hashlib.sha256(manifest_body.encode()).hexdigest()
    (blobs / manifest_digest).write_text(manifest_body)

    index_body = json.dumps({'manifests': [{
        'digest': f'sha256:{manifest_digest}',
        'annotations': {'org.opencontainers.image.ref.name': ref_name},
    }]})
    (layout / 'index.json').write_text(index_body)


@pytest.fixture()
def prepare_local_image(request: pytest.FixtureRequest):
    """Lay down an initial OCI layout before the test and clean it up afterwards.

    The layout path is ``LOCAL_IMAGES_ROOT/oci`` (matching the LOCAL_PATH used in the
    configuration templates). Returns a callable the test can use to *update* the image
    (simulate a rebuild) with a new config-digest seed.
    """
    layout_path = os.path.join(LOCAL_IMAGES_ROOT, 'oci')
    _write_oci_layout(layout_path, config_digest_seed='v1', ref_name='debian:12')

    def _update_image(seed: str = 'v2', ref_name: str = 'debian:12') -> None:
        _write_oci_layout(layout_path, config_digest_seed=seed, ref_name=ref_name)

    yield _update_image

    shutil.rmtree(LOCAL_IMAGES_ROOT, ignore_errors=True)
