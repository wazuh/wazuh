"""Fixtures for the inventory_sync_server integration QA.

The suite attacks the REAL server over its Unix socket (the exact wire remoted
uses) and asserts final state in a REAL OpenSearch -- no agent emulation, no
protocol acks (the HTTP response IS the result).

Environment (all optional):
  INVSYNC_TESTTOOL   path to inventory_sync_server_testtool (default: src/build/bin/...)
  FLATC              path to flatc (default: src/external/flatbuffers/build/flatc)
  INDEXER_URL        an already-running OpenSearch (default: http://127.0.0.1:9200;
                     when unreachable, one is started with docker)
"""

import json
import os
import pathlib
import shutil
import signal
import subprocess
import sys
import time

import pytest

QA_DIR = pathlib.Path(__file__).resolve().parent
SRC_DIR = QA_DIR.parents[2]  # .../src
SCHEMA = SRC_DIR / "shared_modules" / "utils" / "flatbuffers" / "schemas" / "inventorySync.fbs"
GENERATED = QA_DIR / ".generated"
SOCKET_RELPATH = "queue/sockets/inventory-sync.sock"


def _generate_bindings():
    """flatc --python of the shared schema into .generated/ (never committed)."""
    flatc = os.environ.get("FLATC", str(SRC_DIR / "external" / "flatbuffers" / "build" / "flatc"))
    marker = GENERATED / ".from"
    if marker.exists() and marker.read_text() == str(SCHEMA.stat().st_mtime):
        return
    shutil.rmtree(GENERATED, ignore_errors=True)
    GENERATED.mkdir(parents=True)
    subprocess.run([flatc, "--python", "-o", str(GENERATED), str(SCHEMA)], check=True, timeout=60)
    for package in (GENERATED, GENERATED / "Wazuh", GENERATED / "Wazuh" / "SyncSchema"):
        (package / "__init__.py").touch()
    marker.write_text(str(SCHEMA.stat().st_mtime))


# At import time, before the test modules import helpers.session_builder.
_generate_bindings()
sys.path.insert(0, str(GENERATED))
sys.path.insert(0, str(QA_DIR))

from helpers.indexer import Indexer  # noqa: E402  (needs sys.path above)
from helpers.uds_client import ServerClient  # noqa: E402

CONFIG = json.loads((QA_DIR / "config.json").read_text())

# A permissive template with the few fields the server's own queries need typed:
# the checksum sort and the term/update-by-query filters require keyword, and a
# dynamic (text) mapping would fail the sort outright.
STATE_TEMPLATE = {
    "index_patterns": ["wazuh-states-*"],
    "template": {
        "settings": {"number_of_replicas": 0},
        "mappings": {
            "dynamic": True,
            "properties": {
                "checksum": {"properties": {"hash": {"properties": {"sha1": {"type": "keyword"}}}}},
                "state": {"properties": {"document_version": {"type": "long"}}},
                "wazuh": {
                    "properties": {
                        "agent": {
                            "properties": {
                                "id": {"type": "keyword"},
                                "name": {"type": "keyword"},
                                "version": {"type": "keyword"},
                                "groups": {"type": "keyword"},
                            }
                        },
                        "cluster": {"properties": {"name": {"type": "keyword"}}},
                    }
                },
            },
        },
    },
}


def _ensure_opensearch(url):
    indexer = Indexer(url)
    if indexer.available():
        return indexer

    # Same bring-up the sibling suites use: dockerized single node, security off.
    import docker  # local import: not needed when INDEXER_URL points at a live one

    client = docker.from_env()
    try:
        container = client.containers.get("opensearch-test")
        if container.status != "running":
            container.remove(force=True)
            raise docker.errors.NotFound("recreate")
    except docker.errors.NotFound:
        client.containers.run(
            "opensearchproject/opensearch:2.11.1",
            detach=True,
            name="opensearch-test",
            ports={"9200/tcp": 9200},
            environment={
                "discovery.type": "single-node",
                "DISABLE_SECURITY_PLUGIN": "true",
                "OPENSEARCH_JAVA_OPTS": "-Xms512m -Xmx512m",
            },
        )

    for _ in range(120):
        if indexer.available():
            return indexer
        time.sleep(1)
    raise RuntimeError(f"OpenSearch never became available at {url}")


@pytest.fixture(scope="session")
def indexer():
    import requests

    url = os.environ.get("INDEXER_URL", CONFIG["indexer"]["hosts"][0])
    client = _ensure_opensearch(url)
    response = requests.put(f"{url.rstrip('/')}/_index_template/qa-wazuh-states",
                            json=STATE_TEMPLATE, timeout=10)
    response.raise_for_status()
    yield client


@pytest.fixture(scope="session")
def server(indexer, tmp_path_factory):
    """The real module pair booted by the testtool's --serve mode.

    --no-vd keeps the vulnerability scanner facade down: the server's scanner
    seam then reports feed-ready and answers every scan as a legitimate skip
    (D22's skip row), so VD-flagged sessions still index deterministically.
    """
    testtool = os.environ.get("INVSYNC_TESTTOOL", str(SRC_DIR / "build" / "bin" / "inventory_sync_server_testtool"))
    workdir = tmp_path_factory.mktemp("server")

    config = dict(CONFIG)
    # Override only the host, keeping whatever else config.json declares -- `flush_interval_seconds`
    # in particular, without which the ASYNC connector (POST /config, POST /stats) holds a write for
    # its 20 s default and every test that reads one back has to outwait it.
    config["indexer"] = {**CONFIG["indexer"],
                         "hosts": [os.environ.get("INDEXER_URL", CONFIG["indexer"]["hosts"][0])]}
    config_path = workdir / "config.json"
    config_path.write_text(json.dumps(config))

    # Output goes to a FILE, never a pipe: the server logs every bulk response,
    # and an unread pipe buffer would eventually block a worker mid-flush.
    log_path = workdir / "server.log"
    with open(log_path, "w") as log_file:
        process = subprocess.Popen(
            [testtool, "--serve", "--no-vd", "--config", str(config_path)],
            cwd=workdir,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            text=True,
        )

    socket_path = workdir / SOCKET_RELPATH
    if len(str(socket_path)) > 100:  # AF_UNIX sun_path budget
        process.kill()
        raise RuntimeError(f"socket path too long for AF_UNIX: {socket_path}")
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"testtool died during startup:\n{log_path.read_text()[-4000:]}")
        if socket_path.exists():
            break
        time.sleep(0.2)
    else:
        process.kill()
        raise RuntimeError(f"the server socket never appeared; log tail:\n{log_path.read_text()[-4000:]}")

    yield {"socket": str(socket_path), "cluster": config["clusterName"]}

    process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=30)
    except subprocess.TimeoutExpired:
        process.kill()


@pytest.fixture()
def client(server):
    return ServerClient(server["socket"])


@pytest.fixture()
def cluster(server):
    return server["cluster"]


@pytest.fixture(autouse=True)
def clean_states(indexer):
    """Every test starts from empty state indices."""
    indexer.delete_states()
    yield


_AGENT_COUNTER = iter(range(100, 100000))


@pytest.fixture()
def agent_id():
    """A fresh 3-digit-padded agent id per test, so runs never share documents."""
    return f"{next(_AGENT_COUNTER):03d}"
