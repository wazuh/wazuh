from shutil import copy
import sys
import json
import hashlib
from pathlib import Path
from typing import Optional
from datetime import datetime, timezone

from google.protobuf.json_format import ParseDict

from engine_handler.handler import EngineHandler
from shared.default_settings import Constants

from api_communication.client import APIClient
from api_communication.proto import crud_pb2 as api_crud
from api_communication.proto import engine_pb2 as api_engine


# ===================================================================
#  Constants shared with the tests (namespace / UUIDs / filter)
# ===================================================================

POLICY_NS = "testing"

DECODER_TEST_NAME = "decoder/test-message/0"
DECODER_OTHER_NAME = "decoder/other-test-message/0"
FILTER_ALLOW_ALL_NAME = "filter/allow-all/0"
FILTER_ALLOW_ALL_UUID = "b540db06-a761-4c02-8880-1d3e3b964063"

# Valid v4 UUIDs (must match those used in steps.py)
DECODER_TEST_UUID = "2faeea8b-672b-4b42-8f91-657d7810d636"
DECODER_OTHER_UUID = "594ea807-a037-408d-95b8-9a124ea333df"

INTEG_WAZUH_CORE_UUID = "9b1a1ef2-1a70-4a8b-a89b-38b34174c2d1"
INTEG_OTHER_WAZUH_CORE_UUID = "a15bbd77-8cb0-488f-94cd-4783d689a72f"


# ===================================================================
#  Utilities
# ===================================================================

def cpy_conf(env_path: Path, it_path: Path) -> Path:
    serv_conf_file = it_path / "configuration_files" / "config.env"
    dest_conf_file = env_path / "config.env"
    backup_dest_conf_file = env_path / "config.env.bak"

    if not serv_conf_file.is_file():
        raise FileNotFoundError(f"File {serv_conf_file} does not exist")
    if dest_conf_file.is_file():
        dest_conf_file.rename(backup_dest_conf_file)

    # Read the source config once
    conf_str = serv_conf_file.read_text()

    # Replace path placeholder
    conf_str = conf_str.replace(Constants.PLACEHOLDER, env_path.as_posix())

    # Write updated config to destination
    dest_conf_file.write_text(conf_str)

    return dest_conf_file


def send_recv(api_client: APIClient, request, expected_response):
    """
    Minimal helper to call engine-api from init.
    Raises RuntimeError if there is a transport error or if status == ERROR.
    """
    error, response = api_client.send_recv(request)
    if error is not None:
        raise RuntimeError(f"Engine API error: {error}")
    parsed = ParseDict(response, expected_response)
    status = getattr(parsed, "status", None)
    if status == api_engine.ERROR:
        raise RuntimeError(f"Engine API returned ERROR: {parsed.error}")
    return parsed


def md5_file(path: Path) -> str:
    """Calculate MD5 hash of a file."""
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def init_geo_store(env_path: Path, test_path: Path):
    """
    Initialize geo store structure and JSON metadata for databases.
    Creates store/geo/mmdb/0 with nested structure for all databases.
    """
    geo_data_path = test_path / "geo" / "data"
    geo_dest_path = env_path / "geo"
    geo_store_path = env_path / "store" / "geo" / "mmdb"

    # Create directories
    geo_dest_path.mkdir(parents=True, exist_ok=True)
    geo_store_path.mkdir(parents=True, exist_ok=True)

    # Current timestamp
    generated_at = int(datetime.now(timezone.utc).timestamp())

    db_name = "base.mmdb"
    dest_db = geo_data_path / db_name

    # Calculate MD5 hash
    db_hash = md5_file(dest_db)

    # Create nested store metadata JSON
    metadata = {
        "city": {
            "path": dest_db.as_posix(),
            "hash": db_hash,
            "generated_at": generated_at
        }
    }

    # Write JSON to store/geo/mmdb/0 (single file with nested structure)
    store_json_path = geo_store_path / "0"
    with open(store_json_path, "w") as f:
        json.dump(metadata, f, indent=4)

    print(f"  Initialized geo store: city={db_hash[:8]}...")


def init_enrichments_store(env_path: Path):
    """
    Initialize geo store structure and JSON metadata for databases.
    Creates store/geo/mmdb/0 with nested structure for all databases.
    """
    enrichment_geo_path = env_path / "store" / "enrichment" / "geo"
    enrichment_geo_path.mkdir(parents=True, exist_ok=True)

    # Create nested store metadata JSON
    metadata = {
        "client.ip": {
            "as_field": "client.as",
            "geo_field": "client.geo"
        }
    }

    # Write JSON to store/geo/mmdb/0 (single file with nested structure)
    store_json_path = enrichment_geo_path / "0"
    with open(store_json_path, "w") as f:
        json.dump(metadata, f, indent=4)

    print(f"Initialized enrichments")

# ===================================================================
#  YAML builders (decoders / integrations / filter)
# ===================================================================

def build_tester_decoder_yaml(name: str, uuid: str, check_expr: str) -> str:
    """
    Valid decoder for the new asset validator:
      - name + id
      - check
      - normalize with basic map
    """
    return f"""\
name: {name}
id: {uuid}
enabled: true

check: {check_expr}

normalize:
  - map:
    - event.category: array_append(test)
    - event.kind: metric
    - event.type: array_append(info)
"""


def build_integration_yaml(
    integ_uuid: str,
    integ_title: str,
    default_parent: str,
    category: str,
    decoder_uuid: str,
) -> str:
    """
    Integration YAML according to the new model:

      {
        "id": "...",
        "title": "...",
        "enabled": true,
        "category": "other",
        "default_parent": "...",
        "decoders": [ "<decoder_uuid>" ],
        "kvdbs": []
      }
    """
    return f"""\
id: {integ_uuid}
title: {integ_title}
enabled: true
category: {category}
default_parent: {default_parent}
decoders:
  - "{decoder_uuid}"
kvdbs: []
"""


def build_allow_all_filter_yaml() -> str:
    """
    Minimal filter for router tests, same as before.
    """
    return f"""\
name: {FILTER_ALLOW_ALL_NAME}
id: {FILTER_ALLOW_ALL_UUID}
enabled: true
type: pre-filter
check: exists($event.original)
"""


# ===================================================================
#  CM initialization logic (namespace + decoders + integrations + filter)
# ===================================================================

def init_cm_resources(api_client: APIClient):
    # 1) Clean namespace
    ns_del = api_crud.namespaceDelete_Request()
    ns_del.space = POLICY_NS
    # Ignore errors (namespace may not exist yet)
    _, _ = api_client.send_recv(ns_del)

    # Create it again
    ns_post = api_crud.namespacePost_Request()
    ns_post.space = POLICY_NS
    send_recv(api_client, ns_post, api_engine.GenericStatus_Response())

    # 2) Decoders
    dec_test_yaml = build_tester_decoder_yaml(
        DECODER_TEST_NAME,
        DECODER_TEST_UUID,
        check_expr="$wazuh.agent.id == AA11",
    )
    dec_other_yaml = build_tester_decoder_yaml(
        DECODER_OTHER_NAME,
        DECODER_OTHER_UUID,
        check_expr="$wazuh.agent.id == BB22",
    )

    for yml in (dec_test_yaml, dec_other_yaml):
        req = api_crud.resourcePost_Request()
        req.space = POLICY_NS
        req.type = "decoder"
        req.ymlContent = yml
        send_recv(api_client, req, api_engine.GenericStatus_Response())

    # 3) Integrations
    wazuh_core_yaml = build_integration_yaml(
        integ_uuid=INTEG_WAZUH_CORE_UUID,
        integ_title="wazuh-core-test",
        default_parent=DECODER_TEST_UUID,
        category="unclassified",
        decoder_uuid=DECODER_TEST_UUID,
    )

    other_core_yaml = build_integration_yaml(
        integ_uuid=INTEG_OTHER_WAZUH_CORE_UUID,
        integ_title="other-wazuh-core-test",
        default_parent=DECODER_TEST_UUID,
        category="other",
        decoder_uuid=DECODER_OTHER_UUID,
    )

    for yml in (wazuh_core_yaml, other_core_yaml):
        req = api_crud.resourcePost_Request()
        req.space = POLICY_NS
        req.type = "integration"
        req.ymlContent = yml
        send_recv(api_client, req, api_engine.GenericStatus_Response())

    # 4) Allow-all filter (for Router Routes API Management)
    filter_yaml = build_allow_all_filter_yaml()
    req = api_crud.resourcePost_Request()
    req.space = POLICY_NS
    req.type = "filter"
    req.ymlContent = filter_yaml
    send_recv(api_client, req, api_engine.GenericStatus_Response())

    print(f"CM initialized in namespace '{POLICY_NS}' with decoders, integrations and filter.")


# ===================================================================
#  init / run
# ===================================================================

def init(env_path: Path, test_path: Path):
    engine_handler: Optional[EngineHandler] = None

    try:
        print(f"Copying configuration file to {env_path}...")
        config_path = cpy_conf(env_path, test_path)
        print("Configuration file copied.")

        # Init enrichments store with minimal metadata (only client.ip with as and geo fields, no actual data files)
        init_enrichments_store(env_path)

        # Initialize geo databases and store metadata
        print("Initializing geo databases and store...")
        init_geo_store(env_path, test_path)

        # Binary path
        bin_path = env_path / "wazuh-engine"

        print("Starting the Engine...")
        engine_handler = EngineHandler(bin_path.as_posix(), config_path.as_posix())
        engine_handler.start()
        print("Engine started.")

        # Create API client pointing to the engine socket in this env
        socket_path = env_path / "queue" / "sockets" / "engine-api.socket"
        api_client = APIClient(str(socket_path))

        print("Initializing CM resources for tester (namespace 'testing')...")
        init_cm_resources(api_client)
        print("CM resources initialized.")

        print("Stopping the Engine...")
        engine_handler.stop()
        print("Engine stopped.")

    except Exception as e:
        print(f"An error occurred: {e}")
        if engine_handler:
            print("Stopping the engine...")
            engine_handler.stop()
            print("Engine stopped.")
        sys.exit(1)

    sys.exit(0)


def run(args):
    env_path = Path(args["environment"]).resolve()
    test_path = Path(args["test_dir"]).resolve()
    init(env_path, test_path)
