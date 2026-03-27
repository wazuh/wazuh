# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import json
import logging
import os
from datetime import datetime, timezone

from jsonschema import ValidationError, validate

from wazuh.core import common
from wazuh.core.agent import WazuhDBQueryAgents
from wazuh.core.cluster.dapi.dapi import DistributedAPI
from wazuh.core.indexer.indexer import get_indexer_client
from wazuh.stats import get_daemons_stats

# Mapping from OpenSearch field types to JSON Schema type definitions.
_OPENSEARCH_TO_JSONSCHEMA_TYPE: dict[str, dict] = {
    "keyword": {"type": "string"},
    "text": {"type": "string"},
    "match_only_text": {"type": "string"},
    "integer": {"type": "integer"},
    "long": {"type": "integer"},
    "short": {"type": "integer"},
    "unsigned_long": {"type": "integer"},
    "float": {"type": "number"},
    "double": {"type": "number"},
    "scaled_float": {"type": "number"},
    "boolean": {"type": "boolean"},
    # date and ip types: accept strings (no further format enforcement).
    "date": {"type": "string"},
    "ip": {"type": "string"},
}


def _build_jsonschema_properties(properties: dict) -> dict:
    """Recursively convert OpenSearch properties to nested JSON Schema properties.

    Parameters
    ----------
    properties : dict
        The ``properties`` section of an OpenSearch index mapping.

    Returns
    -------
    dict
        A nested mapping of fields to their JSON Schema field definitions.
    """
    json_schema_props: dict = {}
    for field, mapping in properties.items():
        if "properties" in mapping:
            nested_schema = {
                "type": "object",
                "properties": _build_jsonschema_properties(mapping["properties"]),
            }
            if mapping.get("dynamic") == "strict":
                nested_schema["additionalProperties"] = False
            json_schema_props[field] = nested_schema
        else:
            os_type = mapping.get("type", "")
            base_type = _OPENSEARCH_TO_JSONSCHEMA_TYPE.get(os_type)
            if base_type:
                json_schema_props[field] = {
                    "anyOf": [
                        base_type,
                        {"type": "array", "items": base_type}
                    ]
                }
            else:
                json_schema_props[field] = {}
    return json_schema_props


def _opensearch_template_to_jsonschema(template: dict) -> dict:
    """Convert an OpenSearch index template to a nested JSON Schema.

    This function parses the nested OpenSearch mapping properties to produce a JSON
    Schema that can validate nested document objects directly.

    Parameters
    ----------
    template : dict
        Parsed content of an OpenSearch index template JSON file as
        downloaded from ``wazuh-indexer-plugins``.

    Returns
    -------
    dict
        A JSON Schema ``object`` that can be passed to
        :func:`jsonschema.validate`.  Returns an empty dict if the
        template does not contain a ``template.mappings.properties``
        section.
    """
    try:
        mappings = template["template"]["mappings"]
        properties = mappings.get("properties", {})
    except (KeyError, TypeError):
        return {}

    if not properties:
        return {}

    schema: dict = {
        "type": "object",
        "properties": _build_jsonschema_properties(properties),
    }

    # OpenSearch "strict" dynamic mode disallows unknown fields.
    if mappings.get("dynamic") == "strict":
        schema["additionalProperties"] = False

    return schema


class MetricsSnapshotTasks:
    DEFAULT_METRICS_FREQUENCY = 600
    DEFAULT_METRICS_BULK_SIZE = 100
    SCHEMA_VERSION = "1"

    def __init__(self, server, cluster_items: dict):
        self.server = server
        if server is not None and hasattr(server, "setup_task_logger"):
            self.logger = server.setup_task_logger("metrics_snapshot")
        else:
            self.logger = logging.getLogger("wazuh")

        master_interval = cluster_items.get("intervals", {}).get("master", {})
        if "metrics_frequency" not in master_interval:
            self.logger.warning(
                f"metrics_frequency not found in cluster configuration. Using default: {self.DEFAULT_METRICS_FREQUENCY}"
            )

        if "metrics_bulk_size" not in master_interval:
            self.logger.warning(
                f"metrics_bulk_size not found in cluster configuration. Using default: {self.DEFAULT_METRICS_BULK_SIZE}"
            )

        self.frequency = master_interval.get(
            "metrics_frequency", self.DEFAULT_METRICS_FREQUENCY
        )
        if 0 < self.frequency < self.DEFAULT_METRICS_FREQUENCY:
            self.logger.warning(
                f"Configured metrics_frequency ({self.frequency}s) is below the minimum allowed "
                f"({self.DEFAULT_METRICS_FREQUENCY}s). The value will be clamped to "
                f"{self.DEFAULT_METRICS_FREQUENCY}s (10m)."
            )
        self.bulk_size = master_interval.get(
            "metrics_bulk_size", self.DEFAULT_METRICS_BULK_SIZE
        )
        self._schema_cache: dict[str, dict | None] = {}

    async def run_metrics_snapshot(self):
        while True:
            if self.frequency == 0:
                self.logger.info("Metrics snapshot is disabled (metrics_frequency=0).")
                return
            await asyncio.sleep(max(self.frequency, self.DEFAULT_METRICS_FREQUENCY))
            try:
                await self._collect_and_index()
            except Exception:
                self.logger.exception("Metrics snapshot failed - skipping cycle")

    def _get_agents_sync(self):
        query = WazuhDBQueryAgents(limit=None)
        return query.run()["items"]

    async def _collect_agents(self, timestamp: str):
        loop = asyncio.get_running_loop()

        agents_data = await loop.run_in_executor(None, self._get_agents_sync)
        node_name = self.server.configuration.get("node_name", "unknown")
        cluster_name = self.server.configuration.get("cluster_name", "unknown")

        normalized = []
        for agent in agents_data:
            agent["@timestamp"] = timestamp
            agent["wazuh.cluster.node"] = node_name
            agent["wazuh.cluster.name"] = cluster_name
            normalized.append(self._normalize_agent_doc(agent))

        return normalized

    async def _collect_comms_all_nodes(self, timestamp: str) -> list:
        """Collect wazuh-remoted stats from all cluster nodes via DAPI fan-out.

        Parameters
        ----------
        timestamp : str
            ISO 8601 timestamp to inject into each document as ``@timestamp``.

        Returns
        -------
        list of dict
            Documents ready for bulk indexing into ``wazuh-metrics-comms``.
            Each document contains the remoted stats fields plus the metadata
            fields ``@timestamp``, ``wazuh.cluster.node``, and
            ``wazuh.cluster.name``.
        """
        local_node_name = self.server.configuration.get("node_name", "unknown")
        cluster_name = self.server.configuration.get("cluster_name", "unknown")

        all_node_names = [local_node_name]
        for worker_name in self.server.clients:
            all_node_names.append(worker_name)

        comms_data = []
        for node_name in all_node_names:
            try:
                if node_name == local_node_name:
                    result = get_daemons_stats(daemons_list=["wazuh-manager-remoted"])
                else:
                    result = await DistributedAPI(
                        f=get_daemons_stats,
                        f_kwargs={
                            "daemons_list": ["wazuh-manager-remoted"],
                            "node_list": [node_name],
                        },
                        logger=self.logger,
                        request_type="distributed_master",
                        is_async=False,
                        wait_for_complete=True,
                    ).distribute_function()

                for item in getattr(result, "affected_items", []):
                    doc = dict(item)
                    doc["@timestamp"] = timestamp
                    doc["wazuh.cluster.node"] = node_name
                    doc["wazuh.cluster.name"] = cluster_name
                    comms_data.append(self._normalize_comms_doc(doc))
            except Exception:
                self.logger.exception(
                    "Failed to collect comms stats from node '%s'", node_name
                )

        return comms_data

    @staticmethod
    def _drop_none(doc: dict) -> dict:
        """Recursively drop None values from a dictionary."""
        cleaned = {}
        for k, v in doc.items():
            if isinstance(v, dict):
                v = MetricsSnapshotTasks._drop_none(v)
            if v is not None:
                cleaned[k] = v
        return cleaned

    @staticmethod
    def _to_iso(value) -> str | None:
        """Convert a value to an ISO 8601 string.

        Handles ``datetime`` objects returned by ``WazuhDBQueryAgents`` as
        well as plain strings.  Returns *None* for falsy values so that
        ``_drop_none`` can remove the field.
        """
        if value is None:
            return None
        if isinstance(value, datetime):
            return value.strftime("%Y-%m-%dT%H:%M:%SZ")
        return str(value) if value else None

    @staticmethod
    def _normalize_agent_doc(doc: dict) -> dict:
        """Transform raw agent fields into the definitive index field names.

        Parameters
        ----------
        doc : dict
            Raw agent document from WazuhDBQueryAgents.

        Returns
        -------
        dict
            Normalized document ready for indexing into ``wazuh-metrics-agents``.
        """
        os_fields = doc.get("os", {})
        ip = doc.get("ip")
        raw_register_ip = doc.get("registerIP", "")

        register_ip = "0.0.0.0" if raw_register_ip == "any" else (raw_register_ip or None)
        group_config_status = doc.get("group_config_status", "")

        return MetricsSnapshotTasks._drop_none({
            "@timestamp": MetricsSnapshotTasks._to_iso(doc.get("@timestamp")),
            "wazuh": {
                "agent": {
                    "id": doc.get("id"),
                    "name": doc.get("name"),
                    "version": doc.get("version"),
                    "groups": doc.get("group", []),
                    "status": doc.get("status"),
                    "status_code": doc.get("status_code"),
                    "registered_at": MetricsSnapshotTasks._to_iso(doc.get("dateAdd")),
                    "last_seen": MetricsSnapshotTasks._to_iso(doc.get("lastKeepAlive")),
                    "disconnected_at": MetricsSnapshotTasks._to_iso(doc.get("disconnection_time")),
                    "register": {
                        "ip": register_ip
                    },
                    "host": {
                        "ip": [ip] if ip else [],
                        "architecture": os_fields.get("arch"),
                        "os": {
                            "name": os_fields.get("name"),
                            "version": os_fields.get("version"),
                            "platform": os_fields.get("platform"),
                            "full": os_fields.get("uname")
                        }
                    },
                    "config": {
                        "hash": {"md5": doc.get("configSum")},
                        "group": {
                            "synced": group_config_status == "synced",
                            "hash": {"md5": doc.get("mergedSum")}
                        }
                    }
                },
                "cluster": {
                    "name": doc.get("wazuh.cluster.name"),
                    "node": doc.get("wazuh.cluster.node")
                },
                "schema": {
                    "version": MetricsSnapshotTasks.SCHEMA_VERSION
                }
            }
        })

    @staticmethod
    def _normalize_comms_doc(doc: dict) -> dict:
        """Transform raw remoted stats fields into the definitive index field names.

        Parameters
        ----------
        doc : dict
            Raw comms document from DAPI fan-out.  Supports the v5.0 stats
            format where metrics are nested under a ``metrics`` key.

        Returns
        -------
        dict
            Normalized document ready for indexing into ``wazuh-metrics-comms``.
        """
        # v5.0 nests stats under "metrics"; fall back to flat keys for compat
        m = doc.get("metrics", {})
        bytes_info = m.get("bytes", {})
        queues = m.get("queues", {}).get("received", {})
        msgs_recv = m.get("messages", {}).get("received_breakdown", {})
        ctrl_bkdn = m.get("control_messages_queue_breakdown", {})

        raw_queue_usage = queues.get("usage")

        return MetricsSnapshotTasks._drop_none({
            "@timestamp": MetricsSnapshotTasks._to_iso(doc.get("@timestamp")),
            "wazuh": {
                "cluster": {
                    "name": doc.get("wazuh.cluster.name"),
                    "node": doc.get("wazuh.cluster.node")
                },
                "schema": {
                    "version": MetricsSnapshotTasks.SCHEMA_VERSION
                }
            },
            "event": {
                "module": "remoted"
            },
            "events": {
                "total": msgs_recv.get("event") or doc.get("evt_count")
            },
            "queue": {
                "size": raw_queue_usage,
                "capacity": queues.get("size") or doc.get("total_queue_size")
            },
            "tcp": {
                "sessions": m.get("tcp_sessions") or doc.get("tcp_sessions")
            },
            "discarded": {
                "total": msgs_recv.get("discarded") or doc.get("discarded_count")
            },
            "network": {
                "egress": {"bytes": bytes_info.get("sent") or doc.get("sent_bytes")},
                "ingress": {"bytes": bytes_info.get("received") or doc.get("recv_bytes")}
            },
            "messages": {
                "total": m.get("messages", {}).get("received_breakdown", {}).get("control")
                         or doc.get("ctrl_msg_count"),
                "control": {
                    "dropped_on_close": {
                        "total": msgs_recv.get("dequeued_after") or doc.get("dequeued_after_close")
                    },
                    "usage": m.get("control_messages_queue_usage") or doc.get("ctrl_msg_queue_usage"),
                    "received": {"total": ctrl_bkdn.get("inserted") or doc.get("ctrl_msg_queue_inserted")},
                    "replaced": {"total": ctrl_bkdn.get("replaced") or doc.get("ctrl_msg_queue_replaced")},
                    "processed": {"total": ctrl_bkdn.get("processed") or doc.get("ctrl_msg_processed")}
                }
            }
        })

    def _load_schema(self, schema_filename: str) -> dict | None:
        """Load and cache an OpenSearch index template schema.

        Looks for the schema file in :data:`wazuh.core.common.INDEXER_PLUGINS_PATH`.
        If the file is absent or cannot be parsed, a warning is logged and
        ``None`` is returned so that callers can skip validation gracefully.

        Parameters
        ----------
        schema_filename : str
            Basename of the JSON schema file (e.g.
            ``"metrics-agents.json"``).

        Returns
        -------
        dict or None
            Parsed JSON Schema ready for :func:`jsonschema.validate`, or
            ``None`` when the file is unavailable.
        """
        if schema_filename in self._schema_cache:
            return self._schema_cache[schema_filename]

        schema_path = os.path.join(common.INDEXER_PLUGINS_PATH, schema_filename)
        if not os.path.isfile(schema_path):
            self.logger.warning(
                "Metrics schema '%s' not found at '%s'. "
                "Schema validation will be skipped. "
                "Run 'make deps' to download the required schema files.",
                schema_filename,
                schema_path,
            )
            self._schema_cache[schema_filename] = None
            return None

        try:
            with open(schema_path) as f:
                template = json.load(f)
            schema = _opensearch_template_to_jsonschema(template)
            if not schema:
                self.logger.warning(
                    "Could not extract a valid JSON Schema from '%s'. "
                    "Schema validation will be skipped.",
                    schema_filename,
                )
                self._schema_cache[schema_filename] = None
                return None
            self._schema_cache[schema_filename] = schema
            return schema
        except Exception:
            self.logger.exception(
                "Failed to load metrics schema '%s'.", schema_filename
            )
            self._schema_cache[schema_filename] = None
            return None

    def _validate_documents(
        self, docs: list, schema: dict, index_name: str
    ) -> list:
        """Validate a list of documents against a JSON Schema, filtering invalid ones.

        Each document is validated independently.  Documents that fail
        validation are dropped and a detailed error is logged; valid
        documents are returned unchanged.

        Parameters
        ----------
        docs : list of dict
            Documents to validate before indexing.
        schema : dict
            JSON Schema to validate against (as returned by
            :func:`_opensearch_template_to_jsonschema`).
        index_name : str
            Target index name, used only for log messages.

        Returns
        -------
        list of dict
            Subset of ``docs`` that passed validation.
        """
        valid_docs = []
        for doc in docs:
            try:
                validate(instance=doc, schema=schema)
                valid_docs.append(doc)
            except ValidationError as exc:
                self.logger.error(
                    "Document failed schema validation for index '%s': %s",
                    index_name,
                    exc.message,
                )
        return valid_docs

    async def _collect_and_index(self):
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        agent_docs, comms_docs = await asyncio.gather(
            self._collect_agents(timestamp),
            self._collect_comms_all_nodes(timestamp),
        )

        agents_schema = self._load_schema("metrics-agents.json")
        comms_schema = self._load_schema("metrics-comms.json")

        if agents_schema:
            agent_docs = self._validate_documents(
                agent_docs, agents_schema, "wazuh-metrics-agents"
            )
        if comms_schema:
            comms_docs = self._validate_documents(
                comms_docs, comms_schema, "wazuh-metrics-comms"
            )

        async with get_indexer_client() as indexer:
            await asyncio.gather(
                indexer.metrics.bulk_index("wazuh-metrics-agents", agent_docs, self.bulk_size),
                indexer.metrics.bulk_index("wazuh-metrics-comms", comms_docs, self.bulk_size),
            )
