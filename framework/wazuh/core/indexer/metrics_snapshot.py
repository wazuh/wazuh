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


def _flatten_opensearch_properties(properties: dict, prefix: str = "") -> dict:
    """Recursively flatten nested OpenSearch mapping properties to dotted keys.

    Parameters
    ----------
    properties : dict
        The ``properties`` section of an OpenSearch index mapping.
    prefix : str
        Dot-separated path prefix accumulated during recursion.

    Returns
    -------
    dict
        A flat mapping of dotted field paths to their OpenSearch field
        definitions, e.g. ``{"wazuh.agent.id": {"type": "keyword"}}``.
    """
    flat: dict = {}
    for key, value in properties.items():
        full_key = f"{prefix}.{key}" if prefix else key
        if "properties" in value:
            flat.update(_flatten_opensearch_properties(value["properties"], full_key))
        else:
            flat[full_key] = value
    return flat


def _opensearch_template_to_jsonschema(template: dict) -> dict:
    """Convert an OpenSearch index template to a flat JSON Schema.

    The document format used by ``MetricsSnapshotTasks`` stores all fields
    as top-level dotted keys (e.g. ``"wazuh.agent.id"``).  This function
    flattens the nested OpenSearch mapping properties to produce a JSON
    Schema that can validate those flat-key documents directly.

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

    flat_props = _flatten_opensearch_properties(properties)
    if not flat_props:
        return {}

    json_schema_props: dict = {}
    for field, mapping in flat_props.items():
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

    schema: dict = {
        "type": "object",
        "properties": json_schema_props,
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
        return {k: v for k, v in doc.items() if v is not None}

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
        register_ip = "0.0.0.0/0" if raw_register_ip == "any" else (raw_register_ip or None)
        group_config_status = doc.get("group_config_status", "")

        return MetricsSnapshotTasks._drop_none({
            "@timestamp": doc.get("@timestamp"),
            "wazuh.agent.id": doc.get("id"),
            "wazuh.agent.name": doc.get("name"),
            "wazuh.agent.version": doc.get("version"),
            "wazuh.agent.groups": doc.get("group", []),
            "wazuh.agent.host.ip": [ip] if ip else [],
            "wazuh.agent.register.ip": register_ip,
            "wazuh.agent.status": doc.get("status"),
            "wazuh.agent.status_code": doc.get("status_code"),
            "wazuh.agent.registered_at": doc.get("dateAdd"),
            "wazuh.agent.last_seen": doc.get("lastKeepAlive"),
            "wazuh.agent.disconnected_at": doc.get("disconnection_time") or None,
            "wazuh.agent.config.group.synced": group_config_status == "synced",
            "wazuh.agent.config.group.hash.md5": doc.get("mergedSum"),
            "wazuh.agent.host.architecture": os_fields.get("arch"),
            "wazuh.agent.host.os.name": os_fields.get("name"),
            "wazuh.agent.host.os.version": os_fields.get("version"),
            "wazuh.agent.host.os.platform": os_fields.get("platform"),
            "wazuh.cluster.name": doc.get("wazuh.cluster.name"),
            "wazuh.cluster.node": doc.get("wazuh.cluster.node"),
            "wazuh.schema.version": MetricsSnapshotTasks.SCHEMA_VERSION,
        })

    @staticmethod
    def _normalize_comms_doc(doc: dict) -> dict:
        """Transform raw remoted stats fields into the definitive index field names.

        Parameters
        ----------
        doc : dict
            Raw comms document from DAPI fan-out.

        Returns
        -------
        dict
            Normalized document ready for indexing into ``wazuh-metrics-comms``.
        """
        raw_queue_size = doc.get("queue_size")

        return MetricsSnapshotTasks._drop_none({
            "@timestamp": doc.get("@timestamp"),
            "wazuh.cluster.name": doc.get("wazuh.cluster.name"),
            "wazuh.cluster.node": doc.get("wazuh.cluster.node"),
            "wazuh.schema.version": MetricsSnapshotTasks.SCHEMA_VERSION,
            "events.module": "remoted",
            "queue.usage": str(raw_queue_size) if raw_queue_size is not None else None,
            "queue.capacity": doc.get("total_queue_size"),
            "tcp.sessions": doc.get("tcp_sessions"),
            "discarded.total": doc.get("discarded_count"),
            "events.total": doc.get("evt_count"),
            "network.egress.bytes": doc.get("sent_bytes"),
            "network.ingress.bytes": doc.get("recv_bytes"),
            "messages.total": doc.get("ctrl_msg_count"),
            "messages.control.dropped_on_close.total": doc.get("dequeued_after_close"),
            "messages.control.usage": doc.get("ctrl_msg_queue_usage"),
            "messages.control.received.total": doc.get("ctrl_msg_queue_inserted"),
            "messages.control.replaced.total": doc.get("ctrl_msg_queue_replaced"),
            "messages.control.processed.total": doc.get("ctrl_msg_processed"),
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
