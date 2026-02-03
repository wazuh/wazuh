import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from opensearchpy import AsyncOpenSearch
from wazuh.core.indexer.base import IndexerKey


class MaxVersionIndex:
    """
    Indexer client for disconnected agents operations.
    """

    STATE_INDEX_PATTERN = "wazuh-states-*"
    MODULE_INDICES_MAP = {
        "fim": [
            "wazuh-states-fim-files",
            "wazuh-states-fim-registry-keys",
            "wazuh-states-fim-registry-values",
        ],
        "sca": [
            "wazuh-states-sca",
        ],
        "syscollector": [
            "wazuh-states-inventory-system",
            "wazuh-states-inventory-hardware",
            "wazuh-states-inventory-hotfixes",
            "wazuh-states-inventory-packages",
            "wazuh-states-inventory-processes",
            "wazuh-states-inventory-ports",
            "wazuh-states-inventory-interfaces",
            "wazuh-states-inventory-protocols",
            "wazuh-states-inventory-networks",
            "wazuh-states-inventory-users",
            "wazuh-states-inventory-groups",
            "wazuh-states-inventory-services",
            "wazuh-states-inventory-browser-extensions",
            "wazuh-states-vulnerabilities",
        ],
    }

    def __init__(self, client: AsyncOpenSearch) -> None:
        """
        Initialize the MaxVersionIndex.

        Parameters
        ----------
        client : AsyncOpenSearch
            Asynchronous OpenSearch client used to perform index operations.

        Returns
        -------
        None
        """
        super().__init__()
        self._client = client

    async def search(
        self,
        query: dict,
        select: Optional[str] = None,
        exclude: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        sort: Optional[str] = None,
    ) -> dict:
        """Perform a search operation with the given query.

        Parameters
        ----------
        query : dict
            DSL query.
        select : Optional[str], optional
            A comma-separated list of fields to include in the response, by default None.
        exclude : Optional[str], optional
            A comma-separated list of fields to exclude from the response, by default None.
        offset : Optional[int], optional
            The starting index to search from, by default None.
        limit : Optional[int], optional
            How many results to include in the response, by default None.
        sort : Optional[str], optional
            A comma-separated list of fields to sort by, by default None.

        Returns
        -------
        dict
            The search result.
        """
        parameters = {
            IndexerKey.INDEX: self.STATE_INDEX_PATTERN,
            IndexerKey.BODY: query,
        }
        results = await self._client.search(
            **parameters,
            _source_includes=select,
            _source_excludes=exclude,
            size=limit,
            from_=offset,
            sort=sort,
        )
        return results

    async def update_agent_groups(
        self,
        agent_id: str,
        groups: List[str],
        global_version: int,
        refresh: bool = True,
    ) -> Dict[str, dict]:
        """
        Update agent groups across all state indices for an agent.

        Parameters
        ----------
        agent_id : str
            Agent identifier to match documents.
        groups : List[str]
            New list of groups to set on the agent document.
        global_version : int
            Global document version used to compare and set ``state.document_version``.
        refresh : bool, optional
            Whether to refresh the index after the update (default True).

        Returns
        -------
        Dict[str, dict]
            A mapping of index name to the OpenSearch response or an error object.

        Notes
        -----
        The method performs an ``update_by_query`` for each index defined in
        ``MODULE_INDICES_MAP``. Documents that already have the same groups will
        be skipped by setting the operation to ``noop`` in the painless script.
        """

        body = {
            "query": {
                "bool": {
                    "must": [{"term": {"wazuh.agent.id": agent_id}}],
                    "should": [
                        {
                            "bool": {
                                "must_not": {
                                    "exists": {"field": "state.document_version"}
                                }
                            }
                        },
                        {"range": {"state.document_version": {"lte": global_version}}},
                    ],
                    "minimum_should_match": 1,
                }
            },
            "script": {
                "lang": "painless",
                "source": """
                    if (ctx._source.agent.groups == params.groups) {
                        ctx.op = "noop";
                        return;
                    }

                    ctx._source.agent.groups = params.groups;

                    if (ctx._source.state == null) {
                        ctx._source.state = [:];
                    }
                    ctx._source.state.document_version = params.globalVersion;
                    ctx._source.state.modified_at = params.timestamp;
                """,
                "params": {
                    "groups": groups,
                    "globalVersion": global_version,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
            },
        }

        results: Dict[str, dict] = {}
        summary: Dict[str, Any] = {"index": [], "updated_documents": 0}

        for module, indices in self.MODULE_INDICES_MAP.items():
            for index in indices:
                try:
                    response = await self._client.update_by_query(
                        index=index,
                        body=body,
                        refresh=refresh,
                        conflicts="proceed",
                    )
                    results[index] = response
                    summary["module"] = module
                    summary["index"].append(index)
                    documents_updated = response.get("updated", 0)
                    summary["updated_documents"] += documents_updated

                    logging.getLogger("wazuh").debug(
                        f"[{module}] Updated agent_id={agent_id} " f"index={index}"
                    )

                except Exception as e:
                    logging.getLogger("wazuh").error(
                        f"[{module}] Failed updating index={index} "
                        f"agent_id={agent_id}: {e}"
                    )
                    results[index] = {"error": str(e)}
            logging.getLogger("wazuh").info(f"Summary: {summary}")
            summary["index"] = []
            summary["updated_documents"] = 0

        return results

    async def update_agent_cluster_name(
        self,
        agent_id: str,
        cluster_name: str,
        global_version: int,
        refresh: bool = True,
    ) -> Dict[str, dict]:
        """
        Update the cluster name across all state indices for an agent.

        Parameters
        ----------
        agent_id : str
            Agent identifier to match documents.
        cluster_name : str
            Cluster name to set on the agent document (``wazuh.cluster.name``).
        global_version : int
            Global document version to compare and set ``state.document_version``.
        refresh : bool, optional
            Whether to refresh the index after the update (default True).

        Returns
        -------
        Dict[str, dict]
            A mapping of index name to the OpenSearch response or an error object.

        Notes
        -----
        Mirrors ``update_agent_groups`` behavior but targets the
        ``wazuh.cluster.name`` field. Documents with the same cluster name are
        skipped by the painless script using a ``noop`` operation.
        """
        body = {
            "query": {
                "bool": {
                    "must": [{"term": {"agent.id": agent_id}}],
                    "should": [
                        {
                            "bool": {
                                "must_not": {
                                    "exists": {"field": "state.document_version"}
                                }
                            }
                        },
                        {"range": {"state.document_version": {"lte": global_version}}},
                    ],
                    "minimum_should_match": 1,
                }
            },
            "script": {
                "lang": "painless",
                "source": """
                    if (ctx._source.wazuh == null) { ctx._source.wazuh = [:]; }
                    if (ctx._source.wazuh.cluster == null) { ctx._source.wazuh.cluster = [:]; }

                    if (ctx._source.wazuh.cluster.name == params.clusterName) {
                        ctx.op = "noop";
                        return;
                    }
                    ctx._source.wazuh.cluster.name = params.clusterName;
                    if (ctx._source.state == null) { ctx._source.state = [:]; }
                    ctx._source.state.document_version = params.globalVersion;
                    ctx._source.state.modified_at = params.timestamp;
                """,
                "params": {
                    "clusterName": cluster_name,
                    "globalVersion": global_version,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
            },
        }

        results: Dict[str, dict] = {}
        summary: Dict[str, Any] = {"index": [], "updated_documents": 0}

        for module, indices in self.MODULE_INDICES_MAP.items():
            for index in indices:
                try:
                    response = await self._client.update_by_query(
                        index=index,
                        body=body,
                        refresh=refresh,
                        conflicts="proceed",
                    )
                    results[index] = response
                    summary["module"] = module
                    summary["index"].append(index)
                    documents_updated = response.get("updated", 0)
                    summary["updated_documents"] += documents_updated

                    logging.getLogger("wazuh").debug(
                        f"[{module}] Updated cluster name for agent_id={agent_id} index={index}"
                    )

                except Exception as e:
                    logging.getLogger("wazuh").error(
                        f"[{module}] Failed updating index={index} agent_id={agent_id}: {e}"
                    )
                    results[index] = {"error": str(e)}
            logging.getLogger("wazuh").info(f"Summary: {summary}")
            summary["index"] = []
            summary["updated_documents"] = 0

        return results
