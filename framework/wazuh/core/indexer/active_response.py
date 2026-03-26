# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import json
import jsonschema
import logging
import os

from dataclasses import dataclass, field
from datetime import datetime, timezone
from time import perf_counter
from typing import Any, Dict, Optional, List, Callable, Tuple, Set

from wazuh.core import common
from wazuh.core.agent import WazuhDBQueryAgents
from wazuh.core.cluster.cluster import get_node
from wazuh.core.cluster.utils import ClusterFilter
from wazuh.core.exception import WazuhError, IndexerUnavailableError
from wazuh.core.indexer.indexer import get_indexer_client
from wazuh.core.wazuh_queue import WazuhQueue


AR_INDEX = "wazuh-active-responses*"
AR_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "properties": {
        "wazuh": {
            "type": "object",
            "properties": {
                "active_response": {
                    "type": "object",
                    "properties": {
                        "agent_id": {"type": "string"},
                        "executable": {"type": "string"},
                        "extra_arguments": {"type": "string"},
                        "location": {
                            "type": "string",
                            "enum": ["local", "all", "defined-agent"],
                        },
                        "name": {"type": "string"},
                        "stateful_timeout": {"type": "integer", "minimum": 0},
                        "type": {
                            "type": "string",
                            "enum": ["stateful", "stateless"],
                        },
                    },
                    "required": [
                        "executable",
                        "extra_arguments",
                        "location",
                        "name",
                        "type",
                    ],
                    "additionalProperties": False,
                    "allOf": [
                        {
                            "if": {"properties": {"type": {"const": "stateful"}}},
                            "then": {"required": ["stateful_timeout"]},
                        },
                        {
                            "if": {
                                "properties": {"location": {"const": "defined-agent"}}
                            },
                            "then": {"required": ["agent_id"]},
                        },
                    ],
                }
            },
            "required": ["active_response"],
            "additionalProperties": True,
        }
    },
    "required": ["wazuh"],
    "additionalProperties": True,
}

node_id = get_node().get("node")


@dataclass
class ActiveResponseBookmark:
    sort: list[Any] = field(default_factory=list)
    sort_fields: list[str] = field(default_factory=lambda: ["@timestamp", "_id"])
    only_events_after: int | None = None

    def build_sort(self) -> List[Dict[str, str]]:
        """Build the sort structure for OpenSearch queries.

        Returns
        -------
        List[Dict[str, str]]
            List of dictionaries defining the sort order.
        """
        return [{field: "asc"} for field in self.sort_fields]

    def to_search_after(self) -> Optional[List[Any]]:
        """Return the search_after parameter if sort data exists.

        Returns
        -------
        Optional[List[Any]]
            Sort values for pagination or None if empty.
        """
        return self.sort if self.sort else None

    def update(self, sort: List[Any]) -> None:
        """Update the internal sort state.

        Parameters
        ----------
        sort : List[Any]
            New sort values to store.
        """
        self.sort = sort


class ActiveResponseBookmarkFile(ActiveResponseBookmark):
    def __init__(self, path: str = common.AR_BOOKMARK_FILEPATH, **kwargs: Any):
        """Initialize the bookmark file handler.

        Parameters
        ----------
        path : str, optional
            Path to the bookmark JSON file.
        **kwargs : Any
            Additional arguments for the base class.
        """
        super().__init__(**kwargs)
        self.path = path
        self._load()

    def _load(self) -> None:
        """Load bookmark data from the JSON file."""
        if not os.path.exists(self.path):
            return

        try:
            with open(self.path, "r") as f:
                data = json.load(f)
                if data:
                    self.sort = data.get("sort", [])
                    self.sort_fields = data.get("sort_fields", self.sort_fields)
                    self.only_events_after = data.get("only_events_after")
        except (json.JSONDecodeError, IOError):
            pass

    def _save(self) -> None:
        """Persist current bookmark data to the JSON file."""
        data = {
            "sort": self.sort,
            "sort_fields": self.sort_fields,
            "only_events_after": self.only_events_after,
        }
        with open(self.path, "w") as f:
            json.dump(data, f, indent=4)
            f.flush()
            os.fsync(f.fileno())

    def ensure_only_events_after(self) -> int:
        """Set and save initial timestamp if not present.

        Returns
        -------
        int
            The UTC timestamp in milliseconds.
        """
        if self.only_events_after is None:
            self.only_events_after = int(datetime.now(timezone.utc).timestamp() * 1000)
            self._save()
        return self.only_events_after

    def update(self, sort: List[Any]) -> None:
        """Update the sort state and persist changes to disk.

        Parameters
        ----------
        sort : List[Any]
            New sort values to store and save.
        """
        if self.sort != sort:
            self.sort = sort
            self._save()


@dataclass
class ActiveResponse:
    """Represents a single Active Response with its associated data."""

    doc_source: Dict[str, Any]
    bookmark: ActiveResponseBookmark
    event: Optional[Dict[str, Any]] = None

    def target_agents(self, available_agents: List[str]) -> List[str]:
        """Determine target agent IDs based on AR location and availability.

        Parameters
        ----------
        available_agents : List[str]
            List of currently active agent IDs.

        Returns
        -------
        List[str]
            List of agent IDs that should receive the AR.
        """
        location = self.doc_source["wazuh"]["active_response"]["location"]

        match location:
            case "all":
                return available_agents

            case "local":
                agent_id = self.doc_source["wazuh"]["agent"]["id"]
                return [agent_id] if agent_id in available_agents else []

            case "defined-agent":
                agent_id = self.doc_source["wazuh"]["active_response"]["agent_id"]
                return [agent_id] if agent_id in available_agents else []

        return []


class ActiveResponseHelpers:
    logger = logging.getLogger("wazuh")

    @staticmethod
    def get_active_agents() -> List[str]:
        """Retrieve the list of active agents for the current node.

        Returns
        -------
        List[str]
            List of active agent IDs.
        """

        active_agents = []

        filters = {"status": "active", "node_name": node_id}

        try:
            with WazuhDBQueryAgents(
                limit=None, select=["id"], filters=filters
            ) as db_query:
                data = db_query.run()

            active_agents = [data["id"] for data in data["items"]]
        except WazuhError as e:
            ActiveResponseHelpers.logger.error(f"Error fetching active agents: {e}")

        return active_agents

    @staticmethod
    async def fetch_active_response_docs(
        bookmark: ActiveResponseBookmark, validate: bool = False, max: int = 1000
    ) -> List[Dict[str, Any]]:
        """Fetch active response documents incrementally from OpenSearch.

        Parameters
        ----------
        bookmark : ActiveResponseBookmark
            Object containing pagination and filtering state.
        validate : bool, optional
            Whether to validate documents against the JSON schema, by default False.
        max : int, optional
            Maximum number of documents to retrieve, by default 1000.

        Returns
        -------
        List[Dict[str, Any]]
            List of OpenSearch hits matching the query.
        """

        query = {
            "size": max,
            "sort": bookmark.build_sort(),
            "query": {
                "bool": {
                    "filter": [],
                    "must_not": [{ "regexp": {"wazuh.agent.version": "v[0-4]\\..*" }}],
                }
            },
        }

        search_after = bookmark.to_search_after()

        if search_after:
            query["search_after"] = search_after
        else:
            start_ts = bookmark.ensure_only_events_after()
            query["query"]["bool"]["filter"].append(
                {"range": {"@timestamp": {"gte": start_ts}}}
            )

        ActiveResponseHelpers.logger.debug(f"Documents retrieval query: {query}")

        # Execute search
        async with get_indexer_client() as client:
            resp = await client.search(index=AR_INDEX, body=query)

        docs = []

        ActiveResponseHelpers.logger.debug(
            f"{ len(resp['hits']['hits']) or  'No' } active reponse documents fetched."
        )

        for doc in resp["hits"]["hits"]:
            try:
                if validate:
                    jsonschema.validate(instance=doc["_source"], schema=AR_SCHEMA)
                docs.append(doc)
            except jsonschema.ValidationError as e:
                ActiveResponseHelpers.logger.debug(
                    f"Discarding active response document `{doc['_id']}` (`{doc['_index']}`). Reason: {e})"
                )

        return docs

    @staticmethod
    async def get_events_by_ar(ars: List[ActiveResponse]) -> Dict[str, Dict[str, Any]]:
        """Retrieve the events associated with the given active responses.

        Parameters
        ----------
        ars : List[ActiveResponse]
            List of active response objects to enrich.

        Returns
        -------
        Dict[str, Dict[str, Any]]
            Dictionary structured as {index: {doc_id: event_source}}.
        """

        # Group by index
        docs_by_index: Dict[str, Set[str]] = {}

        for ar in ars:
            index = ar.doc_source["event"]["index"]
            doc_id = ar.doc_source["event"]["doc_id"]

            docs_by_index.setdefault(index, set()).add(doc_id)

        events = {}

        if docs_by_index:
            ActiveResponseHelpers.logger.debug(f"Fetching events: {docs_by_index}")

        async with get_indexer_client() as client:
            for index, doc_ids in docs_by_index.items():
                resp = await client.mget(index=index, body={"ids": list(doc_ids)})
                for event in resp.get("docs", []):
                    if event.get("found"):
                        idx = event["_index"]
                        doc_id = event["_id"]
                        events.setdefault(idx, {})[doc_id] = event["_source"]

        return events

    @staticmethod
    def build_ar_messages(
        ars: List[ActiveResponse], agents: List[str]
    ) -> List[Tuple[str, Dict[str, Any], ActiveResponseBookmark]]:
        """Build messages to be sent to agents based on ARs and events.

        Parameters
        ----------
        ars : List[ActiveResponse]
            List of active response objects.
        agents : List[str]
            List of active agent IDs.

        Returns
        -------
        List[Tuple[str, Dict[str, Any], ActiveResponseBookmark]]
            Tuples of (agent_id, message_dict, bookmark_object).
        """

        def format_message(
            ar_source: Dict[str, Any], event: Optional[Dict[str, Any]] = None
        ) -> Dict[str, Any]:
            """Merge AR and event data into a single message.

            Parameters
            ----------
            ar_source : Dict[str, Any]
                Source document of the AR.
            event : Optional[Dict[str, Any]], optional
                Source document of the associated event, by default None.

            Returns
            -------
            Dict[str, Any]
                Formatted message for the agent.
            """

            wazuh = ar_source.get("wazuh", {}).copy()

            if event:
                msg = {**ar_source, **event}
                event_wazuh = event.get("wazuh", {})
                wazuh = {**event_wazuh, **wazuh}

            else:
                msg = dict(ar_source)

            msg["wazuh"] = wazuh

            return msg

        messages = []

        for ar in ars:
            for agent_id in ar.target_agents(agents):
                messages.append(
                    (agent_id, format_message(ar.doc_source, ar.event), ar.bookmark)
                )

        return messages

    @staticmethod
    def is_valid_agent(ar: ActiveResponse, available_agents: List[str]) -> bool:
        """Check if the AR is valid for the given available agents.

        Parameters
        ----------
        ar : ActiveResponse
            The active response object to check.
        available_agents : List[str]
            List of available agent IDs.

        Returns
        -------
        bool
            True if the AR targets at least one available agent.
        """
        return ar.target_agents(available_agents) != []


class ActiveResponseBuilder:
    def __init__(
        self,
        logger: logging.Logger,
        active_agents: Optional[List[str]] = None,
        bookmark_file: Optional[ActiveResponseBookmarkFile] = None,
    ):
        """Initialize the AR builder.

        Parameters
        ----------
        logger : logging.Logger
            Logger instance for reporting.
        active_agents : Optional[List[str]], optional
            List of active agents, by default None (retrieves automatically).
        bookmark_file : Optional[ActiveResponseBookmarkFile], optional
            Bookmark handler, by default None (creates new).
        """
        self.logger = logger
        self._active_agents = (
            active_agents
            if active_agents is not None
            else ActiveResponseHelpers.get_active_agents()
        )
        self._ars: List[ActiveResponse] = []
        self._bookmark_file = (
            bookmark_file if bookmark_file is not None else ActiveResponseBookmarkFile()
        )

    def get_target_agents(self) -> List[str]:
        """Return the target active agents.

        Returns
        -------
        List[str]
            List of active agent IDs.
        """
        return self._active_agents

    async def fetch_ars(self, validate: bool = True) -> "ActiveResponseBuilder":
        """Fetch AR documents and initialize objects.

        Parameters
        ----------
        validate : bool, optional
            Whether to validate docs against schema, by default True.

        Returns
        -------
        ActiveResponseBuilder
            The builder instance.
        """
        docs = await ActiveResponseHelpers.fetch_active_response_docs(
            self._bookmark_file, validate=validate
        )
        self._ars = [
            ActiveResponse(
                doc_source=doc["_source"], bookmark=ActiveResponseBookmark(doc["sort"])
            )
            for doc in docs
        ]
        return self

    def filter(self, fn: Callable[[ActiveResponse], bool]) -> "ActiveResponseBuilder":
        """Filter the active responses based on a provided function.

        Parameters
        ----------
        fn : Callable[[ActiveResponse], bool]
            Predicate function for filtering.

        Returns
        -------
        ActiveResponseBuilder
            The builder instance.
        """
        self._ars = [ar for ar in self._ars if fn(ar)]
        return self

    async def enrich_ar_with_events_info(
        self, allow_empty_event: bool = False
    ) -> "ActiveResponseBuilder":
        """Enrich active responses with their associated event data.

        Parameters
        ----------
        allow_empty_event : bool, optional
            Whether to keep ARs when the event is missing, by default False.

        Returns
        -------
        ActiveResponseBuilder
            The builder instance.
        """

        events = await ActiveResponseHelpers.get_events_by_ar(self._ars)

        ars_with_events = []

        for ar in self._ars:
            try:
                index_id = ar.doc_source["event"]["index"]
                event_id = ar.doc_source["event"]["doc_id"]
                ar.event = events[index_id][event_id]
                ars_with_events.append(ar)
            except KeyError:
                self.logger.debug(
                    f"Expected event `{event_id}` (`{index_id}`) not found."
                    f"{' Discarding related active response.' if not allow_empty_event else ''}"
                )
                if allow_empty_event:
                    ars_with_events.append(ar)

        self._ars = ars_with_events

        return self

    def keep_only_active_agents_ars(self) -> "ActiveResponseBuilder":
        """Keep only active responses for agents that are currently active.

        Returns
        -------
        ActiveResponseBuilder
            The builder instance.
        """

        if not self._ars:
            return self

        self.logger.debug(
            f"Keeping only active responses for agents {self._active_agents}."
        )

        last_ar_bookmark = self._ars[-1].bookmark.sort

        self.filter(
            lambda ar: ActiveResponseHelpers.is_valid_agent(ar, self._active_agents)
        )

        if not self._ars:
            self.logger.debug(
                f"No active responses left after filtering active agents. "
                f"Moving the bookmark to the last fetched active response (`{last_ar_bookmark}`)."
            )
            self._bookmark_file.update(last_ar_bookmark)

        return self

    def dispatch(self) -> "ActiveResponseBuilder":
        """Dispatch active responses to their target agents.

        Returns
        -------
        ActiveResponseBuilder
            The builder instance.
        """
        msgs = ActiveResponseHelpers.build_ar_messages(self._ars, self._active_agents)

        if not msgs:
            return self

        msgs_sent = 0

        with WazuhQueue(common.AR_SOCKET) as wq:
            for agent_id, msg, bookmark in msgs:
                try:
                    wq.send_msg_to_agent(
                        msg=json.dumps(msg), agent_id=agent_id, msg_type=WazuhQueue.AR_TYPE
                    )
                    msgs_sent += 1
                except WazuhError as e:
                    self.logger.error(
                        f"Failed to send active response message to agent `{agent_id}`: {e}"
                    )
                finally:
                    # Bookmark is updated no matter the dispatch result.
                    self._bookmark_file.update(bookmark.sort)

        self.logger.info(
            f"Dispatched {msgs_sent}/{len(msgs)} messages to agents"
            f" from {len(self._ars)} active responses."
        )

        return self


class ActiveResponseFetchTask:
    DEFAULT_POLLING_INTERVAL = 60

    def __init__(self, server: Any):
        """Initialize the AR fetch task.

        Parameters
        ----------
        server : Any
            The server instance containing configuration.
        """
        self.logger = server.logger.getChild("ar")
        self.logger.addFilter(ClusterFilter(tag=server.tag, subtag="Active Response"))

        self.polling_interval: int = (
            server.cluster_items.get("intervals", {})
            .get("common", {})
            .get(
                "active_response_polling",
                self.DEFAULT_POLLING_INTERVAL,
            )
        )
        ActiveResponseHelpers.logger = self.logger

    async def active_response_processing(self) -> None:
        """Execute one full cycle of AR processing.

        Raises
        ------
        WazuhException
            If there is a connection issue with the indexer.
        """
        try:
            builder = ActiveResponseBuilder(logger=self.logger)
            await builder.fetch_ars(validate=True)
            builder.keep_only_active_agents_ars()
            await builder.enrich_ar_with_events_info()
            builder.dispatch()
        except IndexerUnavailableError:
            self.logger.warning("Cannot connect to Wazuh Indexer")

    async def run(self) -> None:
        """Run the task loop indefinitely."""
        while True:
            before = perf_counter()
            self.logger.info("Starting")
            try:
                await self.active_response_processing()
            except Exception as e:
                self.logger.error(
                    f"Error during active response processing: {e}.",
                )
            finally:
                after = perf_counter()
                self.logger.info(f"Finished in {(after - before):.3f}s.")

            await asyncio.sleep(self.polling_interval)
