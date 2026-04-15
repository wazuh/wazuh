# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging
from typing import List

from opensearchpy import AsyncOpenSearch
from opensearchpy.helpers import async_bulk


class MetricsIndex:
    """
    Indexer client for metrics snapshot bulk indexing operations.
    """

    def __init__(self, client: AsyncOpenSearch) -> None:
        """
        Initialize the MetricsIndex.

        Parameters
        ----------
        client : AsyncOpenSearch
            Asynchronous OpenSearch client used to perform index operations.
        """
        super().__init__()
        self._client = client
        self._logger = logging.getLogger('wazuh').getChild('MetricsIndex')

    async def bulk_index(self, index: str, docs: List[dict], bulk_size: int) -> None:
        """
        Bulk index a list of documents into the given data stream.

        Parameters
        ----------
        index : str
            Target data stream name (e.g. ``wazuh-metrics-agents``).
        docs : List[dict]
            List of document dicts to index.
        bulk_size : int
            Number of documents per bulk request chunk, mapped from
            ``metrics_bulk_size`` in ``cluster.json``.

        Returns
        -------
        None

        Notes
        -----
        Uses ``_op_type: create`` because data streams only support
        append operations. ``raise_on_error=False`` ensures individual
        document failures do not crash the cluster task.
        """
        actions = (
            {
                "_op_type": "create",
                "_index": index,
                "_source": doc,
            }
            for doc in docs
        )
        success, failed = await async_bulk(
            self._client,
            actions,
            chunk_size=bulk_size,
            raise_on_error=False,
        )
        if failed:
            self._logger.warning(
                "Metrics bulk index on '%s': %d indexed, %d failed", index, success, failed
            )
