from wazuh.core.indexer.base import BaseIndex
from wazuh.core.indexer.bulk import MixinBulk

from opensearchpy import AsyncOpenSearch

HARDCODED_EVENTS_INDEX_NAME = "events"


class EventsIndex(BaseIndex, MixinBulk):
    """A class to interact with the Events index in OpenSearch."""

    INDEX = HARDCODED_EVENTS_INDEX_NAME

    def __init__(self, client: AsyncOpenSearch):
        super().__init__(client)
