import pytest
from wazuh.core.indexer import utils
from wazuh.core.indexer.base import IndexerKey


@pytest.fixture
def search_result():
    return {IndexerKey.HITS: {IndexerKey.HITS: [
        {IndexerKey._ID: 1, IndexerKey._SOURCE: {'name': 'test1'}},
        {IndexerKey._ID: 2, IndexerKey._SOURCE: {'name': 'test2'}},
        {IndexerKey._ID: 3, IndexerKey._SOURCE: {'name': 'test3'}}
    ]}}


def test_get_source_items(search_result: dict):
    """Check the correct function of `get_source_items`."""
    output = [item for item in utils.get_source_items(search_result)]

    assert output == [{'name': 'test1'}, {'name': 'test2'}, {'name': 'test3'}]


def test_get_source_items_id(search_result: dict):
    """Check the correct function of `get_source_items_id`."""
    output = utils.get_document_ids(search_result)

    assert output == [1, 2, 3]
