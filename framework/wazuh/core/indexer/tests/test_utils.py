import pytest
from wazuh.core.indexer import utils
from wazuh.core.indexer.constants import HITS_KEY, ID_KEY, SOURCE_KEY


@pytest.fixture
def search_result():
    return {HITS_KEY: {HITS_KEY: [{SOURCE_KEY: {ID_KEY: 1}}, {SOURCE_KEY: {ID_KEY: 2}}, {SOURCE_KEY: {ID_KEY: 3}}]}}


def test_get_source_items(search_result: dict):
    """Check the correct function of `get_source_items`."""
    output = [item for item in utils.get_source_items(search_result)]

    assert output == [{ID_KEY: 1}, {ID_KEY: 2}, {ID_KEY: 3}]


def test_get_source_items_id(search_result: dict):
    """Check the correct function of `get_source_items_id`."""
    output = utils.get_source_items_id(search_result)

    assert output == [1, 2, 3]
