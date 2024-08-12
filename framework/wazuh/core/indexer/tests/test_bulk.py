import pytest
from unittest.mock import AsyncMock

from wazuh.core.indexer.bulk import BulkAction, BulkMetadata, BulkDoc, MixinBulk, RequiresClient


def test_bulk_action_values():
    """Test the values of the BulkAction enum."""
    assert BulkAction.CREATE.value == "create"
    assert BulkAction.CREATE_OR_UPDATE.value == "index"
    assert BulkAction.UPDATE.value == "update"
    assert BulkAction.DELETE.value == "delete"


def test_bulk_metadata_decode():
    """Test decoding of BulkMetadata into a dictionary."""
    metadata = BulkMetadata(index="test_index", doc_id="1", action=BulkAction.CREATE)
    expected_output = {"create": {"_index": "test_index", "_id": "1"}}
    assert metadata.decode() == expected_output


@pytest.mark.parametrize(
    "index, doc_id, action, doc, expected_output",
    [
        (
            "test_index",
            "1",
            BulkAction.CREATE,
            {"field": "value"},
            [{"create": {"_index": "test_index", "_id": "1"}}, {"field": "value"}],
        ),
        (
            "test_index",
            "1",
            BulkAction.DELETE,
            None,
            [{"delete": {"_index": "test_index", "_id": "1"}}],
        ),
    ],
)
def test_bulk_doc_decode(index, doc_id, action, doc, expected_output):
    """Test decoding of BulkDoc into a list of dictionaries."""
    bulk_doc = BulkDoc(index=index, doc_id=doc_id, action=action, doc=doc)
    assert bulk_doc.decode() == expected_output


def test_bulk_doc_create():
    """Test the creation of a BulkDoc with the 'create' action."""
    doc = {"field": "value"}
    bulk_doc = BulkDoc.create(index="test_index", doc_id="1", doc=doc)
    assert bulk_doc.metadata.index == "test_index"
    assert bulk_doc.metadata.doc_id == "1"
    assert bulk_doc.metadata.action == BulkAction.CREATE
    assert bulk_doc.doc == doc


def test_bulk_doc_create_or_update():
    """Test the creation of a BulkDoc with the 'create_or_update' action."""
    doc = {"field": "value"}
    bulk_doc = BulkDoc.create_or_update(index="test_index", doc_id="1", doc=doc)
    assert bulk_doc.metadata.index == "test_index"
    assert bulk_doc.metadata.doc_id == "1"
    assert bulk_doc.metadata.action == BulkAction.CREATE_OR_UPDATE
    assert bulk_doc.doc == doc


def test_bulk_doc_update():
    """Test the creation of a BulkDoc with the 'update' action."""
    doc = {"field": "value"}
    bulk_doc = BulkDoc.update(index="test_index", doc_id="1", doc=doc)
    assert bulk_doc.metadata.index == "test_index"
    assert bulk_doc.metadata.doc_id == "1"
    assert bulk_doc.metadata.action == BulkAction.UPDATE
    assert bulk_doc.doc == doc


def test_bulk_doc_delete():
    """Test the creation of a BulkDoc with the 'delete' action."""
    bulk_doc = BulkDoc.delete(index="test_index", doc_id="1")
    assert bulk_doc.metadata.index == "test_index"
    assert bulk_doc.metadata.doc_id == "1"
    assert bulk_doc.metadata.action == BulkAction.DELETE
    assert bulk_doc.doc is None


@pytest.mark.asyncio
async def test_mixin_bulk():
    """Test the MixinBulk's bulk method."""
    class TestClient(MixinBulk):
        _client = AsyncMock()

    data = [
        BulkDoc.create(index="test_index", doc_id="1", doc={"field": "value"}),
        BulkDoc.delete(index="test_index", doc_id="2"),
    ]

    test_instance = TestClient()

    await test_instance.bulk(data)

    expected_bulk_docs = [
        {"create": {"_index": "test_index", "_id": "1"}},
        {"field": "value"},
        {"delete": {"_index": "test_index", "_id": "2"}},
    ]

    test_instance._client.bulk.assert_called_once_with(expected_bulk_docs)
