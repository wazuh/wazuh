import pytest
from unittest.mock import AsyncMock

from wazuh.core.indexer.bulk import Operation, BulkMetadata, BulkDoc, MixinBulk, RequiresClient


def test_bulk_action_values():
    """Test the values of the BulkAction enum."""
    assert Operation.CREATE.value == 'create'
    assert Operation.UPDATE.value == 'update'
    assert Operation.DELETE.value == 'delete'


def test_bulk_action_exists_with_valid_action():
    """Check that the `exists` method works as expected."""
    assert Operation.exists('create') is True
    assert Operation.exists('update') is True
    assert Operation.exists('delete') is True


def test_bulk_action_exists_with_invalid_action():
    """Check that the `exists` method works as expected with invalid options"""
    assert Operation.exists('invalid_action') is False
    assert Operation.exists('') is False
    assert Operation.exists('CREATE') is False


def test_bulk_metadata_decode():
    """Check that the `decode` method works as expected."""
    metadata = BulkMetadata(index='test_index', doc_id='1', operation=Operation.CREATE)
    expected_output = {'create': {'_index': 'test_index', '_id': '1'}}
    assert metadata.decode() == expected_output


@pytest.mark.parametrize(
    "index, doc_id, action, doc, expected_output",
    [
        (
            'test_index',
            '1',
            Operation.CREATE,
            {'field': 'value'},
            [{'create': {'_index': 'test_index', '_id': '1'}}, {'field': 'value'}],
        ),
        (
            'test_index',
            '1',
            Operation.UPDATE,
            {'field': 'value'},
            [{'update': {'_index': 'test_index', '_id': '1'}}, {'doc': {'field': 'value'}}],
        ),
        (
            'test_index',
            '1',
            Operation.DELETE,
            None,
            [{'delete': {'_index': 'test_index', '_id': '1'}}],
        ),
    ],
)
def test_bulk_doc_decode(index, doc_id, action, doc, expected_output):
    """Check that the `decode` method works as expected."""
    bulk_doc = BulkDoc(index=index, doc_id=doc_id, operation=action, doc=doc)
    assert bulk_doc.decode() == expected_output


def test_bulk_doc_create():
    """Check that the `create` method works as expected."""
    doc = {'field': 'value'}
    bulk_doc = BulkDoc.create(index='test_index', doc_id='1', doc=doc)
    assert bulk_doc.metadata.index == 'test_index'
    assert bulk_doc.metadata.doc_id == '1'
    assert bulk_doc.metadata.operation == Operation.CREATE
    assert bulk_doc.doc == doc


def test_bulk_doc_update():
    """Check that the `update` method works as expected."""
    doc = {'field': 'value'}
    bulk_doc = BulkDoc.update(index='test_index', doc_id='1', doc=doc)
    assert bulk_doc.metadata.index == 'test_index'
    assert bulk_doc.metadata.doc_id == '1'
    assert bulk_doc.metadata.operation == Operation.UPDATE
    assert bulk_doc.doc == doc


def test_bulk_doc_delete():
    """Check that the `delete` method works as expected."""
    bulk_doc = BulkDoc.delete(index='test_index', doc_id='1')
    assert bulk_doc.metadata.index == 'test_index'
    assert bulk_doc.metadata.doc_id == '1'
    assert bulk_doc.metadata.operation == Operation.DELETE
    assert bulk_doc.doc is None


@pytest.mark.asyncio
async def test_mixin_bulk():
    """Check that the `bulk` method works as expected."""
    class TestClient(MixinBulk):
        _client = AsyncMock()

    data = [
        BulkDoc.create(index='test_index', doc_id='1', doc={'field': 'value'}),
        BulkDoc.delete(index='test_index', doc_id='2'),
    ]

    test_instance = TestClient()

    await test_instance.bulk(data)

    expected_bulk_docs = [
        {'create': {'_index': 'test_index', '_id': '1'}},
        {'field': 'value'},
        {'delete': {'_index': 'test_index', '_id': '2'}},
    ]

    test_instance._client.bulk.assert_called_once_with(expected_bulk_docs)
