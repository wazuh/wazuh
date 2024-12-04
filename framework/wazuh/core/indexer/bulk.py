from typing import Optional, Dict, Any, List, Protocol, Coroutine
from enum import Enum

from opensearchpy import AsyncOpenSearch

from wazuh.core.indexer.base import IndexerKey


class Operation(str, Enum):
    """Enum representing bulk operations for the indexer.

    Attributes
    ----------
    CREATE : str
        Operation to create a new document.
    UPDATE : str
        Operation to update an existing document.
    DELETE : str
        Operation to delete an existing document.
    """
    CREATE = 'create'
    UPDATE = 'update'
    DELETE = 'delete'

    @classmethod
    def exists(cls, operation: str) -> bool:
        try:
            cls(operation)
        except ValueError:
            return False
        return True


class BulkMetadata:
    """Class to handle metadata for a bulk operation in the Indexer.

    Parameters
    ----------
    index : str
        Name of the index in the Indexer.
    doc_id : Optional[str]
        ID of the document in the Indexer. Can be None for certain operations.
    operation : Operation
        Type of operation to perform.
    """
    def __init__(self, index: str, doc_id: Optional[str], operation: Operation):
        self.index = index
        self.doc_id = doc_id
        self.operation = operation

    def decode(self) -> Dict[str, Dict[str, str]]:
        """Decode metadata into a dictionary format for the Indexer bulk API.

        Returns
        -------
        Dict[str, Dict[str, str]]
            Metadata in a dictionary format.
        """
        return {str(self.operation.value): {'_index': self.index, '_id': self.doc_id}}


class BulkDoc:
    """Class to represent a bulk document operation for the Indexer.

    Parameters
    ----------
    index : str
        Name of the index in the Indexer.
    doc_id : Optional[str]
        ID of the document in the Indexer. Can be None for certain operations.
    operation : Operation
        Type of operation to perform.
    doc : Optional[Any]
        Document content. Can be None for delete operations.
    """
    def __init__(self, index: str, doc_id: Optional[str], operation: Operation, doc: Optional[Any]):
        self.metadata = BulkMetadata(index=index, doc_id=doc_id, operation=operation)
        self.doc = doc

    def decode(self) -> List[Dict]:
        """Decode the bulk document and its metadata into a list of dictionaries.

        Returns
        -------
        List[Dict]
            List of dictionaries representing the bulk operation.
        """
        if self.doc is None:
            return [self.metadata.decode()]
        else:
            if self.metadata.operation == Operation.UPDATE:
                self.doc = {IndexerKey.DOC: self.doc}
            return [self.metadata.decode(), self.doc]

    @classmethod
    def create(cls, index: str, doc_id: Optional[str], doc: Any) -> 'BulkDoc':
        """Create a new BulkDoc instance with the 'create' operation.

        Parameters
        ----------
        index : str
            Name of the index in the Indexer.
        doc_id : Optional[str]
            ID of the document in the Indexer.
        doc : Any
            Document content.

        Returns
        -------
        BulkDoc
            Instance of BulkDoc with the 'create' operation.
        """
        return cls(index=index, doc_id=doc_id, operation=Operation.CREATE, doc=doc)

    @classmethod
    def update(cls, index: str, doc_id: str, doc: Any) -> 'BulkDoc':
        """Create a new BulkDoc instance with the 'update' operation.

        Parameters
        ----------
        index : str
            Name of the index in the Indexer.
        doc_id : str
            ID of the document in the Indexer.
        doc : Any
            Document content.

        Returns
        -------
        BulkDoc
            Instance of BulkDoc with the 'update' operation.
        """
        return cls(index=index, doc_id=doc_id, operation=Operation.UPDATE, doc=doc)

    @classmethod
    def delete(cls, index: str, doc_id: str) -> 'BulkDoc':
        """Create a new BulkDoc instance with the 'delete' operation.

        Parameters
        ----------
        index : str
            Name of the index in the Indexer.
        doc_id : str
            ID of the document in the Indexer.

        Returns
        -------
        BulkDoc
            Instance of BulkDoc with the 'delete' operation.
        """
        return cls(index=index, doc_id=doc_id, operation=Operation.DELETE, doc=None)


class RequiresClient(Protocol):
    """Protocol to ensure that a class has a _client attribute of type AsyncOpenSearch."""
    _client: AsyncOpenSearch


class MixinBulk:
    """Mixin to add bulk operation functionality to a class.
    This Mixin requires that the class using it has an attribute `_client` of type `AsyncOpenSearch`.
    """
    async def bulk(self: RequiresClient, data: List[BulkDoc]) -> Coroutine:
        """Execute a bulk operation using the provided list of `BulkDoc` instances.

        Parameters
        ----------
        data : List[BulkDoc]
            List of BulkDoc instances representing the bulk operations to be performed.

        Returns
        -------
        Coroutine
            Coroutine that performs the bulk operation in the Indexer.
        """
        bulk_docs = []
        for doc in data:
            bulk_docs += doc.decode()

        return await self._client.bulk(bulk_docs)
