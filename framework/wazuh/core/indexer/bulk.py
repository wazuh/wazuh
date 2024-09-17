from typing import Optional, Dict, Any, List, Protocol, Coroutine
from enum import Enum

from opensearchpy import AsyncOpenSearch


class BulkAction(str, Enum):
    """Enum representing bulk actions for the Indexer.

    Attributes
    ----------
    CREATE : str
        Action to create a new document.
    CREATE_OR_UPDATE : str
        Action to create a new document or update an existing one.
    UPDATE : str
        Action to update an existing document.
    DELETE : str
        Action to delete an existing document.
    """
    CREATE = "create"
    CREATE_OR_UPDATE = "index"
    UPDATE = "update"
    DELETE = "delete"

    @classmethod
    def exists(cls, action: str) -> bool:
        try:
            cls(action)
        except ValueError:
            return False
        return True


class BulkMetadata:
    """Class to handle metadata for a bulk action in the Indexer.

    Parameters
    ----------
    index : str
        Name of the index in the Indexer.
    doc_id : Optional[str]
        ID of the document in the Indexer. Can be None for certain actions.
    action : BulkAction
        Type of bulk action to perform.
    """
    def __init__(self, index: str, doc_id: Optional[str], action: BulkAction):
        self.index = index
        self.doc_id = doc_id
        self.action = action

    def decode(self) -> Dict[str, Dict[str, str]]:
        """Decode metadata into a dictionary format for the Indexer bulk API.

        Returns
        -------
        Dict[str, Dict[str, str]]
            Metadata in a dictionary format.
        """
        return {str(self.action.value): {'_index': self.index, '_id': self.doc_id}}


class BulkDoc:
    """Class to represent a bulk document action for the Indexer.

    Parameters
    ----------
    index : str
        Name of the index in the Indexer.
    doc_id : Optional[str]
        ID of the document in the Indexer. Can be None for certain actions.
    action : BulkAction
        Type of bulk action to perform.
    doc : Optional[Any]
        Document content. Can be None for delete actions.
    """
    def __init__(self, index: str, doc_id: Optional[str], action: BulkAction, doc: Optional[Any]):
        self.metadata = BulkMetadata(index=index, doc_id=doc_id, action=action)
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
            return [self.metadata.decode(), self.doc]

    @classmethod
    def create(cls, index: str, doc_id: Optional[str], doc: Any) -> 'BulkDoc':
        """Create a new BulkDoc instance with the 'create' action.

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
            Instance of BulkDoc with the 'create' action.
        """
        return cls(index=index, doc_id=doc_id, action=BulkAction.CREATE, doc=doc)

    @classmethod
    def create_or_update(cls, index: str, doc_id: str, doc: Any) -> 'BulkDoc':
        """Create a new BulkDoc instance with the 'create_or_update' action.

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
            Instance of BulkDoc with the 'create_or_update' action.
        """
        return cls(index=index, doc_id=doc_id, action=BulkAction.CREATE_OR_UPDATE, doc=doc)

    @classmethod
    def update(cls, index: str, doc_id: str, doc: Any) -> 'BulkDoc':
        """Create a new BulkDoc instance with the 'update' action.

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
            Instance of BulkDoc with the 'update' action.
        """
        return cls(index=index, doc_id=doc_id, action=BulkAction.UPDATE, doc=doc)

    @classmethod
    def delete(cls, index: str, doc_id: str) -> 'BulkDoc':
        """Create a new BulkDoc instance with the 'delete' action.

        Parameters
        ----------
        index : str
            Name of the index in the Indexer.
        doc_id : str
            ID of the document in the Indexer.

        Returns
        -------
        BulkDoc
            Instance of BulkDoc with the 'delete' action.
        """
        return cls(index=index, doc_id=doc_id, action=BulkAction.DELETE, doc=None)


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
