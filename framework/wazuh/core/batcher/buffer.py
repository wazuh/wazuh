import sys
from typing import List

from wazuh.core.batcher.mux_demux import Item


class Buffer:
    """Manage the buffer for batching items.

    Parameters
    ----------
    max_elements : int
        Maximum number of items in the buffer.
    max_size : int
        Maximum size of the buffer in bytes.
    """
    def __init__(self, max_elements: int, max_size: int):
        self.max_elements = max_elements
        self.max_size = max_size
        self._buffer: List[Item] = []

    def add_item(self, item: Item):
        """Add an item to the buffer.

        Parameters
        ----------
        item : Item
            Item to add to buffer.

        Returns
        -------
        bool
            `True` if the item was successfully added to the buffer, `False` if adding
            the item would exceed the buffer's limits.
        """
        if self.check_count_limit() or self.check_size_limit():
            return False

        self._buffer.append(item)
        return True

    def get_length(self) -> int:
        """Get the current length of the buffer.

        Returns
        -------
        int
            Number of items currently in the buffer.
        """
        return len(self._buffer)

    def check_count_limit(self) -> bool:
        """Check if the buffer has reached the maximum number of items.

        Returns
        -------
        bool
            True if the buffer has reached the maximum number of items, False otherwise.
        """
        return self.get_length() >= self.max_elements

    def check_size_limit(self) -> bool:
        """Check if the buffer has reached the maximum size in bytes.

        Returns
        -------
        bool
            True if the buffer has reached the maximum size, False otherwise.
        """
        total_size = sum(sys.getsizeof(item.content) for item in self._buffer)
        return total_size >= self.max_size

    def copy(self) -> List[Item]:
        """Return a copy of the buffer.

        Returns
        -------
        List[Item]
            Copy of the list of items in buffer.
        """
        return self._buffer.copy()

    def reset(self):
        """Clear the buffer."""
        self._buffer.clear()
