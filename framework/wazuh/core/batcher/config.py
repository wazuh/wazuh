class BatcherConfig:
    """Configuration for the Batcher, specifying limits for batching.

    Parameters
    ----------
    max_elements : int
        Maximum number of items in a batch.
    max_size : int
        Maximum size of the batch in bytes.
    max_time_seconds : int
        Maximum time in seconds before a batch is sent.
    """
    def __init__(self, max_elements: int, max_size: int, max_time_seconds: int):
        self.max_elements = max_elements
        self.max_size = max_size
        self.max_time_seconds = max_time_seconds
