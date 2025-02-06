from dataclasses import dataclass
from typing import List


@dataclass
class ErrorResponse:
    """Error response data model."""

    error: List[str]
    code: int
