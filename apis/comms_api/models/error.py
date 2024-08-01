import json
from typing import Any

from fastapi import Response

class ErrorResponse(Response):
    """Error response model."""

    def __init__(self, message: str, code: int = None, status_code = 500):
        self.message = message
        self.code = code if code is not None else status_code
        super().__init__(content=None, status_code=status_code)

    def render(self, content: Any = None) -> str:
        return json.dumps({'message': self.message, 'code': self.code})
