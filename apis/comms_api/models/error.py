import json
from typing import Any

from fastapi import status
from fastapi.responses import JSONResponse


class ErrorResponse(JSONResponse):
    """Error response model."""

    def __init__(self, message: str, code: int = None, status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR):
        self.message = message
        self.code = code if code is not None else status_code
        super().__init__(content=None, status_code=status_code)

    def render(self, content: Any = None) -> bytes:
        return json.dumps({'error': {'message': self.message, 'code': self.code}}).encode('utf-8')
