from fastapi import HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

class HTTPError(HTTPException):
    """HTTP error exception model."""

    def __init__(self, message: str, code: int = None, status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR):
        self.message = message
        self.code = code if code is not None else status_code
        self.status_code = status_code
    
    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


async def http_error_handler(request: Request, exc: HTTPError) -> JSONResponse:
    """API internal errors handler.
    
    Parameters
    ----------
    request : Request
        Client request.
    exc : HTTPError
        Exception raised.
    
    Returns
    -------
    JSONResponse
        JSON response containing an error description and code.
    """
    return JSONResponse(
        status_code=exc.status_code,
        content={'message': exc.message, 'code': exc.code},
    )

async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """API request validation errors handler.
    
    Parameters
    ----------
    request : Request
        Client request.
    exc : RequestValidationError
        Validation exception raised.
    
    Returns
    -------
    JSONResponse
        JSON response containing an error description and code.
    """
    error = exc.errors()[0]
    key = '.'.join(error['loc'])
    message = error['msg']
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={'message': f'{key} {message}', 'code': status.HTTP_400_BAD_REQUEST},
    )
