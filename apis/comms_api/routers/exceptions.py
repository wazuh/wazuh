from fastapi import HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException


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
    key = '.'.join(error['loc']) if isinstance(error['loc'], list) else error['loc']
    message = error['msg'].lower()
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={'message': f'{key} {message}', 'code': status.HTTP_400_BAD_REQUEST},
    )


async def exception_handler(request: Request, exc: Exception):
    """API global errors handler.
    
    Parameters
    ----------
    request : Request
        Client request.
    exc : Exception
        Base exception raised.
    
    Returns
    -------
    JSONResponse
        JSON response containing an error message and code.
    """
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={'message': f'{str(exc)}', 'code': status.HTTP_500_INTERNAL_SERVER_ERROR},
    )


async def starlette_http_exception_handler(request: Request, exc: StarletteHTTPException):
    """Starlette HTTP exception handler.
    
    Parameters
    ----------
    request : Request
        Client request.
    exc : StarletteHTTPException
        Starlette exception.
    
    Returns
    -------
    JSONResponse
        JSON response containing an error message and code.
    """
    return JSONResponse(
        status_code=exc.status_code,
        content={'message': exc.detail, 'code': exc.status_code},
    )
