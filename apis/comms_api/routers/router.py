from fastapi import APIRouter, Request, status
from fastapi.responses import Response, JSONResponse

from comms_api.models.error import HTTPError

router = APIRouter(prefix='/api/v1')


@router.get("/")
async def home():
    return Response(status_code=status.HTTP_200_OK)

async def http_error_handler(request: Request, exc: HTTPError):
    return JSONResponse(
        status_code=exc.status_code,
        content={'message': exc.message, 'code': exc.code},
    )
