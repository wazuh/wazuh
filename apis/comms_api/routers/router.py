from fastapi import APIRouter, status
from fastapi.responses import Response

router = APIRouter(prefix='/api/v1')


@router.get("/")
async def home():
    return Response(status_code=status.HTTP_200_OK)
