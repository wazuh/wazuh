from fastapi import APIRouter, status
from fastapi.responses import Response

from comms_api.routers.authentication import authentication

router = APIRouter(prefix='/api/v1')
router.add_api_route('/authentication', authentication, methods=['POST'])


@router.get('/')
async def home():
    return Response(status_code=status.HTTP_200_OK)
