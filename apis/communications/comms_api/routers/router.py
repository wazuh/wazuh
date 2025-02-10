from fastapi import APIRouter, Depends, status
from fastapi.responses import Response

from comms_api.authentication.authentication import JWTBearer
from comms_api.routers.authentication import authentication
from comms_api.routers.commands import get_commands
from comms_api.routers.events import events_router
from comms_api.routers.files import get_files
from comms_api.routers.vulnerability import post_scan_request

router = APIRouter(prefix='/api/v1')
router.add_api_route('/authentication', authentication, methods=['POST'])
router.add_api_route('/commands', get_commands, methods=['GET'], response_model_exclude_none=True)
router.include_router(events_router)
router.add_api_route('/files', get_files, methods=['GET'], dependencies=[Depends(JWTBearer())])
router.add_api_route(
    '/vulnerability/scan', post_scan_request, methods=['POST'], dependencies=[Depends(JWTBearer())], response_model=None
)


@router.get('/')
async def home():
    return Response(status_code=status.HTTP_200_OK)
