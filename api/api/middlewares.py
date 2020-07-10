from aiohttp import web

from api import configuration
from api.api_exception import APIError
from api.util import raise_if_exc


@web.middleware
async def set_user_name(request, handler):
    if 'token_info' in request:
        request['user'] = request['token_info']['sub']
    response = await handler(request)
    return response


@web.middleware
async def check_experimental(request, handler):
    if 'experimental' in request.path:
        if not configuration.api_conf['experimental_features']:
            raise_if_exc(APIError(code=2008))

    response = await handler(request)
    return response
