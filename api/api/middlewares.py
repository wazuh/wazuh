from aiohttp import web
from api.api_exception import APIException
from werkzeug.exceptions import Forbidden


@web.middleware
async def set_user_name(request, handler):
    if 'token_info' in request:
        request['user'] = request['token_info']['sub']
    response = await handler(request)
    return response


def check_experimental(experimental_features):
    @web.middleware
    async def middleware_experimental(request, handler):
        if 'experimental' in request.path:
            if not experimental_features:
                raise Forbidden(description=str(APIException(2008)))

        response = await handler(request)
        return response
    return middleware_experimental
