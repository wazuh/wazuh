from aiohttp import web
from aiohttp.web_response import Response
from werkzeug.exceptions import Forbidden

from api.api_exception import APIException
from api import configuration


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
            raise Forbidden(description=str(APIException(2008)))

    response = await handler(request)
    return response


@web.middleware
async def cache_middleware(request, handler):
    def get_original_handler(handler):
        if hasattr(handler, 'cache_enable'):
            return handler
        elif hasattr(handler, 'keywords'):
            return get_original_handler(handler.keywords['handler'])

    # Get the first handler, not the ones created after running middlewares
    original_handler = get_original_handler(handler)

    if getattr(original_handler, "cache_enable", False):
        # Is cache disabled?
        if getattr(original_handler, "cache_unless", False) is True:
            return await handler(request)

        cache_backend = request.app["cache"]
        key = await cache_backend.make_key(request)
        cached_response = await cache_backend.get(key)

        if cached_response:
            return Response(**cached_response)

        # Generate cache
        original_response = await handler(request)

        data = {
            "status": original_response.status,
            "headers": dict(original_response.headers),
            "body": original_response.body,
        }

        expires = getattr(original_handler, "cache_expires", 300)
        await cache_backend.set(key, data, expires)

        return original_response

    # Not cached
    return await handler(request)
