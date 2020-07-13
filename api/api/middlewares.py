
from aiohttp import web


@web.middleware
async def set_user_name(request, handler):
    if 'token_info' in request:
        request['user'] = request['token_info']['sub']
    response = await handler(request)
    return response
