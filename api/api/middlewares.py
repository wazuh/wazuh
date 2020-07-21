import connexion
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


@web.middleware
async def response_postprocessing(request, handler):
    """Remove unwanted fields from error responses like 400 or 403.

    Additionally, it cleans the output given by connexion's exceptions. If no exception is raised during the
    'await handler(request) it means the output will be a 200 response and no fields needs to be removed."""
    fields_to_remove = ['status']

    def cleanup_str(detail):
        return ' '.join(str(detail).replace("\n\n", ". ").replace("\n", "").split())

    try:
        return await handler(request)
    except connexion.exceptions.ProblemException as ex:
        problem = ex.to_problem()
        for field in fields_to_remove:
            if field in problem.body:
                del problem.body[field]
        problem.body['detail'] = cleanup_str(problem.body['detail'])
        return problem
