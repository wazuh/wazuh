import functools

import connexion

from api.api_exception import APIError
from api.util import parse_api_param, raise_if_exc


class APIUriParser(connexion.decorators.uri_parsing.OpenAPIURIParser):
    def __call__(self, function):
        """
        :type function: types.FunctionType
        :rtype: types.FunctionType
        """

        @functools.wraps(function)
        def wrapper(request):
            def coerce_dict(md):
                """ MultiDict -> dict of lists
                """
                try:
                    return md.to_dict(flat=False)
                except AttributeError:
                    return dict(md.items())

            # Raise exception if semicolon is used in q parameter
            if 'q' in request.query.keys():
                q = parse_api_param(request.url, 'q')
                if q:
                    if ';' in q:
                        raise_if_exc(APIError(code=2009))

            # Transform to lowercase the values for query parameter's spec.yaml enums
            lower_fields = ['component', 'configuration', 'hash', 'requirement', 'status', 'type', 'section', 'tag',
                            'level', 'resource']
            request.query.update(
                {k.lower(): [list_item.lower() for list_item in v] if isinstance(v, list) else v.lower()
                 for k, v in request.query.items() if k in lower_fields})

            query = coerce_dict(request.query)
            path_params = coerce_dict(request.path_params)
            form = coerce_dict(request.form)

            request.query = self.resolve_query(query)
            request.path_params = self.resolve_path(path_params)
            request.form = self.resolve_form(form)
            response = function(request)
            return response

        return wrapper
