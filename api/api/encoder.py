import json

import six
from connexion.jsonifier import JSONEncoder

from api.models.base_model_ import Model
from wazuh.core.results import AbstractWazuhResult


class WazuhAPIJSONEncoder(JSONEncoder):
    include_nulls = False

    def default(self, o):
        if isinstance(o, Model):
            result = {}
            for attr, _ in six.iteritems(o.swagger_types):
                value = getattr(o, attr)
                if value is None and not self.include_nulls:
                    continue
                attr = o.attribute_map[attr]
                result[attr] = value
            return result
        elif isinstance(o, AbstractWazuhResult):
            return o.render()
        return JSONEncoder.default(self, o)


def dumps(obj: object) -> str:
    """
    Get a JSON encoded str from an object.

    Parameters
    ----------
    obj: object
        Object to be encoded in a JSON string

    Raises
    ------
    TypeError

    Returns
    -------
    str
    """
    return json.dumps(obj, cls=WazuhAPIJSONEncoder)


def prettify(obj: object) -> str:
    """
    Get a prettified JSON encoded str from an object.

    Parameters
    ----------
    obj: object
        Object to be encoded in a JSON string

    Raises
    ------
    TypeError

    Returns
    -------
    str
    """
    return json.dumps(obj, cls=WazuhAPIJSONEncoder, indent=3)
