from typing import Any

class EngineMock:

    policies: dict[str, list] = {}

    def add_catalog_resource(self, resource_type: str, resource_format: str, content: str):
        self.policies[resource_type] = {
            resource_format: resource_format,
            content: content
        }

    def delete_catalog_resource(self, name: str):
        self.policies.pop(name)
    
    def get_catalog_resource(self, name: str, resource_type: str) -> object:
        return self.policies[name]
    
    def update_catalog_resource(self, name: str, resource_format: str, content: str):
        resource = self.policies[name]
        resource['resource_format'] = resource_format
        resource['content'] = content

    def validate_catalog_resource(self, name: str, resource_format: str, content: str) -> bool:
        return len(self.policies[name]) == 0

ENGINE = EngineMock()


def add_catalog_resource(resource_type: str, resource_format: str, content: str) -> dict[str, Any]:
    """Add a resource to the catalog.

    Parameters
    ----------
    resource_type : str
        Resource type.
    resource_format: str
        Resource format.
    content : str
        Resource content

    Returns
    -------
    dict[str, Any]
        Engine response.
    """
    # TODO: use socket to send the command instead of the mock
    ENGINE.add_catalog_resource(resource_type, resource_format, content)
    resp = {'status': 'OK', 'error': None}
    return resp

def delete_catalog_resource(name: str) -> dict[str, Any]:
    """Delete a resource from the catalog.

    Parameters
    ----------
    name : str
        Resource name.

    Returns
    -------
    dict[str, Any]
        Engine response.
    """
    # TODO: use socket to send the command instead of the mock
    ENGINE.delete_catalog_resource(name)
    resp = {'status': 'OK', 'error': None}
    return resp

def get_catalog_resource(name: str, resource_type: str) -> dict[str, Any]:
    """Get a resource from the catalog.

    Parameters
    ----------
    name : str
        Resource name.

    Returns
    -------
    dict[str, Any]
        Engine response.
    """
    # TODO: use socket to send the command instead of the mock
    resp = {
        'content': ENGINE.get_catalog_resource(name, resource_type),
        'status': 'OK', 
        'error': None
    }
    return resp

def update_catalog_resource(name: str, resource_format: str, content: str) -> dict[str, Any]:
    """Update a resource from the catalog.

    Parameters
    ----------
    name : str
        Resource name.
    resource_format: str
        Resource format.
    content : str
        Resource content

    Returns
    -------
    dict[str, Any]
        Engine response.
    """
    # TODO: use socket to send the command instead of the mock
    ENGINE.update_catalog_resource(name, resource_format, content)
    resp = {'status': 'OK', 'error': None}
    return resp

def validate_catalog_resource(name: str, resource_format: str, content: str) -> dict[str, Any]:
    """Validate the contents of a resource.

    Parameters
    ----------
    name : str
        Resource name.
    resource_format: str
        Resource format.
    content : str
        Resource content

    Returns
    -------
    dict[str, Any]
        Engine response.
    """
    # TODO: use socket to send the command instead of the mock
    ENGINE.validate_catalog_resource(name, resource_format, content)
    resp = {'status': 'OK', 'error': None}
    return resp
