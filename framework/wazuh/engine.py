from wazuh.core.results import WazuhResult
from wazuh.core import engine

def add_catalog_resource(resource_type: str, resource_format: str, content: str) -> WazuhResult:
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
    WazuhResult
        WazuhResult object with information about the operation.
    """
    # TODO: sorting, filters, etc.
    data = engine.add_catalog_resource(resource_type, resource_format, content)
    return WazuhResult({'data': data})

def delete_catalog_resource(name: str) -> WazuhResult:
    """Delete a resource from the catalog.

    Parameters
    ----------
    name : str
        Resource name.

    Returns
    -------
    WazuhResult
        WazuhResult object with information about the operation.
    """
    data = engine.delete_catalog_resource(name)
    return WazuhResult({'data': data})

def get_catalog_resource(name: str, resource_type: str) -> WazuhResult:
    """Get a resource from the catalog.

    Parameters
    ----------
    name : str
        Resource name.

    Returns
    -------
    WazuhResult
        WazuhResult object with information about the operation.
    """
    data = engine.get_catalog_resource(name, resource_type)
    return WazuhResult({'data': data})


def update_catalog_resource(name: str, resource_format: str, content: str) -> WazuhResult:
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
    WazuhResult
        WazuhResult object with information about the operation.
    """
    # TODO: sorting, filters, etc.
    data = engine.update_catalog_resource(name, resource_format, content)
    return WazuhResult({'data': data})

def validate_catalog_resource(name: str, resource_format: str, content: str) -> WazuhResult:
    """Validate a resource.

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
    WazuhResult
        WazuhResult object with information about the operation.
    """
    # TODO: sorting, filters, etc.
    data = engine.validate_catalog_resource(name, resource_format, content)
    return WazuhResult({'data': data})
