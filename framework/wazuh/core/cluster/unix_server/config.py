from typing import Optional

from fastapi import Response, status
from starlette.responses import JSONResponse
from wazuh.core.config.client import CentralizedConfig
from wazuh.core.config.models.central_config import ConfigSections


async def get_config(sections: Optional[str] = None) -> Response:
    """Retrieve the current configuration from the Server.

    Parameters
    ----------
    sections: str
        String with list of sections separated by comma. If None, all sections are included.

    Returns
    -------
    JSONResponse
        HTTP OK response with the configuration as content.
    """
    if sections is not None:
        section_list = sections.split(",")
        try:
            validated_sections = [ConfigSections(section) for section in section_list]
        except ValueError as e:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    'message': f"Invalid configuration section: '{e.args[0]}'",
                    'code': status.HTTP_400_BAD_REQUEST,
                },
            )
    else:
        validated_sections = None
    config = CentralizedConfig.get_config_json(sections=validated_sections)

    return Response(status_code=status.HTTP_200_OK, content=config)
