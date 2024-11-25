from fastapi import Response, status, Query, HTTPException
from starlette.responses import JSONResponse
from typing import Optional

from wazuh.core.config.client import CentralizedConfig, ConfigSections


async def get_config(sections: Optional[str] = Query(default=None)) -> Response:
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
    if sections:
        section_list = sections.split(",")
        try:
            validated_sections = [ConfigSections(section) for section in section_list]
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid section(s): {str(e)}",
            )
    else:
        validated_sections = None
    config = CentralizedConfig.get_config_json(sections=validated_sections)

    return Response(status_code=status.HTTP_200_OK, content=config)
