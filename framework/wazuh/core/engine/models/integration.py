# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from dataclasses import dataclass
from typing import List

@dataclass
class Integration:
    """Data class for an integration resource.

    Attributes
    ----------
    type : str
        The type of the integration.
    name : str
        The name of the integration.
    id : str
        The unique identifier of the integration.
    description : str
        A description of the integration.
    documentation : str
        Documentation URL or text for the integration.
    status : str
        The status of the integration.
    kvdbs : List[str]
        List of associated KVDBs.
    decoders : List[str]
        List of associated decoders.
    """
    type: str
    name: str
    id: str
    description: str
    documentation: str
    status: str
    kvdbs: List[str]
    decoders: List[str]
