# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging
from typing import Dict

from wazuh.core.mitre import WazuhDBQueryMitreMetadata
from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.rbac.decorators import expose_resources

logger = logging.getLogger('wazuh')


@expose_resources(actions=["mitre:read"], resources=["*:*:*"])
def mitre_metadata() -> Dict:
    """Return the metadata of the MITRE's database

    Returns
    -------
    Metadata of MITRE's db
    """
    result = AffectedItemsWazuhResult(none_msg='No metadata information was returned',
                                      all_msg='Metadata information was returned')

    db_query = WazuhDBQueryMitreMetadata()
    data = db_query.run()

    result.affected_items.extend(data['items'])
    result.total_affected_items = data['totalItems']

    return result
