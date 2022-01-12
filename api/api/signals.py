# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


async def modify_response_headers(request, response):
    # Delete 'Server' entry
    response.headers.pop('Server', None)
