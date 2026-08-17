# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import warnings

try:
    from starlette.exceptions import StarletteDeprecationWarning
except ImportError:
    # StarletteDeprecationWarning was removed in newer versions of starlette
    StarletteDeprecationWarning = None

# Connexion unconditionally imports `starlette.testclient` to offer a test helper we never use,
# which warns when only `httpx` (and not `httpx2`) is installed. Not fixed as of connexion 3.3.0.
# Starlette raises this with stacklevel=2, so it is attributed to the importing module rather
# than to starlette.testclient itself; match on the message instead of `module`.
if StarletteDeprecationWarning is not None:
    warnings.filterwarnings(
        'ignore', category=StarletteDeprecationWarning,
        message=r'Using `httpx` with `starlette\.testclient` is deprecated',
    )
