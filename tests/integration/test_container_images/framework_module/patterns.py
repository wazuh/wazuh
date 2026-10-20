"""
Copyright (C) 2015-2024, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

Log callback patterns for the container_images module.

These mirror the log lines emitted by the module (C glue tag `wazuh-modulesd:container_images`
and the C++ library messages routed through it). They are used as deterministic anchors by the
FileMonitor, which is what keeps the tests non-flaky: every assertion waits for a specific line
to appear (with a timeout) instead of sleeping for a fixed amount of time.

In a productized version these constants belong in
`wazuh_testing/modules/modulesd/container_images/patterns.py`. They are kept local to the test
suite here so the exploration is self-contained.
"""

from . import PREFIX
from . import WMODULES_PREFIX

# Lifecycle.
CB_MODULE_INITIALIZED = fr'{PREFIX}DEBUG: Module initialized.'
# The module logs this one at debug level: mdebug1("Module disabled. Exiting.").
CB_MODULE_DISABLED = fr'{PREFIX}DEBUG: Module disabled\. Exiting\.'
CB_MODULE_LOOP_FINISHED = fr'{PREFIX}DEBUG: Module loop finished.'

# Scan lifecycle.
CB_SCAN_ON_START = fr'{PREFIX}DEBUG: Scan on start.'
CB_SCAN_STARTED = fr'{PREFIX}INFO: Scan started.'
# "Scan ended. <N> references, <M> packages."
CB_SCAN_ENDED = fr'{PREFIX}INFO: Scan ended\. \d+ references, \d+ packages\.'

# Inventory deltas. {0} is substituted with the table name
# (dbsync_container_image_references / dbsync_container_image_packages).
CB_INVENTORY_CREATED = fr'{PREFIX}DEBUG: Inventory created in {{0}}:.*'
CB_INVENTORY_MODIFIED = fr'{PREFIX}DEBUG: Inventory modified in {{0}}:.*'
CB_INVENTORY_DELETED = fr'{PREFIX}DEBUG: Inventory deleted in {{0}}:.*'

# Synchronization.
CB_SYNC_PROTOCOL_INITIALIZED = fr'{PREFIX}DEBUG: Sync protocol initialized with database.*'

# Configuration-parser errors (emitted with the wmodules prefix).
CB_INVALID_INTERVAL = fr"{WMODULES_PREFIX}ERROR: Invalid interval at module 'container_images'."
CB_INVALID_BOOL = fr"{WMODULES_PREFIX}ERROR: Invalid content for tag '{{0}}' at module 'container_images'."
CB_EMPTY_ARCHIVE_REFERENCE = fr"{WMODULES_PREFIX}ERROR: Empty 'archive' reference at module 'container_images'."
CB_UNKNOWN_REFERENCE_TYPE = fr"{WMODULES_PREFIX}WARNING: No such reference type '{{0}}' at module 'container_images', ignoring it."

# Reference types the grammar accepts but the module does not implement yet. These are logged by
# the C++ library, so they carry the module prefix rather than the configuration one.
CB_REFERENCE_NOT_IMPLEMENTED = fr"{PREFIX}WARNING: NOT IMPLEMENTED: the '<{{0}}>' reference .* Skipping it\."

# A package format that is recognized but not parsed yet: the image is still inventoried, with
# zero packages.
CB_UNSUPPORTED_PACKAGE_FORMAT = fr"{PREFIX}WARNING: NOT IMPLEMENTED: image at '.*' uses the package format\(s\) .*, which are recognized but not supported yet\. Reporting zero packages\."
