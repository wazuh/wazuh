/*
 * Wazuh keystore
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

// The logging hook of the `keystore` archive. A binary that defines Log::GLOBAL_LOG_FUNCTION itself (the engine)
// links `keystore_core`, which is the same archive without this file.

#include "loggerHelper.h"

namespace Log
{
    std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>
        GLOBAL_LOG_FUNCTION;
};
