/* Copyright (C) Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <cstddef>

namespace od
{
    /// @brief Whether a read that found @p found records, of which @p readable could be read, can be
    /// trusted. Records that cannot be read are skipped one by one, but when the query found records
    /// and none of them could be read, the directory is not readable: an empty answer would leave
    /// every account without groups.
    inline bool readIsTrusted(size_t found, size_t readable)
    {
        return found == 0 || readable > 0;
    }
} // namespace od
