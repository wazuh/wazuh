/*
 * Wazuh shared modules utils
 * Copyright (C) Wazuh Inc.
 * March 15, 2021.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _BYTE_ARRAY_HELPER_H
#define _BYTE_ARRAY_HELPER_H

#include <string>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

namespace Utils
{
    static int32_t toInt32BE(uint8_t const* bytes)
    {
        return static_cast<int32_t>(bytes[3]) |
               static_cast<int32_t>(bytes[2]) << 8 |
               static_cast<int32_t>(bytes[1]) << 16 |
               static_cast<int32_t>(bytes[0]) << 24;
    }

    static int32_t toInt32LE(uint8_t const* bytes)
    {
        return static_cast<int32_t>(bytes[0]) |
               static_cast<int32_t>(bytes[1]) << 8 |
               static_cast<int32_t>(bytes[2]) << 16 |
               static_cast<int32_t>(bytes[3]) << 24;
    }
}

#pragma GCC diagnostic pop

#endif // _BYTE_ARRAY_HELPER_H
