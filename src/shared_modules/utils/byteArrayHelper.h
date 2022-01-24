/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * March 15, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
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
