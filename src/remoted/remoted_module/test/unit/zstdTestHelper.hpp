/*
 * Wazuh remoted module (C++ worker bridge) - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 30, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_MODULE_TEST_ZSTD_TEST_HELPER_HPP
#define _REMOTED_MODULE_TEST_ZSTD_TEST_HELPER_HPP

#include <zstd.h>

#include <stdexcept>
#include <string>
#include <string_view>

namespace remoted::testutil
{

    /**
     * @brief Test-only zstd compressor: the inverse of production's zstdDecode(), used to build
     *        valid `Content-Encoding: zstd` fixtures. Not used by any production code path -- the
     *        manager only ever decompresses agent-sent bodies, never compresses its own.
     */
    inline std::string zstdCompress(std::string_view plain, int level = 3)
    {
        std::string out(ZSTD_compressBound(plain.size()), '\0');
        const std::size_t written = ZSTD_compress(out.data(), out.size(), plain.data(), plain.size(), level);
        if (ZSTD_isError(written))
        {
            throw std::runtime_error(std::string("ZSTD_compress failed: ") + ZSTD_getErrorName(written));
        }
        out.resize(written);
        return out;
    }

} // namespace remoted::testutil

#endif // _REMOTED_MODULE_TEST_ZSTD_TEST_HELPER_HPP
