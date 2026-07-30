/*
 * Wazuh remoted module (C++ worker bridge) - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 28, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_MODULE_TEST_GZIP_TEST_HELPER_HPP
#define _REMOTED_MODULE_TEST_GZIP_TEST_HELPER_HPP

#include <zlib.h>

#include <array>
#include <stdexcept>
#include <string>
#include <string_view>

namespace remoted::testutil
{

    /**
     * @brief Test-only gzip compressor: the inverse of production's gzipDecode(), used to build
     *        valid `Content-Encoding: gzip` fixtures. Not used by any production code path -- the
     *        manager only ever decompresses agent-sent bodies, never compresses its own.
     */
    inline std::string gzipCompress(std::string_view plain)
    {
        z_stream strm {};
        // 15 + 16: emit a gzip-formatted stream (header + CRC32/size trailer), matching what
        // gzipDecode() (windowBits 15 + 16 on the inflate side) expects to parse.
        if (deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK)
        {
            throw std::runtime_error("deflateInit2 failed");
        }

        strm.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(plain.data()));
        strm.avail_in = static_cast<uInt>(plain.size());

        std::string out;
        std::array<char, 4096> chunk {};
        int ret;
        do
        {
            strm.next_out = reinterpret_cast<Bytef*>(chunk.data());
            strm.avail_out = static_cast<uInt>(chunk.size());
            ret = deflate(&strm, Z_FINISH);
            out.append(chunk.data(), chunk.size() - strm.avail_out);
        } while (ret != Z_STREAM_END);

        deflateEnd(&strm);
        return out;
    }

} // namespace remoted::testutil

#endif // _REMOTED_MODULE_TEST_GZIP_TEST_HELPER_HPP
