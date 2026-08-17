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

#include <algorithm>
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

    /**
     * @brief Like zstdCompress(), but produces a frame whose header declares NO decompressed size.
     *
     * ZSTD_compress() always records the size (it knows it up front), so it cannot produce this
     * shape. Streaming compression without a pledged source size can -- which is what an agent
     * compressing on the fly would emit. zstdDecode() has a separate path for these frames (it must
     * grow the output buffer in blocks instead of sizing it once), so it needs its own fixtures.
     */
    inline std::string zstdCompressWithoutDeclaredSize(std::string_view plain, int level = 3)
    {
        ZSTD_CCtx* cctx = ZSTD_createCCtx();
        if (cctx == nullptr)
        {
            throw std::runtime_error("ZSTD_createCCtx failed");
        }
        struct Guard
        {
            ZSTD_CCtx* ctx;
            ~Guard()
            {
                ZSTD_freeCCtx(ctx);
            }
        } guard {cctx};

        ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel, level);
        // Not calling ZSTD_CCtx_setPledgedSrcSize() is necessary but NOT sufficient: handed the
        // whole input in one ZSTD_e_end call, zstd still knows the total and records it. The header
        // is only written without a size if the frame starts before the input has all been seen --
        // so feed it in pieces, and only end the frame afterwards.
        constexpr std::size_t kFeedSize = 64 * 1024;

        std::string out(ZSTD_compressBound(plain.size()) + 1024, '\0');
        ZSTD_outBuffer output {out.data(), out.size(), 0};

        for (std::size_t offset = 0; offset < plain.size(); offset += kFeedSize)
        {
            const std::size_t take = std::min(kFeedSize, plain.size() - offset);
            ZSTD_inBuffer in {plain.data() + offset, take, 0};
            while (in.pos < in.size)
            {
                const std::size_t ret = ZSTD_compressStream2(cctx, &output, &in, ZSTD_e_continue);
                if (ZSTD_isError(ret))
                {
                    throw std::runtime_error(std::string("ZSTD_compressStream2 failed: ") + ZSTD_getErrorName(ret));
                }
            }
        }

        ZSTD_inBuffer end {nullptr, 0, 0};
        std::size_t remaining = 0;
        do
        {
            remaining = ZSTD_compressStream2(cctx, &output, &end, ZSTD_e_end);
            if (ZSTD_isError(remaining))
            {
                throw std::runtime_error(std::string("ZSTD_compressStream2 (end) failed: ") +
                                        ZSTD_getErrorName(remaining));
            }
        } while (remaining != 0);

        out.resize(output.pos);
        return out;
    }

} // namespace remoted::testutil

#endif // _REMOTED_MODULE_TEST_ZSTD_TEST_HELPER_HPP
