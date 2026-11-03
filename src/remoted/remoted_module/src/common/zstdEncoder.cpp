/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "zstdEncoder.hpp"

// ZSTD_estimateCStreamSize_usingCParams() is behind this opt-in; see zstdDecoder.cpp.
#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>

#include <algorithm>
#include <stdexcept>
#include <string>

namespace remoted::common
{

    namespace
    {
        constexpr int kCompressionLevel = 3;
        constexpr std::uint64_t kMinBufferSize = 4096;

        void check(std::size_t result, const char* what)
        {
            if (ZSTD_isError(result))
            {
                throw std::runtime_error(std::string(what) + ": " + ZSTD_getErrorName(result));
            }
        }

        std::size_t bounded(std::size_t zstdSize, std::optional<std::uint64_t> sizeHint)
        {
            if (!sizeHint)
            {
                return zstdSize;
            }
            return static_cast<std::size_t>(std::min<std::uint64_t>(zstdSize, std::max(*sizeHint, kMinBufferSize)));
        }
    } // namespace

    ZstdEncoder::ZstdEncoder(std::optional<std::uint64_t> sizeHint)
        : m_ctx(ZSTD_createCCtx())
    {
        if (m_ctx == nullptr)
        {
            throw std::runtime_error("ZSTD_createCCtx failed");
        }
        try
        {
            check(ZSTD_CCtx_setParameter(m_ctx, ZSTD_c_compressionLevel, kCompressionLevel), "ZSTD_CCtx_setParameter");
            if (sizeHint)
            {
                check(ZSTD_CCtx_setPledgedSrcSize(m_ctx, *sizeHint), "ZSTD_CCtx_setPledgedSrcSize");
            }
        }
        catch (...)
        {
            ZSTD_freeCCtx(m_ctx);
            throw;
        }
    }

    ZstdEncoder::~ZstdEncoder()
    {
        ZSTD_freeCCtx(m_ctx);
    }

    ZstdEncoder::Step
    ZstdEncoder::step(const char* in, std::size_t inSize, bool finish, char* out, std::size_t outCapacity)
    {
        ZSTD_inBuffer input {in, inSize, 0};
        ZSTD_outBuffer output {out, outCapacity, 0};
        const std::size_t remaining =
            ZSTD_compressStream2(m_ctx, &output, &input, finish ? ZSTD_e_end : ZSTD_e_continue);
        check(remaining, "ZSTD_compressStream2");
        return {input.pos, output.pos, finish && remaining == 0};
    }

    std::size_t ZstdEncoder::estimateMemory(std::optional<std::uint64_t> sizeHint)
    {
        // max(.., 1): getCParams reads 0 as "unknown size", which would size for the worst case.
        const std::size_t size = sizeHint ? ZSTD_estimateCStreamSize_usingCParams(ZSTD_getCParams(
                                                kCompressionLevel, std::max<std::uint64_t>(*sizeHint, 1), 0))
                                          : ZSTD_estimateCStreamSize(kCompressionLevel);
        check(size, "ZSTD_estimateCStreamSize");
        return size;
    }

    std::size_t ZstdEncoder::inputBufferSize(std::optional<std::uint64_t> sizeHint)
    {
        return bounded(ZSTD_CStreamInSize(), sizeHint);
    }

    std::size_t ZstdEncoder::outputBufferSize(std::optional<std::uint64_t> sizeHint)
    {
        return bounded(ZSTD_CStreamOutSize(), sizeHint);
    }

} // namespace remoted::common
