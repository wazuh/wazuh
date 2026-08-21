/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * August 21, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "zstdEncoder.hpp"

// ZSTD_estimateCStreamSize() lives behind this opt-in; same containment rationale as
// zstdDecoder.cpp (vendored, statically linked, pinned zstd).
#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>

#include <stdexcept>
#include <string>

namespace remoted::common
{

    void ZstdStreamCompressor::CctxDeleter::operator()(ZSTD_CCtx* context) const noexcept
    {
        ZSTD_freeCCtx(context);
    }

    ZstdStreamCompressor::ZstdStreamCompressor(int level)
        : m_context {ZSTD_createCCtx()}
    {
        if (!m_context)
        {
            throw std::runtime_error {"could not create a zstd compression context"};
        }

        const std::size_t ret = ZSTD_CCtx_setParameter(m_context.get(), ZSTD_c_compressionLevel, level);
        if (ZSTD_isError(ret))
        {
            throw std::runtime_error {std::string {"could not set the zstd compression level: "} +
                                      ZSTD_getErrorName(ret)};
        }
    }

    ZstdStreamCompressor::Step
    ZstdStreamCompressor::step(const char* input, std::size_t inputSize, bool endOfInput, char* output,
                               std::size_t capacity)
    {
        ZSTD_inBuffer in {input, inputSize, 0};
        ZSTD_outBuffer out {output, capacity, 0};

        const auto mode = endOfInput ? ZSTD_e_end : ZSTD_e_continue;
        const std::size_t ret = ZSTD_compressStream2(m_context.get(), &out, &in, mode);
        if (ZSTD_isError(ret))
        {
            // Propagates out of IByteSource::read(), which aborts the transfer without a
            // terminating chunk -- exactly what a mid-frame compressor failure must do.
            throw std::runtime_error {std::string {"zstd compression failed: "} + ZSTD_getErrorName(ret)};
        }

        Step result;
        result.consumed = in.pos;
        result.produced = out.pos;
        // With ZSTD_e_end, ret is the number of bytes still to be flushed: 0 with all input taken
        // means the frame terminator is in the output.
        result.frameComplete = endOfInput && ret == 0 && in.pos == in.size;
        return result;
    }

    std::size_t ZstdStreamCompressor::estimatedStateBytes(int level)
    {
        const std::size_t estimate = ZSTD_estimateCStreamSize(level);
        if (ZSTD_isError(estimate))
        {
            // Sizing failing is not a reason to refuse compression; fall back to a conservative
            // figure in the order of what level 3 really costs.
            return 4U * 1024U * 1024U;
        }
        return estimate;
    }

    std::size_t ZstdStreamCompressor::recommendedInputSize()
    {
        return ZSTD_CStreamInSize();
    }

} // namespace remoted::common
