/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * July 30, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "zstdDecoder.hpp"

#include <zstd.h>

#include <array>

namespace remoted::common
{

    namespace
    {
        constexpr std::size_t kChunkSize = 64U * 1024U;

        // Mirrors zstd's own ZSTD_WINDOWLOG_MIN / ZSTD_WINDOWLOG_LIMIT_DEFAULT. Both are documented,
        // stable-value constants, but zstd.h only exposes their names behind
        // ZSTD_STATIC_LINKING_ONLY (its "experimental API" opt-in) -- not worth pulling in that
        // whole experimental surface for two numbers that don't change.
        constexpr int kWindowLogMin = 10;
        constexpr int kWindowLogLimitDefault = 27;

        // Smallest power-of-two window (as a log2) that could hold maxOutputSize, clamped to
        // [kWindowLogMin, kWindowLogLimitDefault]. Used to tell the decoder to refuse any frame
        // asking for more upfront memory than we could ever accept anyway -- see the comment at
        // the call site in zstdDecode() for why this matters.
        int windowLogFor(std::size_t maxOutputSize)
        {
            int log = kWindowLogMin;
            while (log < kWindowLogLimitDefault && (std::size_t {1} << log) < maxOutputSize)
            {
                ++log;
            }
            return log;
        }
    } // namespace

    std::variant<std::string, ZstdDecodeError> zstdDecode(std::string_view compressed, std::size_t maxOutputSize)
    {
        // Zero bytes is not a valid (empty) frame, it is simply not a frame at all.
        if (compressed.empty())
        {
            return ZstdDecodeError::Malformed;
        }

        ZSTD_DStream* dstream = ZSTD_createDStream();
        if (dstream == nullptr)
        {
            return ZstdDecodeError::Malformed;
        }

        // RAII: guarantees ZSTD_freeDStream() on every return path below, including the early ones.
        struct DStreamGuard
        {
            ZSTD_DStream* stream;
            ~DStreamGuard()
            {
                ZSTD_freeDStream(stream);
            }
        } guard {dstream};

        // Unlike gzip/DEFLATE (fixed 32 KiB window by spec), a zstd frame's header can itself
        // declare an arbitrarily large window, forcing the decoder to allocate that much memory
        // up front -- before a single byte of output exists for our maxOutputSize check below to
        // catch. ZSTD_initDStream() alone would only cap that at ZSTD_WINDOWLOG_LIMIT_DEFAULT (128
        // MiB), which is far more than we'd ever actually allow through maxOutputSize. Instead, we
        // explicitly cap it to whatever window could possibly hold maxOutputSize: a frame that
        // needs more than that is guaranteed to fail our size check anyway, so there is no reason
        // to let the decoder allocate for it. ZSTD_DCtx_setParameter() must be called before
        // ZSTD_initDStream(): the latter only resets session state (buffers/counters), not
        // parameters set this way.
        if (ZSTD_isError(ZSTD_DCtx_setParameter(dstream, ZSTD_d_windowLogMax, windowLogFor(maxOutputSize)))
            || ZSTD_isError(ZSTD_initDStream(dstream)))
        {
            return ZstdDecodeError::Malformed;
        }

        ZSTD_inBuffer input {compressed.data(), compressed.size(), 0};
        std::string output;
        std::array<char, kChunkSize> chunk {};
        std::size_t frameRemaining = 0;

        while (input.pos < input.size)
        {
            ZSTD_outBuffer out {chunk.data(), chunk.size(), 0};
            const std::size_t ret = ZSTD_decompressStream(dstream, &out, &input);
            if (ZSTD_isError(ret))
            {
                return ZstdDecodeError::Malformed;
            }
            frameRemaining = ret;

            if (out.pos > 0)
            {
                if (output.size() + out.pos > maxOutputSize)
                {
                    return ZstdDecodeError::TooLarge;
                }
                output.append(chunk.data(), out.pos);
            }
        }

        // frameRemaining != 0 after all input has been fed means the frame is incomplete (more
        // input would be required to finish it) -- a truncated stream.
        if (frameRemaining != 0)
        {
            return ZstdDecodeError::Malformed;
        }

        return output;
    }

} // namespace remoted::common
