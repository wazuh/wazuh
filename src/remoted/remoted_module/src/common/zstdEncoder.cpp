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

// ZSTD_estimateCStreamSize() sits behind this opt-in. It is what lets a caller reserve the
// compressor's real footprint against a shared budget; the vendored zstd is pinned and statically
// linked, so a signature change breaks the build instead of failing at runtime (same reasoning as
// zstdDecoder.cpp).
#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>

#include <stdexcept>
#include <string>

namespace remoted::common
{

    namespace
    {
        constexpr int kCompressionLevel = 3;
    } // namespace

    struct ZstdEncoder::Impl
    {
        ZSTD_CCtx* ctx {nullptr};

        Impl()
            : ctx {ZSTD_createCCtx()}
        {
            if (ctx == nullptr)
            {
                throw std::runtime_error("could not create the zstd compression context");
            }
            // Cannot fail for a level within range; checked anyway so a future change surfaces here.
            if (ZSTD_isError(ZSTD_CCtx_setParameter(ctx, ZSTD_c_compressionLevel, kCompressionLevel)))
            {
                ZSTD_freeCCtx(ctx);
                throw std::runtime_error("could not set the zstd compression level");
            }
        }

        ~Impl()
        {
            ZSTD_freeCCtx(ctx);
        }
    };

    ZstdEncoder::ZstdEncoder()
        : m_impl {std::make_unique<Impl>()}
    {
    }

    ZstdEncoder::~ZstdEncoder() = default;

    std::size_t ZstdEncoder::memoryRequired()
    {
        return ZSTD_estimateCStreamSize(kCompressionLevel) + inputSize();
    }

    std::size_t ZstdEncoder::inputSize()
    {
        return ZSTD_CStreamInSize();
    }

    ZstdEncoder::Step ZstdEncoder::compress(std::string_view input, char* output, std::size_t capacity, bool last)
    {
        ZSTD_inBuffer in {input.data(), input.size(), 0};
        ZSTD_outBuffer out {output, capacity, 0};

        const std::size_t remaining = ZSTD_compressStream2(m_impl->ctx, &out, &in, last ? ZSTD_e_end : ZSTD_e_continue);
        if (ZSTD_isError(remaining))
        {
            throw std::runtime_error(std::string("zstd compression failed: ") + ZSTD_getErrorName(remaining));
        }

        // With ZSTD_e_end a zero return means the epilogue is fully flushed.
        return Step {in.pos, out.pos, last && remaining == 0};
    }

} // namespace remoted::common
