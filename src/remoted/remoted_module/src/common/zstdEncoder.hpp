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

#ifndef _REMOTED_COMMON_ZSTD_ENCODER_HPP
#define _REMOTED_COMMON_ZSTD_ENCODER_HPP

#include <cstddef>
#include <memory>

// Kept an incomplete type here: <zstd.h> stays confined to zstdEncoder.cpp, mirroring zstdDecoder.
typedef struct ZSTD_CCtx_s ZSTD_CCtx;

namespace remoted::common
{

    /// Compression level used for every zstd-encoded response. Fixed by design (#38282): level 3
    /// is ~10x faster than gzip at less than half the size on merged.mg content, and higher levels
    /// buy a modest size win for an exponential CPU cost the fleet-scale download path cannot pay.
    constexpr int kZstdResponseCompressionLevel {3};

    /**
     * @brief Incremental zstd frame compressor (streaming counterpart of zstdDecode()).
     *
     * One instance produces exactly one frame. step() is fed input slices as they become available
     * and fills whatever output room the caller offers, so it fits a pull-based consumer that owns
     * both buffers (see ZstdCompressingByteSource): neither side is ever required to buffer the
     * whole document.
     */
    class ZstdStreamCompressor final
    {
    public:
        /**
         * @brief Result of one step() call.
         */
        struct Step
        {
            std::size_t consumed {0};  ///< Input bytes consumed by this call.
            std::size_t produced {0};  ///< Output bytes written by this call.
            bool frameComplete {false}; ///< The frame is fully written; step() must not be called again.
        };

        /**
         * @brief Create a compressor. Throws std::runtime_error if the zstd context cannot be
         *        created or configured.
         *
         * @param level zstd compression level.
         */
        explicit ZstdStreamCompressor(int level = kZstdResponseCompressionLevel);

        /**
         * @brief Feed input and/or drain output.
         *
         * With @p endOfInput false the call compresses as much of the input as fits the compressor's
         * internal block buffering; it may legitimately consume input while producing ZERO output
         * (zstd buffers up to a block before emitting). With @p endOfInput true it flushes and
         * terminates the frame across as many calls as the output capacity requires; once a call
         * reports frameComplete the frame checksum/terminator is in the output and the instance is
         * spent. Throws std::runtime_error on a zstd error.
         *
         * @param input      Input slice (may be null when @p inputSize is 0).
         * @param inputSize  Bytes available at @p input.
         * @param endOfInput True when @p input is the last input this frame will ever see.
         * @param output     Output destination.
         * @param capacity   Room at @p output.
         */
        Step step(const char* input, std::size_t inputSize, bool endOfInput, char* output, std::size_t capacity);

        /**
         * @brief Bytes of working memory a compressor of @p level costs, per zstd's own sizing
         *        helper. Used to charge the compressor state against the in-flight byte budget
         *        before creating one.
         */
        static std::size_t estimatedStateBytes(int level = kZstdResponseCompressionLevel);

        /// zstd's recommended input staging size for streaming compression.
        static std::size_t recommendedInputSize();

    private:
        struct CctxDeleter
        {
            void operator()(ZSTD_CCtx* context) const noexcept;
        };

        std::unique_ptr<ZSTD_CCtx, CctxDeleter> m_context;
    };

} // namespace remoted::common

#endif // _REMOTED_COMMON_ZSTD_ENCODER_HPP
