/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_COMMON_ZSTD_ENCODER_HPP
#define _REMOTED_COMMON_ZSTD_ENCODER_HPP

#include <cstddef>
#include <cstdint>
#include <optional>

struct ZSTD_CCtx_s;

namespace remoted::common
{

    /**
     * @brief Streaming zstd compressor (level 3, no checksum) producing a single frame; the
     *        counterpart of zstdDecode(). Not thread-safe.
     *
     * With a size hint the frame header declares that size and zstd rejects any other total.
     */
    class ZstdEncoder
    {
    public:
        struct Step
        {
            std::size_t consumed;
            std::size_t produced;
            bool done;
        };

        /**
         * @param sizeHint Exact number of input bytes that will be compressed, if known.
         * @throws std::runtime_error if the compression context cannot be set up.
         */
        explicit ZstdEncoder(std::optional<std::uint64_t> sizeHint);
        ~ZstdEncoder();

        ZstdEncoder(const ZstdEncoder&) = delete;
        ZstdEncoder& operator=(const ZstdEncoder&) = delete;
        ZstdEncoder(ZstdEncoder&&) = delete;
        ZstdEncoder& operator=(ZstdEncoder&&) = delete;

        /**
         * @brief Compress as much of @p in as fits into @p out.
         *
         * With @p finish the frame is being ended: keep calling (re-passing any unconsumed input)
         * until done is true. done is never true without @p finish, and calling again after done
         * starts a second frame.
         *
         * @throws std::runtime_error on a zstd error, including a total that differs from the hint.
         */
        Step step(const char* in, std::size_t inSize, bool finish, char* out, std::size_t outCapacity);

        /// Bytes zstd allocates for a stream of at most @p sizeHint bytes (unknown size without a hint).
        static std::size_t estimateMemory(std::optional<std::uint64_t> sizeHint);
        /// zstd's preferred input chunk, bounded by the hint.
        static std::size_t inputBufferSize(std::optional<std::uint64_t> sizeHint = std::nullopt);
        /// zstd's recommended output chunk, bounded by the hint; any non-zero capacity still makes progress.
        static std::size_t outputBufferSize(std::optional<std::uint64_t> sizeHint = std::nullopt);

    private:
        ZSTD_CCtx_s* m_ctx;
    };

} // namespace remoted::common

#endif // _REMOTED_COMMON_ZSTD_ENCODER_HPP
