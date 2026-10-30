/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_HTTP_SERVER_ZSTD_COMPRESSING_BYTE_SOURCE_HPP
#define _REMOTED_HTTP_SERVER_ZSTD_COMPRESSING_BYTE_SOURCE_HPP

#include "IHttpServer.hpp"
#include "common/zstdEncoder.hpp"

#include <cstddef>
#include <memory>
#include <string>

namespace remoted::http
{

    /**
     * @brief IByteSource decorator that hands out the zstd frame of another source's bytes.
     *
     * The inner source's failure semantics are preserved on purpose: an exception from it (the file
     * changed mid-transfer) propagates out of read(), the pump withholds the terminating chunk, and
     * the peer is left with a truncated frame it cannot decode.
     */
    class ZstdCompressingByteSource final : public IByteSource
    {
    public:
        explicit ZstdCompressingByteSource(std::shared_ptr<IByteSource> inner);

        /**
         * @brief Produce the next slice of the frame.
         *
         * Returns 0 only once the frame is complete and flushed: 0 means end-of-stream to the
         * pump, which would emit the terminating chunk for whatever it had sent so far, so an early
         * 0 would pass a truncated frame off as a complete body. The call therefore keeps pulling
         * from the inner source until it has bytes to return, since zstd may swallow several input
         * slices before emitting any output.
         *
         * @throws whatever the inner source throws, and std::runtime_error on a compression failure.
         */
        std::size_t read(char* buffer, std::size_t capacity) override;

    private:
        std::shared_ptr<IByteSource> m_inner;
        remoted::common::ZstdEncoder m_encoder;
        std::string m_staging;         ///< Plain bytes read from the inner source, not yet consumed.
        std::size_t m_stagedPos {0};   ///< Next unconsumed byte of m_staging.
        std::size_t m_stagedSize {0};  ///< Valid bytes in m_staging.
        bool m_innerExhausted {false}; ///< The inner source has returned 0.
        bool m_finished {false};       ///< The frame has been completely handed out.
    };

} // namespace remoted::http

#endif // _REMOTED_HTTP_SERVER_ZSTD_COMPRESSING_BYTE_SOURCE_HPP
