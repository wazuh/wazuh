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

#ifndef _REMOTED_HTTP_COMPRESSING_BYTE_SOURCE_HPP
#define _REMOTED_HTTP_COMPRESSING_BYTE_SOURCE_HPP

#include "IHttpServer.hpp"

#include "common/zstdEncoder.hpp"

#include <cstddef>
#include <memory>
#include <string>

namespace remoted::http
{

    /**
     * @brief IByteSource decorator that zstd-compresses another source's bytes as they are pulled.
     *
     * Sits between the transport's StreamPump and the endpoint's source (a FileByteSource for
     * /download), so neither side knows compression is happening: the pump keeps pulling
     * chunk-sized slices -- now of COMPRESSED bytes -- and the inner source keeps producing plain
     * bytes. An exception from the inner source (e.g. the mid-transfer modification check)
     * propagates through read() untouched, so an aborted transfer still ends without a terminating
     * chunk and reaches the agent as a truncated zstd frame.
     *
     * The reservation passed in charges the compressor's working memory (state + staging buffer)
     * against the in-flight byte budget for exactly as long as this source -- and therefore the
     * transfer -- lives.
     */
    class ZstdCompressingByteSource final : public IByteSource
    {
    public:
        /**
         * @brief Wrap @p inner. Throws std::runtime_error if the zstd context cannot be created.
         *
         * @param inner       The plain-byte producer. Must not be null.
         * @param reservation In-flight budget reservation covering this object's working memory;
         *                    held until destruction.
         */
        ZstdCompressingByteSource(std::shared_ptr<IByteSource> inner, InFlightBudget::Reservation reservation);

        /**
         * @brief Produce the next slice of COMPRESSED body.
         *
         * Honors IByteSource's contract that 0 means end-of-stream: zstd may consume input without
         * emitting output (it buffers up to a block internally), so this loops -- pulling more
         * plain bytes as needed -- until it has at least one compressed byte or the frame is
         * genuinely complete. Returning 0 early would make the transport emit the terminating
         * chunk around a truncated frame that looks complete at the HTTP layer.
         */
        std::size_t read(char* buffer, std::size_t capacity) override;

        /// Working memory this source costs: compressor state plus the input staging buffer.
        /// This is the figure to reserve against the in-flight budget before constructing one.
        static std::size_t workingMemoryBytes();

    private:
        std::shared_ptr<IByteSource> m_inner;
        InFlightBudget::Reservation m_reservation;
        remoted::common::ZstdStreamCompressor m_compressor;
        std::string m_staging;        ///< Plain bytes pulled from the inner source, pending compression.
        std::size_t m_stagingFill {0}; ///< Valid bytes in m_staging.
        std::size_t m_stagingPos {0};  ///< Bytes of m_staging already consumed by the compressor.
        bool m_innerEof {false};
        bool m_frameComplete {false};
    };

} // namespace remoted::http

#endif // _REMOTED_HTTP_COMPRESSING_BYTE_SOURCE_HPP
