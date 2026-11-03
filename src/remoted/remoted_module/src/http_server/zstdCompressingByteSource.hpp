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

#include "common/zstdEncoder.hpp"
#include "http_server/IHttpServer.hpp"
#include "http_server/inFlightBudget.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

namespace remoted::http
{

    /**
     * @brief IByteSource decorator that serves its inner source as a single zstd frame.
     *
     * read() returns 0 only once the frame is complete and fully delivered, never earlier, so the
     * transport never ends the body on a truncated frame. An exception from the inner source (or
     * from the encoder) propagates unchanged and the frame is left unfinished.
     */
    class ZstdCompressingByteSource final : public IByteSource
    {
    public:
        /**
         * @param inner       Source to compress; shared, never moved from.
         * @param reservation Memory held for the encoder, released when this source is destroyed.
         * @param sizeHint    Exact total size of the inner source, if known.
         */
        ZstdCompressingByteSource(std::shared_ptr<IByteSource> inner,
                                  InFlightBudget::Reservation reservation,
                                  std::optional<std::uint64_t> sizeHint);

        /// @pre capacity > 0
        std::size_t read(char* buffer, std::size_t capacity) override;

    private:
        // Declared first so it is destroyed last: the budget must not report free memory still allocated.
        InFlightBudget::Reservation m_reservation;
        std::shared_ptr<IByteSource> m_inner;
        common::ZstdEncoder m_encoder;
        std::vector<char> m_in;
        std::size_t m_inPos {0};
        std::size_t m_inLen {0};
        std::vector<char> m_out;
        std::size_t m_outPos {0};
        std::size_t m_outLen {0};
        bool m_finishing {false}; ///< The inner source returned 0; only ZSTD_e_end from now on.
        bool m_done {false};      ///< The frame is complete.
    };

} // namespace remoted::http

#endif // _REMOTED_HTTP_SERVER_ZSTD_COMPRESSING_BYTE_SOURCE_HPP
