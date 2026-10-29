/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_HTTP_SERVER_COMPRESSING_RESPONDER_HPP
#define _REMOTED_HTTP_SERVER_COMPRESSING_RESPONDER_HPP

#include "IHttpServer.hpp"
#include "common/zstdEncoder.hpp"
#include "inFlightBudget.hpp"
#include "zstdCompressingByteSource.hpp"

#include <cstddef>
#include <functional>
#include <memory>
#include <optional>
#include <utility>

namespace remoted::http
{

    /**
     * @brief Responder decorator that compresses a streamed body with zstd.
     *
     * Installed by the transport only when the client offered `zstd` and the feature is enabled, so
     * a request that did not negotiate it never sees this class. Handlers and the auth gateway are
     * unaware of it.
     *
     * send() is delegated untouched: buffered bodies are error documents, and they stay plain and
     * byte-identical to a response that was never offered compression. stream() compresses unless
     *  - the response says it is not compressible (an already-compressed WPK), or
     *  - the compressor's memory cannot be reserved: the response is then served plain, which every
     *    client has to accept anyway, so degrading costs nothing.
     */
    class CompressingResponder final : public IHttpResponder
    {
    public:
        /// Reserves @p bytes against the in-flight byte budget; nullopt when they do not fit.
        using ReserveFn = std::function<std::optional<InFlightBudget::Reservation>(std::size_t bytes)>;

        CompressingResponder(std::shared_ptr<IHttpResponder> inner, ReserveFn reserve)
            : m_inner {std::move(inner)}
            , m_reserve {std::move(reserve)}
        {
        }

        void send(HttpResponse response) override
        {
            m_inner->send(std::move(response));
        }

        void stream(StreamResponse response) override
        {
            if (response.compressible && response.source != nullptr)
            {
                if (auto reservation = m_reserve(remoted::common::ZstdEncoder::memoryRequired()))
                {
                    response.headers.emplace_back("Content-Encoding", "zstd");
                    response.source = std::make_shared<ZstdCompressingByteSource>(std::move(response.source),
                                                                                  std::move(*reservation));
                }
            }
            m_inner->stream(std::move(response));
        }

    private:
        std::shared_ptr<IHttpResponder> m_inner;
        ReserveFn m_reserve;
    };

} // namespace remoted::http

#endif // _REMOTED_HTTP_SERVER_COMPRESSING_RESPONDER_HPP
