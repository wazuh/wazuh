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

#include "http_server/IHttpServer.hpp"
#include "http_server/inFlightBudget.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>

namespace remoted::http
{

    /**
     * @brief IHttpResponder decorator that serves a streamed body as zstd when it can.
     *
     * stream() compresses only a compressible response with a source and no Content-Encoding of
     * its own, and only once the encoder's memory is reserved; otherwise, or if preparing the
     * compressor throws, the response is forwarded unchanged. Either way the inner responder is
     * called exactly once and nothing from the preparation escapes. send() is forwarded as is.
     *
     * Holds no mutable state: send() and stream() may race on the same responder.
     */
    class CompressingResponder final : public IHttpResponder
    {
    public:
        /// Reserves @p bytes for one encoder; std::nullopt refuses compression.
        using ReserveFn = std::function<std::optional<InFlightBudget::Reservation>(std::size_t bytes)>;
        /// Builds the compressed source over a copy of the original (inner, reservation, sizeHint).
        using SourceFactory = std::function<std::shared_ptr<IByteSource>(
            std::shared_ptr<IByteSource>, InFlightBudget::Reservation, std::optional<std::uint64_t>)>;
        /// Told why a response is served uncompressed despite the client's offer.
        using FallbackFn = std::function<void(const char* reason)>;

        /**
         * @param inner      Responder that delivers the response.
         * @param reserve    Encoder memory reservation.
         * @param makeSource Empty: a ZstdCompressingByteSource.
         * @param onFallback Empty: fallbacks are silent.
         */
        CompressingResponder(std::shared_ptr<IHttpResponder> inner,
                             ReserveFn reserve,
                             SourceFactory makeSource = {},
                             FallbackFn onFallback = {});

        void send(HttpResponse response) override;

        void stream(StreamResponse response) override;

    private:
        void fallback(const char* reason) const noexcept;

        std::shared_ptr<IHttpResponder> m_inner;
        ReserveFn m_reserve;
        SourceFactory m_makeSource;
        FallbackFn m_onFallback;
    };

} // namespace remoted::http

#endif // _REMOTED_HTTP_SERVER_COMPRESSING_RESPONDER_HPP
