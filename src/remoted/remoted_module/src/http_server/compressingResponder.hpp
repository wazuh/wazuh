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

#ifndef _REMOTED_HTTP_COMPRESSING_RESPONDER_HPP
#define _REMOTED_HTTP_COMPRESSING_RESPONDER_HPP

#include "IHttpServer.hpp"

#include <memory>
#include <string_view>

namespace remoted::http
{

    /**
     * @brief Whether an Accept-Encoding header value advertises zstd.
     *
     * Minimal token parse for the header's element list (agents are the only clients): an element
     * whose coding token is "zstd" (case-insensitive) counts, unless its q parameter is 0. The
     * wildcard "*" is deliberately NOT honored -- compression is served only to a client that
     * names zstd, so a generic client never receives an encoding it didn't ask for by name.
     *
     * @param acceptEncoding The raw Accept-Encoding value ("" when the header is absent).
     */
    bool acceptsZstdResponseEncoding(std::string_view acceptEncoding);

    /**
     * @brief IHttpResponder decorator that zstd-compresses streamed response bodies.
     *
     * Created by the transport for a Streamable route whose request advertised
     * `Accept-Encoding: zstd` (and with response compression enabled), so no endpoint handler has
     * to know compression exists. What it does per delivery mode:
     *
     * - send(): delegates untouched. Buffered responses are the error bodies (400/404/500 JSON),
     *   which stay plain and byte-identical to an uncompressed deployment.
     * - stream(): compresses -- unless the response opted out (StreamResponse::compressible is
     *   false, e.g. a WPK, which is already-compressed payload), or the compressor's working
     *   memory doesn't fit the in-flight byte budget right now, in which case the response is
     *   served plain exactly as today. When it does compress, it appends `Content-Encoding: zstd`
     *   and wraps the source; the budget reservation lives inside the wrapped source, released
     *   when the transfer ends.
     *
     * The exactly-once send()/stream() guarantee is the inner responder's; this class keeps no
     * delivery state of its own.
     */
    class ZstdCompressingResponder final : public IHttpResponder
    {
    public:
        /**
         * @param inner  The transport's real responder. Must not be null.
         * @param budget Budget to charge the compressor's working memory against. May be null
         *               (never compresses -- serves plain), so a misconfigured wiring degrades
         *               instead of crashing.
         */
        ZstdCompressingResponder(std::shared_ptr<IHttpResponder> inner, InFlightBudget* budget);

        void send(HttpResponse response) override;

        void stream(StreamResponse response) override;

    private:
        std::shared_ptr<IHttpResponder> m_inner;
        InFlightBudget* m_budget;
    };

} // namespace remoted::http

#endif // _REMOTED_HTTP_COMPRESSING_RESPONDER_HPP
