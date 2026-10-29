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
#include "headerUtils.hpp"
#include "responseEncoding.hpp"

#include <cstddef>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace remoted::http
{

    /**
     * @brief Responder decorator that sends a streamed body in the content coding the client asked for.
     *
     * Codec-neutral: everything specific to a coding lives behind IResponseEncoding. Installed per
     * request by makeResponseEncodingDecorator(), only when the client offered that coding, so a
     * request that did not negotiate it never sees this class. Handlers and the auth gateway are
     * unaware of it.
     *
     * send() is delegated untouched: buffered bodies are error documents, and they stay plain and
     * byte-identical to a response that was never offered a coding. stream() encodes unless
     *  - the response says it is not compressible (an already-compressed WPK), or
     *  - the encoding's memory cannot be reserved: the response is then served plain, which every
     *    client has to accept anyway, so degrading costs nothing.
     */
    class CompressingResponder final : public IHttpResponder
    {
    public:
        CompressingResponder(std::shared_ptr<IHttpResponder> inner,
                             std::shared_ptr<const IResponseEncoding> encoding,
                             ReserveBytesFn reserve)
            : m_inner {std::move(inner)}
            , m_encoding {std::move(encoding)}
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
                if (auto reservation = m_reserve(m_encoding->memoryRequired()))
                {
                    response.headers.emplace_back("Content-Encoding", std::string {m_encoding->token()});
                    response.source = m_encoding->wrap(std::move(response.source), std::move(*reservation));
                }
            }
            m_inner->stream(std::move(response));
        }

    private:
        std::shared_ptr<IHttpResponder> m_inner;
        std::shared_ptr<const IResponseEncoding> m_encoding;
        ReserveBytesFn m_reserve;
    };

    /// The codings a server can answer in, most preferred first.
    using ResponseEncodings = std::vector<std::shared_ptr<const IResponseEncoding>>;

    /**
     * @brief Builds the hook the transport calls for every request to a streamable route
     *        (HttpServerConfig::decorateStreamResponder).
     *
     * The first of @p encodings the request offers in `Accept-Encoding` wins, so the server's
     * preference order decides when a client offers several. A request that offers none of them, or
     * carries no `Accept-Encoding` at all, gets the transport's own responder back untouched.
     */
    inline StreamResponderDecorator makeResponseEncodingDecorator(ResponseEncodings encodings)
    {
        return [encodings = std::move(encodings)](const HttpRequest& request,
                                                  std::shared_ptr<IHttpResponder> responder,
                                                  const ReserveBytesFn& reserve) -> std::shared_ptr<IHttpResponder>
        {
            const auto offered = headerValue(request.headers, "accept-encoding");
            if (offered.empty())
            {
                return responder;
            }
            for (const auto& encoding : encodings)
            {
                if (acceptsEncoding(offered, encoding->token()))
                {
                    return std::make_shared<CompressingResponder>(std::move(responder), encoding, reserve);
                }
            }
            return responder;
        };
    }

} // namespace remoted::http

#endif // _REMOTED_HTTP_SERVER_COMPRESSING_RESPONDER_HPP
