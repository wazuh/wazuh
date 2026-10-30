/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_HTTP_SERVER_RESPONSE_ENCODING_HPP
#define _REMOTED_HTTP_SERVER_RESPONSE_ENCODING_HPP

#include "IHttpServer.hpp"
#include "headerUtils.hpp"
#include "holdingByteSource.hpp"
#include "inFlightBudget.hpp"

#include <cstddef>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace remoted::http
{

    /**
     * @brief A content coding a streamed response body can be sent in.
     *
     * The response-side counterpart of decoding::IBodyDecoder: the transport and the code below depend
     * on this and never on a codec, so supporting another coding means implementing this interface
     * and listing it where the factory is built, nothing else.
     */
    class IResponseEncoding
    {
    public:
        virtual ~IResponseEncoding() = default;

        /// Lowercase coding token: what the response carries in `Content-Encoding` and what a
        /// client offers in `Accept-Encoding`.
        virtual std::string_view token() const noexcept = 0;

        /// Memory one transfer holds while it is being encoded. Reserved against the in-flight byte
        /// budget before wrap() and held until the transfer ends, so the cost is shared with every
        /// other consumer of that budget. Accounting is not the encoding's business: it only reports
        /// the figure.
        virtual std::size_t memoryRequired() const = 0;

        /**
         * @brief A source yielding @p inner's bytes in this coding.
         *
         * Must keep the failure semantics of IByteSource: an exception from @p inner crosses the
         * wrapper, and the source returns 0 only once the coded body is complete, since 0 is
         * end-of-stream to the pump. May throw (it can allocate); the caller then sends the response
         * as the handler built it.
         */
        virtual std::shared_ptr<IByteSource> wrap(std::shared_ptr<IByteSource> inner) const = 0;
    };

    /// The codings a server can answer in, most preferred first.
    using ResponseEncodings = std::vector<std::shared_ptr<const IResponseEncoding>>;

    /**
     * @brief The transform that sends a streamed response in @p encoding.
     *
     * Leaves the response alone, so the client gets the body as the handler built it, when
     *  - the handler says it is not compressible (an already-compressed WPK),
     *  - there is no source to encode, or
     *  - the encoding's memory cannot be reserved: every client has to accept a plain body anyway,
     *    so degrading costs nothing.
     *
     * Otherwise it reserves memoryRequired(), wraps the source and adds `Content-Encoding`. The
     * reservation travels with the source (HoldingByteSource), so no encoding has to remember to keep
     * it. Nothing is changed unless wrap() succeeds: if it throws, the reservation is released and
     * the response is untouched.
     */
    inline StreamTransform makeEncodingTransform(std::shared_ptr<const IResponseEncoding> encoding,
                                                 ReserveBytesFn reserve)
    {
        return [encoding = std::move(encoding), reserve = std::move(reserve)](StreamResponse& response)
        {
            if (!response.compressible || response.source == nullptr)
            {
                return;
            }

            auto reservation = reserve(encoding->memoryRequired());
            if (!reservation)
            {
                return;
            }

            auto encoded = encoding->wrap(response.source);
            response.source = std::make_shared<HoldingByteSource<InFlightBudget::Reservation>>(std::move(encoded),
                                                                                               std::move(*reservation));
            response.headers.emplace_back("Content-Encoding", std::string {encoding->token()});
        };
    }

    /**
     * @brief Builds the hook the transport calls for every request to a streamable route
     *        (HttpServerConfig::streamTransformFactory).
     *
     * The first of @p encodings the request offers in `Accept-Encoding` wins, so the server's
     * preference order decides when a client offers several. A request that offers none of them, or
     * carries no `Accept-Encoding` at all, gets no transform.
     */
    inline StreamTransformFactory makeResponseEncodingFactory(ResponseEncodings encodings)
    {
        return [encodings = std::move(encodings)](const HttpRequest& request,
                                                  const ReserveBytesFn& reserve) -> StreamTransform
        {
            const auto offered = headerValue(request.headers, "accept-encoding");
            if (offered.empty())
            {
                return {};
            }
            for (const auto& encoding : encodings)
            {
                if (acceptsEncoding(offered, encoding->token()))
                {
                    return makeEncodingTransform(encoding, reserve);
                }
            }
            return {};
        };
    }

} // namespace remoted::http

#endif // _REMOTED_HTTP_SERVER_RESPONSE_ENCODING_HPP
