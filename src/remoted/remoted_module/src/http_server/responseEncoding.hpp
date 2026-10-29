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
#include "inFlightBudget.hpp"

#include <cstddef>
#include <memory>
#include <string_view>

namespace remoted::http
{

    /**
     * @brief A content coding a streamed response body can be sent in.
     *
     * The response-side counterpart of decoding::IBodyDecoder: the transport and CompressingResponder
     * depend on this and never on a codec, so supporting another coding means implementing this
     * interface and listing it where the decorator is built, nothing else.
     */
    class IResponseEncoding
    {
    public:
        virtual ~IResponseEncoding() = default;

        /// Lowercase coding token: what the response carries in `Content-Encoding` and what a
        /// client offers in `Accept-Encoding`.
        virtual std::string_view token() const noexcept = 0;

        /// Memory one transfer holds while it is being encoded. Reserved against the in-flight byte
        /// budget before wrap(), so the cost is shared with every other consumer of that budget.
        virtual std::size_t memoryRequired() const = 0;

        /**
         * @brief A source yielding @p inner's bytes in this coding.
         *
         * Must keep the failure semantics of IByteSource: an exception from @p inner crosses the
         * wrapper, and the source returns 0 only once the coded body is complete, since 0 is
         * end-of-stream to the pump.
         *
         * @param inner       The handler's plain source.
         * @param reservation What memoryRequired() reserved; the returned source keeps it for as long
         *                    as the transfer lives.
         */
        virtual std::shared_ptr<IByteSource> wrap(std::shared_ptr<IByteSource> inner,
                                                  InFlightBudget::Reservation reservation) const = 0;
    };

} // namespace remoted::http

#endif // _REMOTED_HTTP_SERVER_RESPONSE_ENCODING_HPP
