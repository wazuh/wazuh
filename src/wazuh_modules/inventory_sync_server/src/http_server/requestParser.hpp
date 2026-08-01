/*
 * Wazuh inventory sync server module
 * Copyright (C) 2015, Wazuh Inc.
 * July 28, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVSYNC_HTTP_REQUEST_PARSER_HPP
#define _INVSYNC_HTTP_REQUEST_PARSER_HPP

#include "IUdsHttpServer.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace invsync::http
{

    /**
     * @brief Incremental HTTP/1.1 request parser: an llhttp wrapper that also enforces the size
     *        limits llhttp itself does not have.
     *
     * Deliberately free of both asio and loggerHelper.h. That is what lets the test binary include
     * this header directly and drive it with plain byte strings -- no sockets, no threads, no log
     * sink -- which matters because this is where the parsing bugs live: header fields that straddle
     * a read boundary, a request line split mid-token, a body that arrives in pieces.
     *
     * llhttp gives us no limits of its own (remoted gets those for free from RESTinio's
     * incoming_http_msg_limits_t; here they are applied by hand), so maxUrlSize, maxHeaderNameSize,
     * maxHeaderValueSize, maxHeaderCount and maxBodySize are all checked in the callbacks.
     *
     * USAGE. The parser deliberately STOPS once the head is parsed, so admission control can run
     * before a single body byte is buffered:
     *
     *     feed(...)  -> Incomplete            keep reading
     *                -> HeadersReady          run admission control, then either resume() to accept
     *                                         or answer and close to reject
     *                -> Reject                answer rejectStatus() and close
     *                -> ProtocolError         answer 400 and close
     *     resume()   -> Incomplete            keep reading (drains bytes that arrived with the head)
     *                -> Complete              dispatch request()
     *                -> Reject/ProtocolError  as above
     *
     * That pause is why the parser does not just run to completion: a request small enough to arrive
     * in one read would otherwise be fully buffered before the caller ever got a say.
     */
    class RequestParser final
    {
    public:
        /// @brief What the last call concluded about the bytes so far.
        enum class Feed
        {
            Incomplete,   ///< Need more bytes.
            HeadersReady, ///< Head fully parsed and parsing PAUSED; admission control runs now.
            Complete,     ///< Whole request (head + body) parsed; request() is final.
            Reject,       ///< A limit was exceeded; answer rejectStatus() and close.
            ProtocolError ///< Not valid HTTP/1.1; answer 400 and close.
        };

        /// @brief Limits applied while parsing. Mirrors the matching UdsHttpServerConfig fields.
        struct Limits
        {
            std::size_t maxBodySize {16U * 1024U * 1024U};
            std::size_t maxUrlSize {2048};
            std::size_t maxHeaderNameSize {256};
            std::size_t maxHeaderValueSize {8192};
            std::size_t maxHeaderCount {32};
        };

        explicit RequestParser(Limits limits);
        ~RequestParser();

        RequestParser(const RequestParser&) = delete;
        RequestParser& operator=(const RequestParser&) = delete;
        RequestParser(RequestParser&&) = delete;
        RequestParser& operator=(RequestParser&&) = delete;

        /**
         * @brief Feed the next chunk of received bytes.
         *
         * Returns HeadersReady exactly once, on the call that completes the head; parsing is paused
         * at that point and any bytes from the same chunk that belong to the body are retained
         * internally until resume(). Once Reject or ProtocolError has been returned the parser is
         * spent and every further call returns the same verdict.
         *
         * @param data Pointer to the chunk (may be null when @p length is 0).
         * @param length Chunk length in bytes.
         * @return The verdict for the bytes seen so far.
         */
        Feed feed(const char* data, std::size_t length);

        /**
         * @brief Accept the request after HeadersReady and continue parsing its body.
         *
         * Reserves room for the declared body (bounded: the caller has already compared
         * declaredContentLength() against its cap) and drains whatever body bytes arrived in the
         * same read as the head. Calling this in any state other than HeadersReady is a no-op that
         * returns the current verdict.
         */
        Feed resume();

        /**
         * @brief Signal that the peer closed its side without completing the request.
         *
         * @return Complete if the message was in fact already complete, ProtocolError otherwise.
         */
        Feed finish();

        /// @brief HTTP status to answer when the verdict was Reject (411, 413, 414 or 431).
        int rejectStatus() const noexcept
        {
            return m_rejectStatus;
        }

        /// @brief The request built so far. Only final once the verdict is Complete.
        HttpRequest& request() noexcept
        {
            return m_request;
        }

        /**
         * @brief The body length the client declared, valid from HeadersReady onwards.
         *
         * 0 both for "no body" and for an explicit `Content-Length: 0`; the two need not be
         * distinguished. A chunked request never reaches HeadersReady -- it is rejected 411,
         * because without a declared length there is nothing to reserve and one connection could
         * consume the whole in-flight budget.
         */
        std::uint64_t declaredContentLength() const noexcept
        {
            return m_declaredContentLength;
        }

    private:
        struct Impl;
        std::unique_ptr<Impl> m_impl;

        /// Maps an llhttp_execute() result onto a verdict, and stashes any bytes received past the
        /// head when it paused.
        Feed interpret(int error, const char* data, std::size_t length);

        /// Turns the paused-at-head state into either HeadersReady or Reject, exactly once.
        Feed reportHeadOutcome();

        HttpRequest m_request;
        Limits m_limits;
        std::uint64_t m_declaredContentLength {0};
        int m_rejectStatus {0};
    };

} // namespace invsync::http

#endif // _INVSYNC_HTTP_REQUEST_PARSER_HPP
