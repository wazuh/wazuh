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

#include "requestParser.hpp"

#include <llhttp.h>

#include <algorithm>
#include <cctype>
#include <string_view>
#include <utility>

namespace
{
    /// Lower-cases in place. ASCII only, which is all an HTTP header name may contain.
    void toLowerAscii(std::string& value)
    {
        std::transform(value.begin(),
                       value.end(),
                       value.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    }
} // namespace

namespace invsync::http
{

    /**
     * @brief llhttp state and callbacks. Kept out of the header so neither llhttp nor its enums leak.
     *
     * Every callback lives here rather than in a file-local lambda for an access reason: Impl is a
     * nested class of RequestParser, so its members may touch RequestParser's private state, while a
     * free function in this file could not.
     */
    struct RequestParser::Impl
    {
        llhttp_t parser {};
        RequestParser* owner {nullptr};

        /// Header accumulation. llhttp fires on_header_field/on_header_value repeatedly for a single
        /// header when it straddles a read boundary, so a pair is only committed when the NEXT field
        /// starts, or at headers-complete.
        std::string pendingName;
        std::string pendingValue;
        bool inValue {false};

        bool chunked {false};
        bool headersReported {false};
        bool messageComplete {false};
        bool paused {false};
        bool spent {false};

        /// Body bytes that arrived in the same read as the head, held until resume().
        std::string deferredAfterHead;

        static Impl* of(llhttp_t* parser)
        {
            return static_cast<Impl*>(parser->data);
        }

        void commitPendingHeader()
        {
            if (pendingName.empty())
            {
                return;
            }

            toLowerAscii(pendingName);

            if (pendingName == "transfer-encoding")
            {
                auto lowered = pendingValue;
                toLowerAscii(lowered);
                if (lowered.find("chunked") != std::string::npos)
                {
                    chunked = true;
                }
            }

            owner->m_request.headers.insert_or_assign(std::move(pendingName), std::move(pendingValue));
            pendingName.clear();
            pendingValue.clear();
        }

        int onUrl(const char* at, std::size_t length)
        {
            auto& target = owner->m_request.target;
            if (target.size() + length > owner->m_limits.maxUrlSize)
            {
                // 414 URI Too Long. HPE_USER is llhttp's documented sentinel for a
                // callback-signalled abort, distinct from a protocol error -- which is how
                // interpret() tells "a limit we enforced" from "these bytes are not HTTP".
                owner->m_rejectStatus = 414;
                return HPE_USER;
            }
            target.append(at, length);
            return 0;
        }

        int onHeaderField(const char* at, std::size_t length)
        {
            // A field name arriving after a value means the previous pair is finished.
            if (inValue)
            {
                commitPendingHeader();
                inValue = false;
            }

            if (owner->m_request.headers.size() >= owner->m_limits.maxHeaderCount)
            {
                owner->m_rejectStatus = 431;
                return HPE_USER;
            }
            if (pendingName.size() + length > owner->m_limits.maxHeaderNameSize)
            {
                owner->m_rejectStatus = 431;
                return HPE_USER;
            }

            pendingName.append(at, length);
            return 0;
        }

        int onHeaderValue(const char* at, std::size_t length)
        {
            inValue = true;

            if (pendingValue.size() + length > owner->m_limits.maxHeaderValueSize)
            {
                owner->m_rejectStatus = 431;
                return HPE_USER;
            }

            pendingValue.append(at, length);
            return 0;
        }

        int onHeadersComplete()
        {
            commitPendingHeader();

            owner->m_request.method = methodFrom(parser.method);
            owner->m_declaredContentLength = parser.content_length;

            // Chunked bodies are refused rather than supported. The peer always sends
            // Content-Length, and accepting chunked would break the admission arithmetic: with no
            // declared length there is nothing to reserve, so one connection could consume the whole
            // in-flight budget. Detected from the header rather than an llhttp flag enum, which keeps
            // it version-proof.
            if (chunked)
            {
                owner->m_rejectStatus = 411;
            }
            else if (parser.content_length > owner->m_limits.maxBodySize)
            {
                // Decided from the DECLARED length, so an oversized body is refused without reading
                // one byte of it.
                owner->m_rejectStatus = 413;
            }

            // Always pause, whatever the verdict. Returning 0 here would let llhttp go straight on
            // to the body, and 1 and 2 are reserved by llhttp for "no body" and "upgrade" -- so
            // neither can be borrowed to mean "stop". Pausing is what gives the caller a turn before
            // any body byte is buffered.
            paused = true;
            return HPE_PAUSED;
        }

        int onBody(const char* at, std::size_t length)
        {
            auto& body = owner->m_request.body;

            // Checked per chunk, so a client that lies about Content-Length and keeps sending cannot
            // grow the body past the cap by more than one read.
            if (body.size() + length > owner->m_limits.maxBodySize)
            {
                owner->m_rejectStatus = 413;
                return HPE_USER;
            }

            body.append(at, length);
            return 0;
        }

        static Method methodFrom(std::uint8_t method)
        {
            switch (method)
            {
                case HTTP_GET: return Method::Get;
                case HTTP_POST: return Method::Post;
                case HTTP_PUT: return Method::Put;
                case HTTP_DELETE: return Method::Delete;
                case HTTP_PATCH: return Method::Patch;
                default: break;
            }
            // Any other verb is one no route can match, so routing answers 405 for it.
            return Method::Get;
        }

        /**
         * @brief The shared callback table.
         *
         * File-local, stateless and built once for the process; each parser reaches its own Impl
         * through llhttp_t::data.
         */
        static const llhttp_settings_t* settings()
        {
            static const llhttp_settings_t table = []
            {
                llhttp_settings_t s;
                llhttp_settings_init(&s);
                s.on_url = [](llhttp_t* p, const char* at, std::size_t len)
                {
                    return of(p)->onUrl(at, len);
                };
                s.on_header_field = [](llhttp_t* p, const char* at, std::size_t len)
                {
                    return of(p)->onHeaderField(at, len);
                };
                s.on_header_value = [](llhttp_t* p, const char* at, std::size_t len)
                {
                    return of(p)->onHeaderValue(at, len);
                };
                s.on_headers_complete = [](llhttp_t* p)
                {
                    return of(p)->onHeadersComplete();
                };
                s.on_body = [](llhttp_t* p, const char* at, std::size_t len)
                {
                    return of(p)->onBody(at, len);
                };
                s.on_message_complete = [](llhttp_t* p)
                {
                    of(p)->messageComplete = true;
                    return 0;
                };
                return s;
            }();
            return &table;
        }
    };

    RequestParser::RequestParser(Limits limits)
        : m_impl {std::make_unique<Impl>()}
        , m_limits {limits}
    {
        m_impl->owner = this;
        llhttp_init(&m_impl->parser, HTTP_REQUEST, Impl::settings());
        m_impl->parser.data = m_impl.get();
    }

    RequestParser::~RequestParser() = default;

    RequestParser::Feed RequestParser::feed(const char* data, std::size_t length)
    {
        if (m_impl->spent)
        {
            return m_rejectStatus != 0 ? Feed::Reject : Feed::ProtocolError;
        }

        // The head is parsed and we are waiting on the caller's admission decision, so new bytes
        // wait for resume() rather than being handed to a paused parser.
        if (m_impl->paused)
        {
            if (data != nullptr && length > 0)
            {
                m_impl->deferredAfterHead.append(data, length);
            }
            return m_impl->headersReported ? Feed::Incomplete : reportHeadOutcome();
        }

        const auto error = llhttp_execute(&m_impl->parser, data == nullptr ? "" : data, length);
        return interpret(error, data, length);
    }

    RequestParser::Feed RequestParser::resume()
    {
        if (m_impl->spent)
        {
            return m_rejectStatus != 0 ? Feed::Reject : Feed::ProtocolError;
        }
        if (!m_impl->paused)
        {
            return m_impl->messageComplete ? Feed::Complete : Feed::Incomplete;
        }

        m_impl->paused = false;
        llhttp_resume(&m_impl->parser);

        // Bounded: the caller has already compared declaredContentLength() against its cap, so this
        // cannot be used to make us allocate more than one permitted body.
        if (m_declaredContentLength > 0)
        {
            m_request.body.reserve(static_cast<std::size_t>(m_declaredContentLength));
        }

        // Moved out first, so an append during execute cannot reallocate the buffer being read.
        const auto pending = std::move(m_impl->deferredAfterHead);
        m_impl->deferredAfterHead.clear();

        const auto error = llhttp_execute(&m_impl->parser, pending.empty() ? "" : pending.data(), pending.size());
        return interpret(error, pending.data(), pending.size());
    }

    RequestParser::Feed RequestParser::finish()
    {
        if (m_impl->messageComplete)
        {
            return Feed::Complete;
        }
        if (m_impl->spent)
        {
            return m_rejectStatus != 0 ? Feed::Reject : Feed::ProtocolError;
        }

        // A half-sent request is a protocol error, not a limit breach: the peer closed early.
        m_impl->spent = true;
        llhttp_finish(&m_impl->parser);
        return m_impl->messageComplete ? Feed::Complete : Feed::ProtocolError;
    }

    RequestParser::Feed RequestParser::interpret(int error, const char* data, std::size_t length)
    {
        if (error == HPE_PAUSED)
        {
            // llhttp stopped inside on_headers_complete. error_pos is the resume point, so
            // everything from it to the end of the chunk is body (or the start of a pipelined
            // request, which we do not support -- the peer sends Connection: close and one request
            // per connection). requestParser_test pins this byte accounting exactly, because an
            // off-by-one here would silently corrupt every body that shares a read with its head.
            const auto* resumeAt = llhttp_get_error_pos(&m_impl->parser);
            if (resumeAt != nullptr && data != nullptr && resumeAt >= data && resumeAt < data + length)
            {
                m_impl->deferredAfterHead.append(resumeAt, static_cast<std::size_t>(data + length - resumeAt));
            }
            return reportHeadOutcome();
        }

        if (error != HPE_OK)
        {
            m_impl->spent = true;
            // rejectStatus is set only by our own callbacks, so it is what separates a limit we
            // enforced from bytes that simply are not HTTP.
            return m_rejectStatus != 0 ? Feed::Reject : Feed::ProtocolError;
        }

        return m_impl->messageComplete ? Feed::Complete : Feed::Incomplete;
    }

    RequestParser::Feed RequestParser::reportHeadOutcome()
    {
        m_impl->headersReported = true;

        if (m_rejectStatus != 0)
        {
            m_impl->spent = true;
            return Feed::Reject;
        }
        return Feed::HeadersReady;
    }

} // namespace invsync::http
