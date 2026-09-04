/*
 * Wazuh task manager module
 * Copyright (C) 2015, Wazuh Inc.
 * September 1, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "udsHttpClient.hpp"

#include <curl/curl.h>

#include <stdexcept>
#include <utility>

namespace
{
    /// @brief The host part is a placeholder: CURLOPT_UNIX_SOCKET_PATH decides where the request
    ///        actually goes, and libcurl still requires a syntactically valid URL.
    constexpr auto URL_PREFIX {"http://localhost"};

    struct ResponseSink
    {
        std::string* buffer {nullptr};
        std::size_t limit {0};
    };

    std::size_t writeCallback(char* data, std::size_t size, std::size_t members, void* userData)
    {
        auto* sink {static_cast<ResponseSink*>(userData)};
        const auto incoming {size * members};

        if (sink != nullptr && sink->buffer != nullptr && sink->buffer->size() < sink->limit)
        {
            const auto room {sink->limit - sink->buffer->size()};
            sink->buffer->append(data, incoming < room ? incoming : room);
        }

        // Always claim the whole chunk. Returning less aborts the transfer with
        // CURLE_WRITE_ERROR, which would turn "the consumer sent a long body" into a transport
        // failure -- the body is discarded past the limit, not treated as an error.
        return incoming;
    }
} // namespace

namespace task_manager::handlers
{
    struct UdsHttpClient::Impl
    {
        Options options;
        CURL* handle {nullptr};
        curl_slist* headers {nullptr};

        ~Impl()
        {
            if (headers != nullptr)
            {
                curl_slist_free_all(headers);
            }
            if (handle != nullptr)
            {
                curl_easy_cleanup(handle);
            }
        }
    };

    UdsHttpClient::UdsHttpClient(Options options)
        : m_impl {std::make_unique<Impl>()}
    {
        m_impl->options = std::move(options);
        m_impl->handle = curl_easy_init();

        if (m_impl->handle == nullptr)
        {
            throw std::runtime_error("Could not create a libcurl handle for the task manager's consumer calls");
        }

        m_impl->headers = curl_slist_append(nullptr, "Content-Type: application/json");
        m_impl->headers = curl_slist_append(m_impl->headers, "Accept: application/json");
        // The consumers answer at completion, which can be minutes away. Expect: 100-continue
        // would add a round trip and a one-second stall when the peer ignores it.
        m_impl->headers = curl_slist_append(m_impl->headers, "Expect:");
    }

    UdsHttpClient::~UdsHttpClient() = default;
    UdsHttpClient::UdsHttpClient(UdsHttpClient&&) noexcept = default;
    UdsHttpClient& UdsHttpClient::operator=(UdsHttpClient&&) noexcept = default;

    registry::TransportResult UdsHttpClient::post(const std::string& path, const std::string& body)
    {
        // Zeroed before every call. The mapper's "request was never sent" sentinel is exactly
        // "-1 with this struct untouched", so reusing a populated struct would present the
        // previous call's values as this one's.
        registry::TransportResult result;

        auto* handle {m_impl->handle};
        curl_easy_reset(handle);

        std::string response;
        ResponseSink sink {&response, m_impl->options.maxResponseBytes};

        const auto url {std::string {URL_PREFIX} + path};

        curl_easy_setopt(handle, CURLOPT_UNIX_SOCKET_PATH, m_impl->options.socketPath.c_str());
        curl_easy_setopt(handle, CURLOPT_URL, url.c_str());
        curl_easy_setopt(handle, CURLOPT_POST, 1L);
        curl_easy_setopt(handle, CURLOPT_POSTFIELDS, body.c_str());
        curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
        curl_easy_setopt(handle, CURLOPT_HTTPHEADER, m_impl->headers);
        curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, writeCallback);
        curl_easy_setopt(handle, CURLOPT_WRITEDATA, &sink);

        // Both deadlines set EXPLICITLY, because zero means different things to libcurl: an unset
        // CURLOPT_TIMEOUT_MS is "never", while an unset CURLOPT_CONNECTTIMEOUT_MS is its own 300 s
        // default. Leaving either implicit would silently ignore the descriptor's intent.
        curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT_MS, static_cast<long>(m_impl->options.connectTimeout.count()));
        curl_easy_setopt(handle, CURLOPT_TIMEOUT_MS, static_cast<long>(m_impl->options.requestTimeout.count()));

        // Mandatory in a threaded process: without it libcurl installs signal handlers and can use
        // SIGALRM, and this daemon wires SIGALRM to a TERMINATING handler.
        curl_easy_setopt(handle, CURLOPT_NOSIGNAL, 1L);

        const auto code {curl_easy_perform(handle)};

        long status {0};
        curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &status);

        result.curlCode = static_cast<int>(code);
        result.httpStatus = static_cast<int>(status);
        result.body = std::move(response);

        if (code != CURLE_OK)
        {
            result.returnCode = -static_cast<int>(code);
        }
        else if (status < 200 || status > 299)
        {
            result.returnCode = static_cast<int>(status);
        }
        else
        {
            result.returnCode = 0;
        }

        return result;
    }
} // namespace task_manager::handlers
