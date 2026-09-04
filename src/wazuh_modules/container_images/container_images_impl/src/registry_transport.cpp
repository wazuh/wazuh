/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "registry_transport.hpp"

#include "ci_logging_helper.hpp"

#include <algorithm>
#include <cctype>
#include <mutex>
#include <utility>

#include <curl/curl.h>

namespace
{
    constexpr long MAX_REDIRECTS {5};
    constexpr auto ALLOWED_PROTOCOLS {"https"};
    constexpr auto USER_AGENT {"Wazuh-Agent-ContainerImages"};

    /// @brief Where a response body is accumulated, with its own ceiling.
    struct BodySink
    {
        std::string* body {nullptr};
        std::uint64_t limit {0};
        bool exceeded {false};
    };

    std::size_t writeBody(char* data, const std::size_t size, const std::size_t members, void* userdata)
    {
        auto* sink {static_cast<BodySink*>(userdata)};
        const auto bytes {size * members};

        if (sink == nullptr || sink->body == nullptr)
        {
            return 0;
        }

        if (sink->body->size() + bytes > sink->limit)
        {
            // A short return aborts the transfer with CURLE_WRITE_ERROR, which is how a
            // ceiling is enforced while the response is still arriving rather than after
            // it has all been held in memory.
            sink->exceeded = true;
            return 0;
        }

        sink->body->append(data, bytes);

        return bytes;
    }

    std::size_t collectHeader(char* data, const std::size_t size, const std::size_t members, void* userdata)
    {
        auto* headers {static_cast<std::map<std::string, std::string>*>(userdata)};
        const auto bytes {size * members};

        if (headers == nullptr)
        {
            return bytes;
        }

        const std::string line {data, bytes};
        const auto separator {line.find(':')};

        // The status line and the blank line separating the headers have no colon.
        if (separator == std::string::npos)
        {
            return bytes;
        }

        auto name {line.substr(0, separator)};
        auto value {line.substr(separator + 1)};

        std::transform(name.begin(),
                       name.end(),
                       name.begin(),
                       [](const unsigned char character) { return static_cast<char>(std::tolower(character)); });

        const auto trim = [](std::string& text)
        {
            const auto isSpace = [](const char character)
            { return character == ' ' || character == '\t' || character == '\r' || character == '\n'; };

            while (!text.empty() && isSpace(text.front()))
            {
                text.erase(text.begin());
            }

            while (!text.empty() && isSpace(text.back()))
            {
                text.pop_back();
            }
        };

        trim(name);
        trim(value);

        // A redirect produces a second set of headers. The last one wins, which is the
        // response the caller actually received.
        (*headers)[name] = value;

        return bytes;
    }
} // namespace

namespace containerimages
{
    void ensureCurlInitialized()
    {
        static std::once_flag initialized;

        std::call_once(initialized, [] { curl_global_init(CURL_GLOBAL_DEFAULT); });
    }

    CurlRegistryTransport::CurlRegistryTransport(TransportConfig config)
        : m_config {std::move(config)}
    {
        ensureCurlInitialized();

        m_handle = curl_easy_init();
    }

    CurlRegistryTransport::~CurlRegistryTransport()
    {
        if (m_handle != nullptr)
        {
            curl_easy_cleanup(static_cast<CURL*>(m_handle));
            m_handle = nullptr;
        }
    }

    bool CurlRegistryTransport::get(const std::string& url,
                                    const std::vector<std::string>& headers,
                                    HttpResponse& response,
                                    std::string& error)
    {
        return perform(url, headers, nullptr, response, error);
    }

    bool CurlRegistryTransport::getWithBasicAuth(const std::string& url,
                                                 const std::vector<std::string>& headers,
                                                 const std::string& user,
                                                 const Secret& password,
                                                 HttpResponse& response,
                                                 std::string& error)
    {
        // Assembled here and destroyed with this scope, so the credential is not held for
        // the lifetime of the transport.
        std::string credentials {user + ":" + password.value()};

        const auto result {perform(url, headers, &credentials, response, error)};

        // Written through a volatile pointer. A std::fill into a buffer that is freed on
        // the next line is a dead store, and a compiler is entitled to remove it; this is
        // the same reason Secret::scrub does it this way, and this is the one place
        // outside Secret that handles an assembled credential.
        volatile char* data {const_cast<volatile char*>(credentials.data())};

        for (std::size_t index = 0; index < credentials.size(); ++index)
        {
            data[index] = '\0';
        }

        return result;
    }

    bool CurlRegistryTransport::perform(const std::string& url,
                                        const std::vector<std::string>& headers,
                                        const std::string* basicCredentials,
                                        HttpResponse& response,
                                        std::string& error)
    {
        response = {};
        error.clear();

        if (m_handle == nullptr)
        {
            error = "the HTTP client could not be created";
            return false;
        }

        if (m_config.caBundle.empty())
        {
            // Refused rather than attempted unverified. Reaching here means the caller
            // skipped the certificate resolution, and connecting anyway would silently
            // drop the guarantee the resolution exists to provide.
            error = "no certificate bundle is available, so the registry cannot be verified";
            return false;
        }

        auto* handle {static_cast<CURL*>(m_handle)};

        curl_easy_reset(handle);

        BodySink sink {&response.body, m_config.maxResponseBytes, false};

        curl_easy_setopt(handle, CURLOPT_URL, url.c_str());
        curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, writeBody);
        curl_easy_setopt(handle, CURLOPT_WRITEDATA, &sink);
        curl_easy_setopt(handle, CURLOPT_HEADERFUNCTION, collectHeader);
        curl_easy_setopt(handle, CURLOPT_HEADERDATA, &response.headers);

        // Verification, stated rather than inherited. Both are libcurl defaults; setting
        // them explicitly means the posture reads in one place and a later change to the
        // defaults cannot quietly weaken it.
        curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 2L);
        curl_easy_setopt(handle, CURLOPT_CAINFO, m_config.caBundle.c_str());

        // https only, for the request and for anything it is redirected to. Without the
        // second, a redirect could downgrade to plain http, which libcurl permits by
        // default.
        curl_easy_setopt(handle, CURLOPT_PROTOCOLS_STR, ALLOWED_PROTOCOLS);
        curl_easy_setopt(handle, CURLOPT_REDIR_PROTOCOLS_STR, ALLOWED_PROTOCOLS);

        curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(handle, CURLOPT_MAXREDIRS, MAX_REDIRECTS);

        // Left off deliberately, and named here so nobody turns it on to "fix" an
        // authentication problem: a blob request is redirected off the registry to a
        // content host, and that host neither needs nor should receive the token.
        curl_easy_setopt(handle, CURLOPT_UNRESTRICTED_AUTH, 0L);

        curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT_MS, m_config.connectTimeoutMs);
        curl_easy_setopt(handle, CURLOPT_TIMEOUT_MS, m_config.requestTimeoutMs);

        // The module runs inside a thread of wazuh-modulesd. Without this, libcurl may
        // use signals for its own timeouts, which is not safe off the main thread.
        curl_easy_setopt(handle, CURLOPT_NOSIGNAL, 1L);

        curl_easy_setopt(handle, CURLOPT_USERAGENT, USER_AGENT);

        if (basicCredentials != nullptr)
        {
            curl_easy_setopt(handle, CURLOPT_HTTPAUTH, static_cast<long>(CURLAUTH_BASIC));
            curl_easy_setopt(handle, CURLOPT_USERPWD, basicCredentials->c_str());
        }

        curl_slist* headerList {nullptr};

        for (const auto& header : headers)
        {
            headerList = curl_slist_append(headerList, header.c_str());
        }

        if (headerList != nullptr)
        {
            curl_easy_setopt(handle, CURLOPT_HTTPHEADER, headerList);
        }

        const auto result {curl_easy_perform(handle)};

        curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &response.status);

        // The handle is reset before the credential-bearing options can outlive this
        // call, and the header list is freed only after the transfer that referenced it.
        curl_easy_reset(handle);

        if (headerList != nullptr)
        {
            curl_slist_free_all(headerList);
        }

        if (result != CURLE_OK)
        {
            if (sink.exceeded)
            {
                error = "the response exceeded the " + std::to_string(m_config.maxResponseBytes) + " byte limit";
            }
            else
            {
                // curl_easy_strerror describes the class of failure and never echoes the
                // request, so it cannot carry a credential into the log.
                error = curl_easy_strerror(result);
            }

            response.status = 0;

            return false;
        }

        return true;
    }
} // namespace containerimages
