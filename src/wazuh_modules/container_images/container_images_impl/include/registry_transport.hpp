/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REGISTRY_TRANSPORT_HPP
#define _REGISTRY_TRANSPORT_HPP

#include "credential_provider.hpp"

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace containerimages
{
    /// @brief One HTTP response: its status, its body, and its headers.
    struct HttpResponse
    {
        long status {0}; ///< HTTP status, or 0 when no response was produced.
        std::string body;
        std::map<std::string, std::string> headers; ///< Names lower-cased.

        /// @brief A header value by lower-cased name, or an empty string when absent.
        std::string header(const std::string& name) const
        {
            const auto entry {headers.find(name)};

            return entry != headers.end() ? entry->second : std::string {};
        }
    };

    /// @brief How the transport is allowed to behave.
    struct TransportConfig
    {
        std::string caBundle;                                ///< Certificate bundle to verify against. Required.
        long connectTimeoutMs {10000};                        ///< Ceiling on establishing a connection.
        long requestTimeoutMs {30000};                        ///< Ceiling on one whole request.
        std::uint64_t maxResponseBytes {16ULL * 1024 * 1024}; ///< Ceiling on one buffered response.
        long blobTimeoutMs {300000};                          ///< Ceiling on one whole blob transfer.
    };

    /// @brief Requests this module makes of a registry.
    ///
    /// Narrow on purpose. This is a transport for one protocol, not a general HTTP
    /// client: there is no post, no put, no proxy handling and no cookie jar, and adding
    /// any of them is how a second HTTP client gets into the product by accident. Layer
    /// blobs do not come through here either, because they are streamed rather than
    /// buffered.
    class IRegistryTransport
    {
        public:
            virtual ~IRegistryTransport() = default;

            /// @brief GET a small document, such as a token, an index or a manifest.
            ///
            /// A non-2xx status is a result, not a failure: the caller needs the `401`
            /// and its `WWW-Authenticate` header to know how to authenticate. False is
            /// returned only when no response was produced at all.
            ///
            /// @param url     Absolute https URL.
            /// @param headers Request headers, as "Name: value".
            /// @param response Filled in when a response was received.
            /// @param error   Why no response was produced, when that is the outcome.
            ///                Never carries a credential.
            virtual bool get(const std::string& url,
                             const std::vector<std::string>& headers,
                             HttpResponse& response,
                             std::string& error) = 0;

            /// @brief GET with HTTP Basic credentials, used only for a token exchange.
            ///
            /// On the interface rather than only on the cURL implementation, so the one
            /// call that carries a credential can be observed by a test double. Without
            /// it the authentication path could not be covered at all.
            virtual bool getWithBasicAuth(const std::string& url,
                                          const std::vector<std::string>& headers,
                                          const std::string& user,
                                          const Secret& password,
                                          HttpResponse& response,
                                          std::string& error) = 0;
    };

    /// @brief Registry transport over libcurl.
    ///
    /// libcurl reaches the agent through `wazuhext`, which this module already links, so
    /// this adds no dependency to any agent package.
    ///
    /// The security posture is set explicitly in one place rather than inherited from
    /// defaults: the peer and the host name are verified against a named bundle, only
    /// https is allowed for the request and for anything it is redirected to, and the
    /// `Authorization` header is not carried across a redirect to another host, which
    /// matters because a blob download is redirected off the registry to a content host
    /// that neither needs nor should see the token.
    class CurlRegistryTransport final : public IRegistryTransport
    {
        public:
            explicit CurlRegistryTransport(TransportConfig config);
            ~CurlRegistryTransport() override;

            CurlRegistryTransport(const CurlRegistryTransport&) = delete;
            CurlRegistryTransport& operator=(const CurlRegistryTransport&) = delete;

            bool get(const std::string& url,
                     const std::vector<std::string>& headers,
                     HttpResponse& response,
                     std::string& error) override;

            bool getWithBasicAuth(const std::string& url,
                                  const std::vector<std::string>& headers,
                                  const std::string& user,
                                  const Secret& password,
                                  HttpResponse& response,
                                  std::string& error) override;

            const TransportConfig& config() const
            {
                return m_config;
            }

        private:
            /// @brief Perform one request, optionally with Basic credentials.
            bool perform(const std::string& url,
                         const std::vector<std::string>& headers,
                         const std::string* basicCredentials,
                         HttpResponse& response,
                         std::string& error);

            TransportConfig m_config;
            void* m_handle {nullptr}; ///< CURL*, kept opaque so callers need no curl headers.
    };

    /// @brief Initialize libcurl once for this process.
    ///
    /// The shared HTTP wrapper in the product never calls `curl_global_init`, and the
    /// agent's own HTTPS client does so in a different process, so nothing has
    /// necessarily initialized libcurl inside `wazuh-modulesd` before this module runs.
    /// Relying on the implicit initialization that `curl_easy_init` performs is what the
    /// library documentation warns against in a threaded program.
    void ensureCurlInitialized();
} // namespace containerimages

#endif // _REGISTRY_TRANSPORT_HPP
